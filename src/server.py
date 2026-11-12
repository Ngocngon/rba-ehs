"""
RBA 8.0.1 EHS Audit Automation — Web server.
Per-user workspaces, autosave, round-2 re-audit, report archive with ownership
permissions, admin console and backup/restore.
© NGUYỄN NGỌC NGÔN — RBA 8.0.1 EHS Automation Suite
"""
import os
import re
import sys
import json
import base64
import secrets
import shutil
import threading
import time
import datetime
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler

# Windows consoles may not support Vietnamese characters: force UTF-8 output
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
from socketserver import ThreadingMixIn

from engine import (
    BASE_DIR, OUTPUT_DIR,
    load_checklist_reference, parse_findings_xlsm,
    generate_checklist_xlsx, generate_summary_docx, generate_findings_file,
    compute_penalty_violation, build_summary_6_categories, auto_classify_significance,
    audit_period, report_title, cap_violations_pair, select_top_violations,
)
from system_core import (
    STORAGE_DIR, DB_DIR, MASTER_RULES_FILE,
    init_auth_config, load_auth_config, save_auth_config,
    authenticate_user, get_session_context, check_permission, add_audit_log,
    _hash_password, ACTIVE_SESSIONS, change_password, password_policy_error, security_settings, restore_record_revision, delete_record_revisions, STORAGE_FOLDERS,
    save_master_rules, run_qa_checks, apply_qa_fixes_to_data,
    load_file_repository, save_file_repository, archive_audit_session, get_storage_overview,
    get_or_create_local_admin_session, DEFAULT_PASSWORDS, set_finding_vietnamese, remember_translation,
)
from round2 import build_round2, rescore_round2, build_round2_export_data, build_round2_docx_data
import backup
import notify
import learning
from history import detect_recurring
from merge_findings import merge_findings_files
from report_pdf import pdf_engine, build_report_html, make_pdf, make_zip
from translator import EXPORT_LANG_MODES, normalize_export_lang

init_auth_config()
CHECKLIST_REF = load_checklist_reference()
AUTOSAVE_DIR = os.path.join(DB_DIR, "autosave")
SESSIONS_FILE = os.path.join(DB_DIR, "sessions.json")
os.makedirs(AUTOSAVE_DIR, exist_ok=True)
LOCK = threading.RLock()

# Listens on this machine only by default; HOST=0.0.0.0 shares it on the LAN
BIND_HOST = os.environ.get('HOST', '127.0.0.1')
# Set RBA_TRUST_PROXY=1 only behind a reverse proxy (Funnel, ngrok...) that sets the forwarded headers itself
TRUST_PROXY = os.environ.get('RBA_TRUST_PROXY') == '1'
LOOPBACK_HOSTS = ('127.0.0.1', 'localhost')
LOOPBACK_IPS = ('127.0.0.1', '::1', '::ffff:127.0.0.1')
MAX_BODY_BYTES = 100 * 1024 * 1024
SEVERITIES = ('Conformance', 'Minor', 'Major', 'Priority', 'N/A')
SEV_ORDER = {'N/A': -1, 'Conformance': 0, 'Minor': 1, 'Major': 2, 'Priority': 3}
CONTENT_SECURITY_POLICY = ("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
                           "img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; base-uri 'none'; "
                           "form-action 'self'; frame-ancestors 'none'")

# username -> workspace {mode, data, source_xlsm_path, r1_source_xlsm_path, bound_record_id, dirty, autosaved_at, ver}
WS = {}
VER = {'v': 1}


# ---------------------------------------------------------------------------
# Sessions persistence (users stay signed in across restarts)
# ---------------------------------------------------------------------------
def load_sessions():
    try:
        with open(SESSIONS_FILE, 'r', encoding='utf-8') as f:
            ACTIVE_SESSIONS.update(json.load(f))
    except Exception:
        pass


def persist_sessions():
    try:
        tmp = SESSIONS_FILE + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(ACTIVE_SESSIONS, f, ensure_ascii=False)
        os.replace(tmp, SESSIONS_FILE)
    except Exception:
        pass


load_sessions()


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------
def recalculate_state(data, reclassify_from_master=False):
    """Recalculates scores, counts, grade, penalty marks, 6-category breakdown and QA."""
    global CHECKLIST_REF
    CHECKLIST_REF = load_checklist_reference()
    master_items_by_code = {it['audit_id']: it for it in CHECKLIST_REF['items']}
    mand_triggers = CHECKLIST_REF.get('mandatory_triggers', ['mandatory', 'bắt buộc', 'hmbb', 'x', 'yes', '1'])
    checklist = data.get('checklist', [])
    findings = data.get('findings', [])
    findings_by_code = {}
    for f in findings:
        findings_by_code.setdefault(f['audit_id'], []).append(f)

    total_score = 0
    counts = {'Conformance': 0, 'Minor': 0, 'Major': 0, 'Priority': 0, 'N/A': 0}
    for it in checklist:
        cid = it['audit_id']
        m_item = master_items_by_code.get(cid, {})
        if m_item:
            it['scores_table'] = m_item.get('scores', it.get('scores_table', {}))
            it['penalty_item'] = m_item.get('penalty_item', it.get('penalty_item', ''))
            it['penalty_criteria'] = m_item.get('penalty_criteria', it.get('penalty_criteria', ''))
            it['rule'] = m_item.get('rule', it.get('rule', {}))
        if reclassify_from_master and data.get('source_type') != 'checklist':
            f_for_cid = findings_by_code.get(cid, [])
            sig, reason = auto_classify_significance(
                cid, f_for_cid, it.get('criteria_vn', ''), it.get('criteria_en', ''),
                custom_rule=it.get('rule'), mandatory_triggers=mand_triggers)
            base_sig = it.get('checklist_base_sig')
            if base_sig:
                if base_sig == 'N/A' and not f_for_cid:
                    sig = 'N/A'
                elif base_sig != 'N/A' and SEV_ORDER.get(base_sig, 0) > SEV_ORDER.get(sig, 0):
                    sig = base_sig
            it['significance'] = sig
            it['auto_reason'] = reason
        sig = it.get('significance', 'Conformance')
        sc = it.get('scores_table', {}).get(sig, 0)
        it['score'] = sc
        it['violation_mark'] = "X" if sig not in ("Conformance", "N/A") else ""
        it['penalty_violation'] = compute_penalty_violation(it.get('penalty_item', ''), it.get('penalty_criteria', ''), sig)
        total_score += sc
        if sig in counts:
            counts[sig] += 1

    total_score = round(total_score, 2)
    if isinstance(total_score, float) and total_score.is_integer():
        total_score = int(total_score)
    g = CHECKLIST_REF.get('grade_thresholds', {'A': 90, 'B': 80, 'C': 70})
    grade = 'A' if total_score >= g.get('A', 90) else 'B' if total_score >= g.get('B', 80) else 'C' if total_score >= g.get('C', 70) else 'D'
    data['summary'] = {
        'total_findings': len(findings),
        'total_items': len(checklist),
        'violated_items_count': counts['Minor'] + counts['Major'] + counts['Priority'],
        'mandatory_count': sum(1 for f in findings if str(f.get('mandatory', '')).strip().lower() in tuple(t.lower() for t in mand_triggers)),
        'penalty_violation_count': sum(1 for it in checklist if it.get('penalty_violation') == 'X'),
        'total_score': total_score,
        'grade_level': grade,
        'counts': counts,
        'compliance_rate': round((counts['Conformance'] / len(checklist)) * 100, 2) if checklist else 0,
        'category_breakdown': build_summary_6_categories(checklist, CHECKLIST_REF.get('category_groups')),
        'audit_warnings': data.get('summary', {}).get('audit_warnings', []),
    }
    code_to_sig = {it['audit_id']: it['significance'] for it in checklist}
    for ki in data.get('key_issues', []):
        if ki.get('audit_id') in code_to_sig:
            ki['significance'] = code_to_sig[ki['audit_id']]
    if not data.get('doc_violations') and not data.get('facility_violations') and findings:
        data['doc_violations'], data['facility_violations'] = select_top_violations(findings, checklist, max_per_type=3, max_total=5)
    else:
        data['doc_violations'], data['facility_violations'] = cap_violations_pair(
            data.get('doc_violations'), data.get('facility_violations'), max_per_type=3, max_total=5
        )
    data['qa_report'] = run_qa_checks(data)
    return data


# ---------------------------------------------------------------------------
# Payload slimming: photos are served via /api/photo
# ---------------------------------------------------------------------------
def _slim_photos(photos, no, kind, ver):
    return [{'col': ph.get('col'), 'data_url': f"/api/photo?k={kind}&no={no}&i={i}&v={ver}"} for i, ph in enumerate(photos or [])]


def slim(ws):
    data, ver = ws['data'], ws.get('ver', 1)
    out = dict(data)
    by_id = {}
    out['findings'] = []
    for f in data.get('findings', []):
        nf = dict(f)
        nf['photos'] = _slim_photos(f.get('photos'), f.get('no'), 'p', ver)
        nf['after_photos'] = _slim_photos(f.get('after_photos'), f.get('no'), 'pa', ver)
        by_id[id(f)] = nf
        out['findings'].append(nf)
    out['checklist'] = [dict(it, findings=[by_id.get(id(f)) or dict(f, photos=_slim_photos(f.get('photos'), f.get('no'), 'p', ver))
                                          for f in it.get('findings', [])]) for it in data.get('checklist', [])]
    out['key_issues'] = [dict(k, photos=_slim_photos(k.get('photos'), k.get('no'), 'p', ver)) for k in data.get('key_issues', [])]
    if data.get('round2'):
        r2 = dict(data['round2'])
        r2['items'] = [dict(i, after_photos=_slim_photos(i.get('after_photos'), i['r1_no'], 'a', ver)) for i in r2.get('items', [])]
        r2['new_findings'] = [dict(n, after_photos=_slim_photos(n.get('after_photos'), n['r2_no'], 'na', ver),
                                   photos=_slim_photos(n.get('photos'), n['r2_no'], 'np', ver)) for n in r2.get('new_findings', [])]
        out['round2'] = r2
    if data.get('round2'):
        v = build_round2_docx_data(data)
        out['round2_doc'] = {
            'doc_violations': v['doc_violations'],
            'facility_violations': v['facility_violations'],
            'checklist': [{'audit_id': it['audit_id'], 'significance': it['significance'], 'evidence_text': it.get('evidence_text', ''),
                           'issues': [f['issue_vn'] for f in it['findings']]} for it in v['checklist']],
            'key_issues': [dict(k, photos=_slim_photos(k.get('photos'), k['no'], 'np' if k.get('is_new') else 'p', ver)) for k in v['key_issues']],
        }
    out['report_title'] = report_title(data.get('metadata', {}), 2 if data.get('round2') else 1)
    out['_ws'] = {
        'mode': ws.get('mode', 'round1'),
        'bound_record_id': ws.get('bound_record_id'),
        'bound_title': ws.get('bound_title', ''),
        'dirty': ws.get('dirty', False),
        'autosaved_at': ws.get('autosaved_at', ''),
    }
    return out


def find_photo(ws, kind, no, idx):
    data = ws['data']
    try:
        if kind in ('p', 'pa'):
            f = next(f for f in data.get('findings', []) if f.get('no') == no)
            return (f.get('photos') if kind == 'p' else f.get('after_photos', []))[idx]
        r2 = data.get('round2') or {}
        if kind == 'a':
            return next(i for i in r2.get('items', []) if i['r1_no'] == no)['after_photos'][idx]
        n = next(n for n in r2.get('new_findings', []) if n['r2_no'] == no)
        return (n.get('after_photos') if kind == 'na' else n.get('photos'))[idx]
    except (StopIteration, IndexError, KeyError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Workspaces & autosave
# ---------------------------------------------------------------------------
def _autosave_path(username):
    safe = ''.join(ch for ch in username if ch.isalnum() or ch in '-_') or 'user'
    return os.path.join(AUTOSAVE_DIR, f"{safe}.json")


def autosave_info(username):
    p = _autosave_path(username)
    if not os.path.exists(p):
        return None
    try:
        with open(p, 'r', encoding='utf-8') as f:
            head = json.load(f)
        m = head.get('data', {}).get('metadata', {})
        return {'saved_at': head.get('saved_at', ''), 'mode': head.get('mode', 'round1'),
                'vendor': m.get('vendor_short', ''), 'audit_date': m.get('audit_date_raw', ''),
                'score': head.get('data', {}).get('summary', {}).get('total_score'),
                'bound_title': head.get('bound_title', '')}
    except Exception:
        return None


def write_autosave(username, ws):
    p = _autosave_path(username)
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    payload = {k: ws.get(k) for k in ('mode', 'source_xlsm_path', 'r1_source_xlsm_path', 'bound_record_id', 'bound_title', 'source_parts')}
    payload.update({'saved_at': now, 'data': ws['data']})
    with open(p + '.tmp', 'w', encoding='utf-8') as f:
        json.dump(payload, f, ensure_ascii=False)
    os.replace(p + '.tmp', p)
    ws['dirty'] = False
    ws['autosaved_at'] = now
    return now


def local_path(path):
    """Saved paths name the folder of the machine that wrote them: re-roots them after the app moves."""
    if not path or os.path.exists(path):
        return path
    norm = path.replace('\\', '/')
    for folder, root in (('storage', STORAGE_DIR), ('output', OUTPUT_DIR)):
        if f'/{folder}/' in norm:
            return os.path.join(root, *norm.rsplit(f'/{folder}/', 1)[1].split('/'))
    return path


def new_ws(mode, data, source, **extra):
    VER['v'] += 1
    ws = {'mode': mode, 'data': data, 'source_xlsm_path': source, 'bound_record_id': None, 'bound_title': '',
          'dirty': True, 'autosaved_at': '', 'ver': VER['v']}
    ws.update(extra)
    for key in ('source_xlsm_path', 'r1_source_xlsm_path'):
        ws[key] = local_path(ws.get(key))
    ws['source_parts'] = {k: local_path(v) for k, v in (ws.get('source_parts') or {}).items() if v}
    return ws


def find_record(record_id):
    repo = load_file_repository()
    return repo, next((r for r in repo.get('records', []) if r['record_id'] == record_id), None)


def load_bundle(rec):
    rel = (rec.get('files', {}).get('bundle') or {}).get('rel_path', '')
    p = os.path.join(STORAGE_DIR, rel)
    if not rel or not os.path.exists(p):
        raise FileNotFoundError('Không tìm thấy gói dữ liệu của báo cáo trên đĩa!')
    with open(p, 'r', encoding='utf-8') as f:
        return json.load(f)


def bundle_source_parts(bundle):
    """{'field': abs_path, 'doc': abs_path} of a saved bundle (stored relative to storage/)."""
    out = {}
    for k, rel in (bundle.get('source_parts') or {}).items():
        if rel:
            out[k] = rel if os.path.isabs(rel) else os.path.join(STORAGE_DIR, rel)
    return out


def load_record_into_ws(rec):
    """Returns a workspace for a round-1 or round-2 record."""
    bundle = load_bundle(rec)
    if int(rec.get('round', 1)) >= 2 or bundle.get('round2'):
        _, parent = find_record(rec.get('parent_record_id') or bundle.get('parent_record_id'))
        if not parent:
            raise FileNotFoundError('Báo cáo lần 1 gốc đã bị xóa — không thể mở báo cáo lần 2.')
        pb = load_bundle(parent)
        data = recalculate_state(pb['data'])
        data['round2'] = bundle['round2']
        rescore_round2(data, data['round2'], CHECKLIST_REF)
        return new_ws('round2', data, bundle.get('source_xlsm_path'),
                      r1_source_xlsm_path=pb.get('source_xlsm_path'), parent_record_id=parent['record_id'])
    data = recalculate_state(bundle['data'])
    return new_ws('round1', data, bundle.get('source_xlsm_path'), source_parts=bundle_source_parts(bundle))


# ---------------------------------------------------------------------------
# Two-slot Finding upload: File hiện trường (field) + File tài liệu (doc)
# ---------------------------------------------------------------------------
SLOT_NAMES = {'field': 'File hiện trường', 'doc': 'File tài liệu'}


def save_upload(item, tag):
    """Writes an uploaded {filename, file_base64} into output/ and returns (path, filename)."""
    filename = os.path.basename(str(item.get('filename') or f'{tag}.xlsm'))
    up = os.path.join(OUTPUT_DIR, f"upload_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}_{secrets.token_hex(3)}_{tag}_{filename}")
    with open(up, 'wb') as f:
        f.write(base64.b64decode(item.get('file_base64', '')))
    return up, filename


def _merge_checklist_metadata_and_ratings(data, info, ref):
    """
    When one or both uploaded files are RBA Audit Checklist (.xlsx) workbooks, merges:
      1) Rich General Information metadata (workers, address, dormitory, cafeteria, legal, etc.)
      2) 41-item Checklist significance ratings & observation marks (O..R) with field findings.
    """
    chk_map = info.get('checklist_data') or {}
    if not chk_map:
        return

    f_meta = dict(data.get('metadata') or {})
    primary_chk = chk_map.get('doc') or chk_map.get('field')
    merged_meta = dict(primary_chk.get('metadata') or {})
    other_chk = chk_map.get('field') if ('doc' in chk_map and 'field' in chk_map) else None
    if other_chk:
        for k, v in (other_chk.get('metadata') or {}).items():
            if merged_meta.get(k) in ('', None) and v not in ('', None):
                merged_meta[k] = v

    f_is_yousung_sample = (
        'YOUSUNG' in str(f_meta.get('vendor_short', '')).upper()
        and 'YOUSUNG' not in str(merged_meta.get('vendor_short', '')).upper()
        and bool(merged_meta.get('vendor_short'))
    )
    for k in ('subsidiary', 'vendor_code', 'vendor_short', 'vendor_full', 'audit_date_raw'):
        fv = f_meta.get(k)
        if merged_meta.get(k) in ('', None) and fv not in ('', None):
            if f_is_yousung_sample and k in ('vendor_code', 'subsidiary', 'vendor_short', 'vendor_full'):
                continue
            merged_meta[k] = fv

    if not f_is_yousung_sample and f_meta.get('auditor_raw'):
        names_seen = []
        for raw_str in (merged_meta.get('auditor_raw', ''), f_meta.get('auditor_raw', '')):
            for nm in str(raw_str).split(','):
                nm = nm.strip()
                if nm and nm.lower() not in {x.lower() for x in names_seen}:
                    names_seen.append(nm)
        if names_seen:
            merged_meta['auditor_1'] = names_seen[0]
            merged_meta['auditor_2'] = ', '.join(names_seen[1:])
            merged_meta['auditor_raw'] = ', '.join(names_seen)
            if not merged_meta.get('auditor_short') or merged_meta.get('auditor_short') == primary_chk.get('metadata', {}).get('auditor_raw'):
                merged_meta['auditor_short'] = merged_meta['auditor_raw']
    data['metadata'] = merged_meta

    mand_triggers = ref.get('mandatory_triggers', ['mandatory', 'bắt buộc', 'hmbb', 'x', 'yes', '1'])
    chk_items = {
        slot: {it['audit_id']: it for it in cd.get('checklist', [])}
        for slot, cd in chk_map.items()
    }
    kinds = info.get('kinds') or {}
    active_slots = [s for s in ('field', 'doc') if s in kinds]
    single_checklist_only = (len(active_slots) == 1 and active_slots[0] in chk_items)
    if single_checklist_only:
        data['source_type'] = 'checklist'

    for it in data.get('checklist', []):
        code = it['audit_id']
        all_fs = it.get('findings') or []
        field_fs = [f for f in all_fs if f.get('source_slot') == 'field']
        doc_fs = [f for f in all_fs if f.get('source_slot') == 'doc']
        doc_chk = chk_items.get('doc', {}).get(code)
        field_chk = chk_items.get('field', {}).get(code)

        for obs_k in ('site_observation', 'record_review', 'mgmt_interview', 'worker_interview'):
            val = (doc_chk or {}).get(obs_k) or (field_chk or {}).get(obs_k) or it.get(obs_k, '')
            if val:
                it[obs_k] = val
        if field_fs:
            it['site_observation'] = 'O'
        if doc_fs:
            it['record_review'] = 'O'

        if single_checklist_only:
            only_slot = active_slots[0]
            c_it = chk_items[only_slot][code]
            sig = c_it['significance']
            it['significance'] = sig
            it['auto_significance'] = sig
            it['checklist_base_sig'] = sig
            it['auto_reason'] = c_it.get('auto_reason') or f"Theo đánh giá trên {SLOT_NAMES[only_slot]} ({sig})"
            if not all_fs and c_it.get('evidence_text'):
                it['evidence_text'] = c_it['evidence_text']
            continue

        doc_sig = doc_chk['significance'] if doc_chk else (
            auto_classify_significance(
                code, doc_fs, it.get('criteria_vn', ''), it.get('criteria_en', ''),
                custom_rule=it.get('rule'), mandatory_triggers=mand_triggers
            )[0] if doc_fs else None
        )
        field_sig = field_chk['significance'] if field_chk else (
            auto_classify_significance(
                code, field_fs, it.get('criteria_vn', ''), it.get('criteria_en', ''),
                custom_rule=it.get('rule'), mandatory_triggers=mand_triggers
            )[0] if field_fs else None
        )
        comb_sig = (
            auto_classify_significance(
                code, all_fs, it.get('criteria_vn', ''), it.get('criteria_en', ''),
                custom_rule=it.get('rule'), mandatory_triggers=mand_triggers
            )[0] if (field_fs and doc_fs) else None
        )

        if field_sig is None and doc_sig is not None:
            sig = doc_sig
            reason = f"Tổng hợp: Tài liệu ({doc_sig}) + Hiện trường (0 lỗi) ➔ {sig}"
        elif doc_sig is None and field_sig is not None:
            sig = field_sig
            reason = f"Tổng hợp: Hiện trường ({field_sig}) + Tài liệu (0 lỗi) ➔ {sig}"
        else:
            cands = [s for s in (doc_sig, field_sig, comb_sig) if s and s != 'N/A']
            sig = max(cands, key=lambda x: SEV_ORDER.get(x, 0)) if cands else 'N/A'
            reason = f"Tổng hợp: Tài liệu ({doc_sig or '0 lỗi'}) + Hiện trường ({field_sig or '0 lỗi'}) ➔ {sig}"

        it['significance'] = sig
        it['auto_significance'] = sig
        it['checklist_base_sig'] = sig
        it['auto_reason'] = reason
        if not all_fs:
            ev_fb = (doc_chk or {}).get('evidence_text') or (field_chk or {}).get('evidence_text')
            if ev_fb:
                it['evidence_text'] = ev_fb


def combine_and_parse(parts, names=None):
    """
    parts = {'field': path|None, 'doc': path|None}. Merges both files (either may be Findings
    .xlsm/.xlsx or RBA Audit Checklist .xlsx, and either may be missing) into a unified
    Findings workbook and parses + scores the combined 41-item audit. Returns (data, combined_path).
    """
    names = names or {}
    field, doc = parts.get('field'), parts.get('doc')
    if not field and not doc:
        raise ValueError('Vui lòng chọn ít nhất 1 file: File hiện trường hoặc File tài liệu.')
    combined = os.path.join(OUTPUT_DIR, f"upload_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}_{secrets.token_hex(3)}_TONG_HOP.xlsm")
    out, info = merge_findings_files(field, doc, combined)
    combined = out or (field or doc)
    ref = load_checklist_reference()
    data = parse_findings_xlsm(combined, ref)

    row_slots = info.get('row_slots') or {}
    for f in data.get('findings', []):
        f['source_slot'] = row_slots.get(f.get('excel_row'))

    if info.get('checklist_data'):
        _merge_checklist_metadata_and_ratings(data, info, ref)

    # Recompute top violations and key issues using the final combined 41-item significances
    data['doc_violations'], data['facility_violations'] = select_top_violations(
        data.get('findings', []), data.get('checklist', []), max_per_type=3, max_total=5
    )
    code_to_sig = {it['audit_id']: it['significance'] for it in data.get('checklist', [])}
    photo_kis, text_kis, used_nos = [], [], set()
    for sig_order in ('Priority', 'Major', 'Minor'):
        for f_obj in data.get('findings', []):
            if f_obj['no'] in used_nos or code_to_sig.get(f_obj['audit_id']) != sig_order:
                continue
            entry = {
                'no': f_obj['no'],
                'excel_row': f_obj['excel_row'],
                'audit_id': f_obj['audit_id'],
                'significance': sig_order,
                'issue_vn': f_obj['issue_vn'],
                'photos': f_obj.get('photos', []),
            }
            if f_obj.get('photos') and len(photo_kis) < 5:
                photo_kis.append(entry)
                used_nos.add(f_obj['no'])
            elif not f_obj.get('photos') and len(text_kis) < 5:
                text_kis.append(entry)
                used_nos.add(f_obj['no'])
    data['key_issues'] = photo_kis if photo_kis else text_kis[:5]
    recalculate_state(data)

    sources = {}
    kinds = info.get('kinds') or {}
    for slot in ('field', 'doc'):
        p = parts.get(slot)
        sources[slot] = (
            {'filename': names.get(slot) or _display_name(p), 'findings': info.get(slot), 'kind': kinds.get(slot)}
            if p else None
        )
    data['sources'] = sources
    warns = data.setdefault('summary', {}).setdefault('audit_warnings', [])
    for slot in ('field', 'doc'):
        if not sources[slot]:
            warns.insert(0, f"Chưa có {SLOT_NAMES[slot]}: kết quả hiện chỉ tổng hợp từ "
                            f"{SLOT_NAMES['doc' if slot == 'field' else 'field']}. Có thể bổ sung sau ở mục Nạp file Finding hoặc Kho lưu trữ.")
    return data, combined


def _display_name(path):
    base = os.path.basename(path or '')
    m = re.match(r'^upload_\d+_[0-9a-f]+_(?:field|doc)_(.*)$', base)
    if m:
        return m.group(1)
    m = re.match(r'^.*?_(?:HIEN_TRUONG|TAI_LIEU)_(.*)$', base)
    return m.group(1) if m else base


def carry_over_edits(old, new):
    """Keeps what the auditor typed by hand when a missing file is added later."""
    om, nm = old.get('metadata', {}), new.get('metadata', {})
    for k, v in om.items():
        if v not in ('', None) and nm.get(k) in ('', None):
            nm[k] = v
    for k in ('report_date', 'gbm'):
        if om.get(k):
            nm[k] = om[k]
    manual = {it['audit_id']: it for it in old.get('checklist', []) if str(it.get('auto_reason', '')).startswith('Điều chỉnh thủ công')}
    for it in new.get('checklist', []):
        o = manual.get(it['audit_id'])
        if o and o.get('significance') in SEVERITIES:
            it['auto_significance'] = it.get('significance')
            it['significance'] = o['significance']
            it['auto_reason'] = o['auto_reason']
    return new


# ---------------------------------------------------------------------------
# Storage permissions: view / edit / delete (admin, or owner with permission)
# ---------------------------------------------------------------------------
def can_record(token, rec, action):
    ctx = get_session_context(token)
    if not ctx['authenticated']:
        return False
    if ctx['user']['role'] == 'admin':
        return True
    perm = {'view': 'can_view_storage', 'edit': 'can_edit_storage', 'delete': 'can_delete_storage'}[action]
    if not ctx['permissions'].get(perm):
        return False
    return bool(rec.get('owner_username')) and rec.get('owner_username') == ctx['user']['username']


def record_files(rec):
    """File entries of a record: the current ones and those of its older revisions."""
    yield from (rec.get('files') or {}).values()
    for rev in rec.get('revisions') or []:
        yield from (rev.get('files') or {}).values()


def storage_for_token(token):
    overview = get_storage_overview()
    ctx = get_session_context(token)
    is_admin = ctx['authenticated'] and ctx['user']['role'] == 'admin'
    overview['records'] = [r for r in overview.get('records', []) if can_record(token, r, 'view')]
    for rec in overview['records']:
        rec.pop('finding_index', None)
        rec['revisions'] = [{k: v for k, v in e.items() if k != 'finding_index'} for e in rec.get('revisions', [])]
        rec['can_edit'] = can_record(token, rec, 'edit')
        rec['can_delete'] = can_record(token, rec, 'delete')
        rec.setdefault('round', 1)
    if not is_admin:
        overview['folders'] = []
        overview['storage_root'] = ''
    return overview


def output_paths(ws):
    """File names follow the template naming and the audit round: ..._Lần 1.2026 / ..._Lần 2.2026"""
    meta = ws['data']['metadata']
    vendor = str(meta.get('vendor_short', 'VENDOR')).replace('/', '_')
    rnd = 2 if ws['mode'] == 'round2' else 1
    year, ymd = audit_period(meta)
    stamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S_%f')
    xname = f"{ymd}_{vendor}_RBA Audit checklist_Lần {rnd}.{year}.xlsx"
    dname = f"{ymd}_{vendor}_Tóm tắt kết quả đánh giá định kỳ RBA 8.0.1_Lần {rnd}.{year}.docx"
    return (os.path.join(OUTPUT_DIR, f"{stamp}_{xname}"), os.path.join(OUTPUT_DIR, f"{stamp}_{dname}"), xname, dname)


def build_outputs(ws, lang_mode=None, need_xlsx=True, need_docx=True):
    """Generates the Checklist (.xlsx) and/or Word report (.docx) for the workspace in `lang_mode`."""
    mode = normalize_export_lang(lang_mode or 'vi_ko')
    xlsx, docx, xname, dname = output_paths(ws)
    data = ws['data']
    if ws['mode'] == 'round2':
        if need_xlsx:
            generate_checklist_xlsx(build_round2_export_data(data), xlsx, lang_mode=mode)
        if need_docx:
            generate_summary_docx(build_round2_docx_data(data), docx,
                                  source_xlsm_path=ws.get('r1_source_xlsm_path') or ws['source_xlsm_path'],
                                  round2_summary=data['round2']['summary2'], round_no=2, lang_mode=mode)
    else:
        recalculate_state(data)
        if need_xlsx:
            generate_checklist_xlsx(data, xlsx, lang_mode=mode)
        if need_docx:
            generate_summary_docx(data, docx, source_xlsm_path=ws['source_xlsm_path'], round_no=1, lang_mode=mode)
    return xlsx, docx, xname, dname


def build_findings(ws, lang_mode=None):
    """(path, download name) of the Findings file in `lang_mode`."""
    mode = normalize_export_lang(lang_mode or 'vi_ko')
    source = ws.get('source_xlsm_path')
    meta = ws['data']['metadata']
    rnd = 2 if ws['mode'] == 'round2' else 1
    year, ymd = audit_period(meta)
    ext = os.path.splitext(source or '.xlsm')[1] or '.xlsm'
    name = f"{ymd}_{str(meta.get('vendor_short', 'VENDOR')).replace('/', '_')}_EHS Audit Findings_Lần {rnd}.{year}{ext}"
    if ws['mode'] == 'round1' and source and os.path.exists(source):
        out = os.path.join(OUTPUT_DIR, f"{datetime.datetime.now().strftime('%Y%m%d_%H%M%S_%f')}_{name}")
        try:
            return generate_findings_file(ws['data'], source, out, lang_mode=mode), name
        except ValueError:
            # Older Checklist-only record whose source was .xlsx without Findings sheet: synthesize .xlsm
            try:
                synth = os.path.join(OUTPUT_DIR, f"synth_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.xlsm")
                merge_findings_files(None, source, synth)
                name_xlsm = os.path.splitext(name)[0] + '.xlsm'
                out_xlsm = os.path.splitext(out)[0] + '.xlsm'
                return generate_findings_file(ws['data'], synth, out_xlsm, lang_mode=mode), name_xlsm
            except Exception as e2:
                print('Findings synth export failed:', e2)
        except (KeyError, OSError) as e:
            print('Findings export failed:', e)
    return source, name


FINDINGS_CTYPE = {'.xlsm': 'application/vnd.ms-excel.sheet.macroEnabled.12',
                  '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'}


def docx_view_data(ws):
    return build_round2_docx_data(ws['data']) if ws['mode'] == 'round2' else ws['data']


def build_pdf_for_ws(ws, docx_path, pdf_name, lang_mode=None):
    mode = normalize_export_lang(lang_mode or 'vi_ko')
    data = ws['data']
    r2s = data['round2']['summary2'] if ws['mode'] == 'round2' else None
    title = report_title(data.get('metadata', {}), 2 if r2s else 1)
    html_text = build_report_html(docx_view_data(ws), r2s, title, lang_mode=mode)
    out = os.path.join(OUTPUT_DIR, f"{datetime.datetime.now().strftime('%Y%m%d_%H%M%S_%f')}_{pdf_name}")
    return make_pdf(docx_path, html_text, out)


def record_notice(rec, verb):
    rnd = int(rec.get('round', 1))
    subject = f"[RBA 8.0.1] {verb}: {rec.get('vendor_short', '')} · Lần {rnd} · {rec.get('total_score')} điểm ({rec.get('grade_level')})"
    body = (f"Báo cáo: {rec.get('title') or rec['record_id']}\nMã: {rec['record_id']}\nNhà máy: {rec.get('vendor_full') or rec.get('vendor_short')} ({rec.get('vendor_code')})\n"
            f"Ngày đánh giá: {rec.get('audit_date')}\nĐánh giá lần: {rnd}\nTổng điểm: {rec.get('total_score')} · Xếp hạng: {rec.get('grade_level')}\n"
            f"Số mục vi phạm: {rec.get('violated_items_count')}/41\nNgười thực hiện: {rec.get('updated_by') or rec.get('created_by')}\nGhi chú: {rec.get('note', '')}")
    files = []
    for key in ('checklist', 'report'):
        fm = (rec.get('files') or {}).get(key)
        if fm and fm.get('rel_path'):
            files.append((os.path.join(STORAGE_DIR, fm['rel_path']), fm['filename']))
    return subject, body, files


def cleanup_output_dir(max_age_hours=6):
    now = time.time()
    for fn in os.listdir(OUTPUT_DIR):
        p = os.path.join(OUTPUT_DIR, fn)
        if os.path.isfile(p) and not fn.startswith('upload_') and now - os.path.getmtime(p) > max_age_hours * 3600:
            try:
                os.remove(p)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------
class RBAAuditHandler(BaseHTTPRequestHandler):
    timeout = 120  # a stalled client must not hold a thread forever

    def end_headers(self):
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', CONTENT_SECURITY_POLICY)
        super().end_headers()

    def log_message(self, fmt, *args):
        if '/api/photo' not in str(args[0] if args else ''):
            super().log_message(fmt, *args)

    def _token(self, parsed):
        h = self.headers.get('X-Auth-Token', '') or self.headers.get('Authorization', '')
        if h.startswith('Bearer '):
            h = h[7:]
        return h.strip() or urllib.parse.parse_qs(parsed.query).get('token', [''])[0]

    def _json(self, obj, status=200):
        payload = json.dumps(obj, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(payload)

    def _err(self, msg, status=400):
        self._json({'status': 'error', 'message': msg}, status)

    def _file(self, path, filename, ctype):
        with open(path, 'rb') as f:
            data = f.read()
        self.send_response(200)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Disposition', f"attachment; filename*=UTF-8''{urllib.parse.quote(filename)}")
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _peer_ip(self):
        return self.client_address[0] if getattr(self, 'client_address', None) else ''

    def _client_ip(self):
        # Forwarded headers are client-controlled unless a local reverse proxy wrote them:
        # visitors can prepend anything to X-Forwarded-For, only the last entry is the proxy's
        forwarded = self.headers.get('X-Forwarded-For', '')
        if TRUST_PROXY and forwarded and self._peer_ip() in LOOPBACK_IPS:
            return forwarded.split(',')[-1].strip()
        return self._peer_ip()

    def _request_host(self):
        return (self.headers.get('Host', '') or '').split(':')[0].strip().lower()

    def _host_allowed(self):
        """DNS-rebinding guard: a loopback-only server answers to loopback names only."""
        return TRUST_PROXY or BIND_HOST not in LOOPBACK_HOSTS or self._request_host() in LOOPBACK_HOSTS

    def _is_local_mac_direct(self):
        for h in ('CF-Connecting-IP', 'X-Forwarded-For', 'X-Real-IP', 'Tailscale-Funnel-Request', 'Forwarded'):
            if self.headers.get(h, '').strip():
                return False
        return self._request_host() in LOOPBACK_HOSTS and self._peer_ip() in LOOPBACK_IPS

    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', '0')
        self.end_headers()

    def _ctx(self, token):
        ctx = get_session_context(token)
        user = ctx['user'] if ctx['authenticated'] else None
        return ctx, (user['username'] if user else None), (user['display_name'] if user else 'Khách')

    def _admin_data(self):
        cfg = load_auth_config()
        return {
            'users': [{'username': u['username'], 'display_name': u.get('display_name', u['username']),
                       'role': u.get('role', 'guest'), 'active': u.get('active', True), 'created_at': u.get('created_at', '')}
                      for u in cfg.get('users', [])],
            'guest_permissions': cfg.get('guest_permissions', {}),
            'allow_quick_guest_login': cfg.get('allow_quick_guest_login', True),
            'audit_logs': cfg.get('audit_logs', [])[:80],
        }

    def _session_payload(self, token):
        ctx = get_session_context(token)
        eng = pdf_engine()
        ctx['pdf_engine'] = eng['label'] if eng else None
        if not self._is_local_mac_direct():
            ctx['allow_quick_guest_login'] = False
        if ctx['authenticated'] and ctx['user']['role'] == 'admin':
            ctx['admin_data'] = self._admin_data()
        return ctx

    def _need(self, token, perm):
        ok, msg = check_permission(token, perm)
        if not ok:
            self._err(msg, 403)
        return ok

    def _need_admin(self, token):
        ctx = get_session_context(token)
        if not ctx['authenticated'] or ctx['user']['role'] != 'admin':
            self._err('Chỉ Admin mới có quyền thực hiện thao tác này!', 403)
            return False
        return True

    def _ws(self, token, required=True):
        _, uname, _ = self._ctx(token)
        ws = WS.get(uname) if uname else None
        if required and not ws:
            self._err('Chưa có dữ liệu đánh giá. Vui lòng nạp file Finding hoặc mở một báo cáo.', 409)
        return uname, ws

    # ------------------------------------------------------------------ GET
    def do_GET(self):
        if not self._host_allowed():
            return self.send_error(403, 'Forbidden')
        parsed = urllib.parse.urlparse(self.path)
        path, token = parsed.path, self._token(parsed)
        qs = urllib.parse.parse_qs(parsed.query)

        if path in ('/', '/index.html'):
            with open(os.path.join(BASE_DIR, 'index.html'), 'rb') as f:
                content = f.read()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(content)))
            self.send_header('Cache-Control', 'no-cache')
            self.end_headers()
            self.wfile.write(content)
            return

        if path.startswith('/static/'):
            static_root = os.path.abspath(os.path.join(BASE_DIR, 'static'))
            target = os.path.abspath(os.path.join(static_root, path[len('/static/'):]))
            if not target.startswith(static_root + os.sep) or not os.path.isfile(target):
                return self.send_error(404, 'Not Found')
            ctype = {'.js': 'application/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
                     '.png': 'image/png', '.svg': 'image/svg+xml', '.woff2': 'font/woff2', '.zip': 'application/zip', '.webmanifest': 'application/manifest+json'}.get(os.path.splitext(target)[1].lower(), 'application/octet-stream')
            with open(target, 'rb') as f:
                content = f.read()
            self.send_response(200)
            self.send_header('Content-Type', ctype)
            self.send_header('Content-Length', str(len(content)))
            self.send_header('Cache-Control', 'public, max-age=604800')
            self.end_headers()
            self.wfile.write(content)
            return

        if path == '/api/auth/session':
            sess = self._session_payload(token)
            if not sess.get('authenticated') and qs.get('manual_logout', [''])[0] != '1' and self._is_local_mac_direct():
                with LOCK:
                    new_tok = get_or_create_local_admin_session()
                    persist_sessions()
                    sess = self._session_payload(new_tok)
                    sess['token'] = new_tok
            return self._json(sess)

        if path == '/api/state':
            ctx, uname, _ = self._ctx(token)
            if not uname:
                return self._err('Vui lòng đăng nhập!', 401)
            ws = WS.get(uname)
            if not ws:
                return self._json({'empty': True, 'autosave': autosave_info(uname)})
            return self._json(slim(ws))

        if path == '/api/photo':
            _, uname, _ = self._ctx(token)
            ws = WS.get(uname) if uname else None
            try:
                ph = find_photo(ws, qs.get('k', ['p'])[0], int(qs.get('no', ['0'])[0]), int(qs.get('i', ['0'])[0])) if ws else None
            except ValueError:
                ph = None
            if not ph or not str(ph.get('data_url', '')).startswith('data:'):
                return self.send_error(404, 'Photo not found')
            header, b64 = ph['data_url'].split(',', 1)
            img = base64.b64decode(b64)
            self.send_response(200)
            self.send_header('Content-Type', header[5:].split(';')[0] or 'image/jpeg')
            self.send_header('Content-Length', str(len(img)))
            self.send_header('Cache-Control', 'private, max-age=86400')
            self.end_headers()
            self.wfile.write(img)
            return

        if path == '/api/master_rules':
            if not self._need_admin(token):
                return
            with open(MASTER_RULES_FILE, 'r', encoding='utf-8') as f:
                return self._json(json.load(f))

        if path == '/api/storage/list':
            if not self._need(token, 'can_view_storage'):
                return
            return self._json(storage_for_token(token))

        if path == '/api/storage/download':
            if not self._need(token, 'can_view_storage'):
                return
            abs_t = os.path.abspath(os.path.join(STORAGE_DIR, qs.get('rel_path', [''])[0]))
            if not abs_t.startswith(os.path.abspath(STORAGE_DIR) + os.sep) or not os.path.isfile(abs_t):
                return self.send_error(404, 'File not found')
            rel = os.path.relpath(abs_t, os.path.abspath(STORAGE_DIR))
            if get_session_context(token)['user']['role'] != 'admin' and not any(
                    can_record(token, r, 'view') and any((fm or {}).get('rel_path') == rel for fm in record_files(r))
                    for r in load_file_repository().get('records', [])):
                return self.send_error(404, 'File not found')
            ext = os.path.splitext(abs_t)[1].lower()
            ctype = {'.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                     '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'}.get(ext, 'application/octet-stream')
            return self._file(abs_t, os.path.basename(abs_t), ctype)

        if path in ('/api/download/xlsx', '/api/download/docx'):
            is_x = path.endswith('xlsx')
            if not self._need(token, 'can_export_excel' if is_x else 'can_export_word'):
                return
            uname, ws = self._ws(token)
            if not ws:
                return
            if ws['mode'] == 'round2' and not ws['data']['round2'].get('confirmed'):
                return self._err('Kết quả lần 2 chưa được xác nhận. Vui lòng kiểm tra và bấm "Xác nhận kết quả lần 2" trước khi xuất file.', 409)
            lang = normalize_export_lang(qs.get('lang', ['vi_ko'])[0])
            with LOCK:
                xlsx, docx, xname, dname = build_outputs(ws, lang_mode=lang, need_xlsx=is_x, need_docx=not is_x)
            if is_x:
                return self._file(xlsx, xname, 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
            return self._file(docx, dname, 'application/vnd.openxmlformats-officedocument.wordprocessingml.document')

        if path == '/api/download/finding':
            if not self._need(token, 'can_export_excel'):
                return
            uname, ws = self._ws(token)
            if not ws:
                return
            lang = normalize_export_lang(qs.get('lang', ['vi_ko'])[0])
            with LOCK:
                out, name = build_findings(ws, lang_mode=lang)
            return self._file(out, name, FINDINGS_CTYPE.get(os.path.splitext(name)[1], 'application/octet-stream'))

        if path in ('/api/storage/xlsx', '/api/storage/docx'):
            if not self._need(token, 'can_view_storage'):
                return
            repo, rec = find_record(qs.get('record_id', [''])[0])
            if not rec:
                return self._err('Không tìm thấy báo cáo!', 404)
            if not can_record(token, rec, 'view'):
                return self._err('Bạn không có quyền xem báo cáo này.', 403)
            lang = normalize_export_lang(qs.get('lang', ['vi_ko'])[0])
            is_x = path.endswith('xlsx')
            with LOCK:
                xlsx, docx, xname, dname = build_outputs(load_record_into_ws(rec), lang_mode=lang, need_xlsx=is_x, need_docx=not is_x)
            if is_x:
                return self._file(xlsx, xname, 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
            return self._file(docx, dname, 'application/vnd.openxmlformats-officedocument.wordprocessingml.document')

        if path == '/api/storage/finding':
            if not self._need(token, 'can_view_storage'):
                return
            repo, rec = find_record(qs.get('record_id', [''])[0])
            if not rec:
                return self._err('Không tìm thấy báo cáo!', 404)
            if not can_record(token, rec, 'view'):
                return self._err('Bạn không có quyền xem báo cáo này.', 403)
            lang = normalize_export_lang(qs.get('lang', ['vi_ko'])[0])
            with LOCK:
                out, name = build_findings(load_record_into_ws(rec), lang_mode=lang)
            return self._file(out, name, FINDINGS_CTYPE.get(os.path.splitext(name)[1], 'application/octet-stream'))

        if path in ('/api/download/pdf', '/api/download/zip'):
            if not self._need(token, 'can_export_word'):
                return
            if path.endswith('zip') and not self._need(token, 'can_export_excel'):
                return
            uname, ws = self._ws(token)
            if not ws:
                return
            if ws['mode'] == 'round2' and not ws['data']['round2'].get('confirmed'):
                return self._err('Kết quả lần 2 chưa được xác nhận. Vui lòng xác nhận trước khi xuất file.', 409)
            lang = normalize_export_lang(qs.get('lang', ['vi_ko'])[0])
            with LOCK:
                xlsx, docx, xname, dname = build_outputs(ws, lang_mode=lang)
            pdf_name = os.path.splitext(dname)[0] + '.pdf'
            pdf_path, pdf_err = None, None
            try:
                pdf_path, _ = build_pdf_for_ws(ws, docx, pdf_name, lang_mode=lang)
            except Exception as e:
                pdf_err = str(e)
            if path.endswith('pdf'):
                if not pdf_path:
                    return self._err(pdf_err or 'Không tạo được PDF', 500)
                return self._file(pdf_path, pdf_name, 'application/pdf')
            with LOCK:
                entries = [build_findings(ws, lang_mode=lang), (xlsx, xname), (docx, dname), (pdf_path, pdf_name)]
            zname = os.path.splitext(dname)[0].replace('Tóm tắt kết quả đánh giá định kỳ RBA 8.0.1', 'Ho so RBA 8.0.1') + '.zip'
            zpath = make_zip(entries, os.path.join(OUTPUT_DIR, f"{datetime.datetime.now().strftime('%Y%m%d_%H%M%S_%f')}_{zname}"))
            return self._file(zpath, zname, 'application/zip')

        if path in ('/api/storage/pdf', '/api/storage/zip'):
            if not self._need(token, 'can_view_storage'):
                return
            repo, rec = find_record(qs.get('record_id', [''])[0])
            if not rec:
                return self._err('Không tìm thấy báo cáo!', 404)
            if not can_record(token, rec, 'view'):
                return self._err('Bạn không có quyền xem báo cáo này.', 403)
            lang = normalize_export_lang(qs.get('lang', ['vi_ko'])[0])
            with LOCK:
                tmp_ws = load_record_into_ws(rec)
                xlsx, docx, xname, dname = build_outputs(tmp_ws, lang_mode=lang)
            pdf_name = os.path.splitext(dname)[0] + '.pdf'
            pdf_path, pdf_err = None, None
            try:
                with LOCK:
                    pdf_path, _ = build_pdf_for_ws(tmp_ws, docx, pdf_name, lang_mode=lang)
            except Exception as e:
                pdf_err = str(e)
            if path.endswith('pdf'):
                if not pdf_path:
                    return self._err(pdf_err or 'Không tạo được PDF', 500)
                return self._file(pdf_path, pdf_name, 'application/pdf')
            with LOCK:
                entries = [build_findings(tmp_ws, lang_mode=lang), (xlsx, xname), (docx, dname), (pdf_path, pdf_name)]
            zname = f"{rec['record_id']}_Ho_so_RBA_8.0.1.zip"
            zpath = make_zip(entries, os.path.join(OUTPUT_DIR, f"{datetime.datetime.now().strftime('%Y%m%d_%H%M%S_%f')}_{zname}"))
            return self._file(zpath, zname, 'application/zip')

        if path == '/api/admin/notify':
            if not self._need_admin(token):
                return
            return self._json({'status': 'ok', 'config': notify.public_config(), 'events': notify.EVENTS})

        if path == '/api/admin/learning':
            if not self._need_admin(token):
                return
            return self._json({'status': 'ok', 'suggestions': learning.get_suggestions(), 'summary': learning.summary(),
                               'min_events': learning.MIN_EVENTS})

        if path == '/api/admin/backups':
            if not self._need_admin(token):
                return
            return self._json({'status': 'ok', 'backups': backup.list_backups(), 'code_hash': backup.code_hash(),
                               'supervised': os.environ.get('RBA_SUPERVISED') == '1'})

        if path == '/api/admin/backups/download':
            if not self._need_admin(token):
                return
            p = backup.safe_backup_path(qs.get('name', [''])[0])
            if not p:
                return self.send_error(404, 'Backup not found')
            return self._file(p, os.path.basename(p), 'application/zip')

        self.send_error(404, 'Not Found')

    # ------------------------------------------------------------------ POST
    def do_POST(self):
        global CHECKLIST_REF
        if not self._host_allowed():
            return self.send_error(403, 'Forbidden')
        parsed = urllib.parse.urlparse(self.path)
        path, token = parsed.path, self._token(parsed)
        n = int(self.headers.get('Content-Length', 0) or 0)
        if n > MAX_BODY_BYTES:
            self.close_connection = True
            return self._err('Tệp quá lớn (tối đa 100 MB).', 413)
        raw = self.rfile.read(n) if n > 0 else b''
        try:
            body = json.loads(raw.decode('utf-8')) if raw else {}
        except Exception:
            body = {}
        try:
            with LOCK:
                return self._post(path, token, body)
        except Exception as e:  # never leave the client without an answer
            import traceback
            traceback.print_exc()
            return self._err(f'Lỗi hệ thống: {e}', 500)

    def _post(self, path, token, body):
        global CHECKLIST_REF
        ctx, uname, actor = self._ctx(token)

        # ---------------- Auth ----------------
        if path == '/api/auth/login':
            # Quick guests share one workspace and the default passwords are public: host machine only
            if not self._is_local_mac_direct() and (body.get('quick_guest') or str(body.get('password', '')) in DEFAULT_PASSWORDS.values()):
                return self._err('Truy cập từ xa cần tài khoản riêng với mật khẩu đã đổi. Vui lòng liên hệ Admin.', 403)
            res, err = authenticate_user(body.get('username', ''), body.get('password', ''), is_quick_guest=bool(body.get('quick_guest')),
                                         ip=self._client_ip())
            if err:
                return self._err(err, 401)
            persist_sessions()
            sess = self._session_payload(res['token'])
            sess['token'] = res['token']
            return self._json({'status': 'ok', 'session': sess})

        if path == '/api/auth/logout':
            if token in ACTIVE_SESSIONS:
                add_audit_log(ACTIVE_SESSIONS[token].get('display_name', 'User'), 'Đăng xuất khỏi hệ thống')
                del ACTIVE_SESSIONS[token]
                persist_sessions()
            return self._json({'status': 'ok'})

        if not uname:
            return self._err('Phiên đăng nhập đã hết hạn. Vui lòng đăng nhập lại!', 401)

        if path == '/api/auth/change_password':
            err = change_password(token, body.get('old_password', ''), body.get('new_password', ''))
            if err:
                return self._err(err)
            persist_sessions()
            return self._json({'status': 'ok', 'session': self._session_payload(token)})

        if ctx['user'].get('must_change_password'):
            return self._err('Vui lòng đổi mật khẩu mặc định trước khi tiếp tục sử dụng hệ thống.', 403)

        # ---------------- Admin: permissions & users ----------------
        if path == '/api/admin/permissions':
            if not self._need_admin(token):
                return
            cfg = load_auth_config()
            for k, v in (body.get('guest_permissions') or {}).items():
                cfg['guest_permissions'][k] = bool(v)
            if 'allow_quick_guest_login' in body:
                cfg['allow_quick_guest_login'] = bool(body['allow_quick_guest_login'])
            if isinstance(body.get('security'), dict):
                sec = cfg.setdefault('security', {})
                limits = {'session_idle_minutes': (5, 720), 'session_max_hours': (1, 72), 'max_failed_logins': (3, 20), 'lock_minutes': (1, 240)}
                for k, (lo, hi) in limits.items():
                    if k in body['security']:
                        try:
                            sec[k] = max(lo, min(hi, int(body['security'][k])))
                        except (TypeError, ValueError):
                            pass
            save_auth_config(cfg)
            add_audit_log(actor, 'Cập nhật phân quyền tính năng cho Khách')
            return self._json({'status': 'ok'})

        if path == '/api/admin/users':
            if not self._need_admin(token):
                return
            cfg = load_auth_config()
            action, target = body.get('action', ''), body.get('username', '').strip()
            if action == 'create':
                pwd = body.get('password', '').strip()
                if not target or not pwd:
                    return self._err('Vui lòng nhập đầy đủ tên đăng nhập và mật khẩu!')
                if any(u['username'].lower() == target.lower() for u in cfg['users']):
                    return self._err(f"Tài khoản '{target}' đã tồn tại!")
                role = body.get('role', 'guest')
                perr = password_policy_error(target, pwd)
                if perr:
                    return self._err(perr)
                cfg['users'].append({'username': target, 'password_hash': _hash_password(pwd), 'must_change_password': True,
                                     'display_name': body.get('display_name', target).strip() or target,
                                     'role': role if role in ('admin', 'guest') else 'guest', 'active': True,
                                     'created_at': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')})
                add_audit_log(actor, f"Tạo tài khoản '{target}' ({role})")
            elif action in ('toggle_active', 'delete') and target == 'ngocngon':
                return self._err('Không thể khóa/xóa tài khoản Admin gốc ngocngon!')
            elif action == 'toggle_active':
                for u in cfg['users']:
                    if u['username'] == target:
                        u['active'] = not u.get('active', True)
                        add_audit_log(actor, f"{'Mở khóa' if u['active'] else 'Khóa'} tài khoản '{target}'")
            elif action == 'reset_password':
                pwd = body.get('password', '').strip()
                if not pwd:
                    return self._err('Mật khẩu mới không được để trống!')
                perr = password_policy_error(target, pwd)
                if perr:
                    return self._err(perr)
                for u in cfg['users']:
                    if u['username'] == target:
                        u['password_hash'] = _hash_password(pwd)
                        u['must_change_password'] = target != uname
                for t_, s_ in list(ACTIVE_SESSIONS.items()):
                    if s_.get('username') == target and t_ != token:
                        del ACTIVE_SESSIONS[t_]
                persist_sessions()
                add_audit_log(actor, f"Đặt lại mật khẩu tài khoản '{target}'")
            elif action == 'delete':
                cfg['users'] = [u for u in cfg['users'] if u['username'] != target]
                add_audit_log(actor, f"Xóa tài khoản '{target}'")
            save_auth_config(cfg)
            return self._json({'status': 'ok'})

        # ---------------- Admin: master data ----------------
        if path == '/api/master_rules/update':
            if not self._need_admin(token):
                return
            with open(MASTER_RULES_FILE, 'r', encoding='utf-8') as f:
                master = json.load(f)
            ups = body.get('item_updates') or {}
            for it in master.get('items', []):
                up = ups.get(it['audit_id'])
                if not up:
                    continue
                for g, v in (up.get('scores') or {}).items():
                    fv = float(v)
                    it['scores'][g] = int(fv) if fv.is_integer() else fv
                if 'penalty_item' in up:
                    it['penalty_item'] = str(up['penalty_item']).strip().upper()
                if 'penalty_criteria' in up:
                    it['penalty_criteria'] = str(up['penalty_criteria']).strip()
                r_up = up.get('rule') or {}
                it.setdefault('rule', {})
                if 'desc' in r_up:
                    it['rule']['desc'] = str(r_up['desc']).strip()
                if 'major_min_count' in r_up:
                    it['rule']['major_min_count'] = int(r_up['major_min_count'])
                for kw in ('priority_kw', 'major_kw'):
                    if kw in r_up:
                        it['rule'][kw] = [k.strip() for k in r_up[kw] if k.strip()]
            save_master_rules(master, actor=actor)
            ws = WS.get(uname)
            if ws and ws['mode'] == 'round1':
                recalculate_state(ws['data'], reclassify_from_master=True)
                ws['dirty'] = True
            return self._json({'status': 'ok', 'master_rules': master, 'data': slim(ws) if ws else None})

        if path == '/api/master_rules/reset':
            if not self._need_admin(token):
                return
            if os.path.exists(MASTER_RULES_FILE):
                os.remove(MASTER_RULES_FILE)
            CHECKLIST_REF = load_checklist_reference()
            ws = WS.get(uname)
            if ws and ws['mode'] == 'round1':
                recalculate_state(ws['data'], reclassify_from_master=True)
                ws['dirty'] = True
            with open(MASTER_RULES_FILE, 'r', encoding='utf-8') as f:
                master = json.load(f)
            add_audit_log(actor, 'Khôi phục Dữ liệu gốc RBA 8.0.1 về mặc định')
            return self._json({'status': 'ok', 'master_rules': master, 'data': slim(ws) if ws else None})

        # ---------------- Admin: notifications & learning ----------------
        if path == '/api/admin/notify/save':
            if not self._need_admin(token):
                return
            cfg = notify.save_config(body.get('config') or {})
            add_audit_log(actor, 'Cập nhật cấu hình thông báo Email/Zalo')
            return self._json({'status': 'ok', 'config': cfg})

        if path == '/api/admin/notify/test':
            if not self._need_admin(token):
                return
            return self._json({'status': 'ok', 'config': notify.send_test(actor)})

        if path in ('/api/admin/learning/apply', '/api/admin/learning/dismiss'):
            if not self._need_admin(token):
                return
            key = body.get('key', '')
            if path.endswith('apply'):
                try:
                    sug = learning.apply_suggestion(key, actor)
                except KeyError as e:
                    return self._err(str(e))
                CHECKLIST_REF = load_checklist_reference()
                add_audit_log(actor, f"Áp dụng gợi ý dữ liệu gốc: {sug['text']}")
            else:
                learning.dismiss_suggestion(key)
            return self._json({'status': 'ok', 'suggestions': learning.get_suggestions(), 'summary': learning.summary()})

        # ---------------- Admin: backups ----------------
        if path == '/api/admin/backups/create':
            if not self._need_admin(token):
                return
            m = backup.create_backup('manual', include_storage=bool(body.get('include_storage')), actor=actor, note=body.get('note', ''))
            add_audit_log(actor, f"Tạo bản sao lưu {m['name']}")
            return self._json({'status': 'ok', 'backup': m, 'backups': backup.list_backups()})

        if path == '/api/admin/backups/upload':
            if not self._need_admin(token):
                return
            import io as _io, zipfile as _zf
            try:
                raw = base64.b64decode(body.get('file_base64', ''))
                with _zf.ZipFile(_io.BytesIO(raw)) as z:
                    if 'backup_manifest.json' not in z.namelist():
                        return self._err('File không phải bản sao lưu RBA hợp lệ (thiếu manifest).')
            except Exception:
                return self._err('File sao lưu bị lỗi hoặc không phải file .zip')
            fname = os.path.basename(body.get('filename') or '') or 'backup_upload.zip'
            if not re.match(r'^backup_[\w.\-]+\.zip$', fname):
                fname = 'backup_' + datetime.datetime.now().strftime('%Y%m%d_%H%M%S') + '_manual_upload.zip'
            os.makedirs(backup.BACKUP_DIR, exist_ok=True)
            with open(os.path.join(backup.BACKUP_DIR, fname), 'wb') as f:
                f.write(raw)
            add_audit_log(actor, f"Tải lên bản sao lưu {fname}")
            return self._json({'status': 'ok', 'name': fname, 'backups': backup.list_backups()})

        if path == '/api/admin/backups/delete':
            if not self._need_admin(token):
                return
            backup.delete_backup(body.get('name', ''))
            add_audit_log(actor, f"Xóa bản sao lưu {body.get('name', '')}")
            return self._json({'status': 'ok', 'backups': backup.list_backups()})

        if path == '/api/admin/backups/restore':
            if not self._need_admin(token):
                return
            name = body.get('name', '')
            rc, rd, rs = bool(body.get('restore_code', True)), bool(body.get('restore_data', True)), bool(body.get('restore_storage', True))
            m = backup.restore_backup(name, restore_code=rc, restore_data=rd, restore_storage=rs, actor=actor)
            add_audit_log(actor, f"Khôi phục hệ thống từ bản sao lưu {name}")
            notify.send_event('system_restore', f"[RBA 8.0.1] Khôi phục hệ thống từ bản sao lưu", f"Bản sao lưu: {name}\nNgười thực hiện: {actor}\nKhôi phục mã nguồn: {rc} · dữ liệu: {rd} · kho: {rs}")
            CHECKLIST_REF = load_checklist_reference()
            supervised = os.environ.get('RBA_SUPERVISED') == '1'
            if rc and supervised:
                threading.Thread(target=lambda: (time.sleep(1.5), os._exit(3)), daemon=True).start()
            return self._json({'status': 'ok', 'restored': m, 'restarting': bool(rc and supervised),
                               'manual_restart_required': bool(rc and not supervised)})

        # ---------------- Workspace / autosave ----------------
        if path == '/api/workspace/autosave':
            ws = WS.get(uname)
            if not ws:
                return self._json({'status': 'ok', 'saved': False})
            if ws.get('dirty') or body.get('force'):
                return self._json({'status': 'ok', 'saved': True, 'saved_at': write_autosave(uname, ws)})
            return self._json({'status': 'ok', 'saved': False, 'saved_at': ws.get('autosaved_at', '')})

        if path == '/api/workspace/restore':
            p = _autosave_path(uname)
            if not os.path.exists(p):
                return self._err('Không có tiến trình tự động lưu nào.', 404)
            with open(p, 'r', encoding='utf-8') as f:
                snap = json.load(f)
            ws = new_ws(snap.get('mode', 'round1'), snap['data'], snap.get('source_xlsm_path'),
                        r1_source_xlsm_path=snap.get('r1_source_xlsm_path'), source_parts=snap.get('source_parts') or {})
            ws['bound_record_id'], ws['bound_title'] = snap.get('bound_record_id'), snap.get('bound_title', '')
            ws['dirty'], ws['autosaved_at'] = False, snap.get('saved_at', '')
            WS[uname] = ws
            add_audit_log(actor, 'Khôi phục tiến trình đang làm dở (tự động lưu)')
            return self._json({'status': 'ok', 'data': slim(ws)})

        if path in ('/api/workspace/discard', '/api/workspace/close'):
            WS.pop(uname, None)
            p = _autosave_path(uname)
            if os.path.exists(p):
                os.remove(p)
            return self._json({'status': 'ok', 'empty': True})

        # ---------------- Upload round 1 (File hiện trường + File tài liệu) ----------------
        if path == '/api/upload_xlsm':
            if not self._need(token, 'can_upload_findings'):
                return
            items = {slot: body.get(slot) for slot in ('field', 'doc') if isinstance(body.get(slot), dict) and body[slot].get('file_base64')}
            if not items and body.get('file_base64'):  # legacy single upload = field file
                items = {'field': {'filename': body.get('filename', 'findings.xlsm'), 'file_base64': body['file_base64']}}
            if not items:
                return self._err('Vui lòng chọn ít nhất 1 file: File hiện trường hoặc File tài liệu.', 400)
            parts, names = {}, {}
            for slot, item in items.items():
                parts[slot], names[slot] = save_upload(item, slot)
            try:
                data, up = combine_and_parse(parts, names)
            except ValueError as e:
                for p in parts.values():
                    try:
                        os.remove(p)
                    except OSError:
                        pass
                return self._err(str(e), 400)
            filename = ' + '.join(names[s] for s in ('field', 'doc') if s in names)
            try:
                detect_recurring(data, owner=None if ctx['user']['role'] == 'admin' else uname)
            except Exception as e:
                print('Recurring detection failed:', e)
            ws = new_ws('round1', data, up, source_parts=parts)
            WS[uname] = ws
            rec = None
            if check_permission(token, 'can_save_to_storage')[0]:
                xlsx, docx, _, _ = build_outputs(ws, lang_mode=body.get('lang') or 'vi')
                rec = archive_audit_session(data, up, xlsx, docx, actor=actor, owner_username=uname,
                                            title=f"{data['metadata'].get('vendor_short', '')} · {data['metadata'].get('audit_date_raw', '')}",
                                            note=f"Tự động lưu khi nạp file '{filename}'", source_parts=parts)
                ws['bound_record_id'], ws['bound_title'] = rec['record_id'], rec['title']
            write_autosave(uname, ws)
            return self._json({'status': 'ok', 'data': slim(ws), 'archived_record': rec})

        # Bổ sung File hiện trường / File tài liệu còn thiếu (hoặc thay file) rồi tổng hợp lại
        if path == '/api/finding/supplement':
            if not self._need(token, 'can_upload_findings'):
                return
            slot = body.get('slot')
            if slot not in ('field', 'doc'):
                return self._err('Loại file không hợp lệ (field/doc).')
            if not body.get('file_base64'):
                return self._err('Vui lòng chọn file cần bổ sung.')
            rec_id = body.get('record_id')
            if rec_id:
                _, rec0 = find_record(rec_id)
                if not rec0:
                    return self._err('Không tìm thấy báo cáo!', 404)
                if not can_record(token, rec0, 'edit'):
                    return self._err('Bạn không có quyền sửa báo cáo này.', 403)
                if int(rec0.get('round', 1)) != 1:
                    return self._err('Chỉ bổ sung file cho báo cáo lần 1.')
                base_ws = load_record_into_ws(rec0)
                base_ws['bound_record_id'], base_ws['bound_title'] = rec0['record_id'], rec0.get('title') or rec0['record_id']
            else:
                uname, base_ws = self._ws(token)
                if not base_ws:
                    return
                if base_ws['mode'] != 'round1':
                    return self._err('Chỉ bổ sung file ở báo cáo lần 1.')
            parts = dict(base_ws.get('source_parts') or {})
            parts = {k: v for k, v in parts.items() if v and os.path.exists(v)}
            if not parts and base_ws.get('source_xlsm_path') and os.path.exists(base_ws['source_xlsm_path']):
                # Older report (one file only): its file counts as the other slot
                parts['doc' if slot == 'field' else 'field'] = base_ws['source_xlsm_path']
            old_sources = base_ws['data'].get('sources') or {}
            names = {k: (old_sources.get(k) or {}).get('filename') for k in parts}
            parts[slot], names[slot] = save_upload(body, slot)
            try:
                data, up = combine_and_parse(parts, names)
            except ValueError as e:
                return self._err(str(e), 400)
            carry_over_edits(base_ws['data'], data)
            recalculate_state(data)
            try:
                detect_recurring(data, exclude_record_id=base_ws.get('bound_record_id'),
                                 owner=None if ctx['user']['role'] == 'admin' else uname)
            except Exception as e:
                print('Recurring detection failed:', e)
            ws = new_ws('round1', data, up, source_parts=parts)
            ws['bound_record_id'], ws['bound_title'] = base_ws.get('bound_record_id'), base_ws.get('bound_title', '')
            WS[uname] = ws
            rec = None
            if ws['bound_record_id']:
                _, brec = find_record(ws['bound_record_id'])
                if brec and can_record(token, brec, 'edit'):
                    xlsx, docx, _, _ = build_outputs(ws, lang_mode=body.get('lang') or 'vi')
                    rec = archive_audit_session(data, up, xlsx, docx, actor=actor, owner_username=brec.get('owner_username') or uname,
                                                note=f"Bổ sung {SLOT_NAMES[slot]} '{names[slot]}'",
                                                overwrite_record_id=brec['record_id'], source_parts=parts)
                    ws['dirty'] = False
            write_autosave(uname, ws)
            add_audit_log(actor, f"Bổ sung {SLOT_NAMES[slot]} '{names[slot]}'" + (f" cho báo cáo '{rec['record_id']}'" if rec else ''))
            return self._json({'status': 'ok', 'data': slim(ws), 'record': rec,
                               'storage': storage_for_token(token) if rec else None})

        # ---------------- Round 2 ----------------
        if path == '/api/round2/upload':
            if not self._need(token, 'can_upload_round2'):
                return
            repo, parent = find_record(body.get('parent_record_id', ''))
            if not parent:
                return self._err('Vui lòng chọn báo cáo lần 1 để đối chiếu!')
            if int(parent.get('round', 1)) != 1:
                return self._err('Chỉ có thể nạp lần 2 cho một báo cáo lần 1.')
            if not can_record(token, parent, 'view'):
                return self._err('Bạn không có quyền truy cập báo cáo lần 1 này.', 403)
            filename = os.path.basename(body.get('filename', 'findings_lan2.xlsm'))
            up = os.path.join(OUTPUT_DIR, f"upload_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}_{secrets.token_hex(3)}_LAN2_{filename}")
            with open(up, 'wb') as f:
                f.write(base64.b64decode(body.get('file_base64', '')))
            pb = load_bundle(parent)
            r1_data = recalculate_state(pb['data'])
            try:
                r2_parsed = parse_findings_xlsm(up, CHECKLIST_REF)
            except ValueError as e:
                if os.path.exists(up):
                    try:
                        os.remove(up)
                    except OSError:
                        pass
                return self._err(str(e), 400)
            r1_data['round2'] = build_round2(r1_data, r2_parsed, parent, up)
            ws = new_ws('round2', r1_data, up, r1_source_xlsm_path=pb.get('source_xlsm_path'), parent_record_id=parent['record_id'])
            WS[uname] = ws
            write_autosave(uname, ws)
            add_audit_log(actor, f"Nạp file Finding lần 2 cho báo cáo '{parent['record_id']}'")
            return self._json({'status': 'ok', 'data': slim(ws)})

        if path == '/api/round2/update':
            if not self._need(token, 'can_upload_round2'):
                return
            uname, ws = self._ws(token)
            if not ws:
                return
            if ws['mode'] != 'round2':
                return self._err('Không ở chế độ đánh giá lần 2.')
            r2 = ws['data']['round2']
            for it in r2['items']:
                v = (body.get('items') or {}).get(str(it['r1_no']))
                if v is not None:
                    it['closed'] = bool(v)
            for nf in r2['new_findings']:
                v = (body.get('new_findings') or {}).get(str(nf['r2_no']))
                if v is not None:
                    nf['include'] = bool(v)
            r2['confirmed'] = False
            rescore_round2(ws['data'], r2, CHECKLIST_REF)
            ws['dirty'] = True
            return self._json({'status': 'ok', 'data': slim(ws)})

        if path == '/api/round2/confirm':
            if not self._need(token, 'can_upload_round2'):
                return
            uname, ws = self._ws(token)
            if not ws or ws['mode'] != 'round2':
                return self._err('Không ở chế độ đánh giá lần 2.')
            r2 = ws['data']['round2']
            rescore_round2(ws['data'], r2, CHECKLIST_REF)
            r2['confirmed'] = bool(body.get('confirmed', True))
            r2['confirmed_by'] = actor if r2['confirmed'] else ''
            r2['confirmed_at'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S') if r2['confirmed'] else ''
            ws['dirty'] = True
            add_audit_log(actor, f"{'Xác nhận' if r2['confirmed'] else 'Hủy xác nhận'} kết quả lần 2 ({r2['summary2']['total_score']} điểm)")
            if r2['confirmed']:
                s1, s2 = ws['data']['summary'], r2['summary2']
                notify.send_event('round2_confirmed', f"[RBA 8.0.1] Xác nhận kết quả lần 2: {ws['data']['metadata'].get('vendor_short', '')} · {s1['total_score']} → {s2['total_score']} điểm",
                                  f"Báo cáo lần 1: {r2.get('parent_title')}\nLần 1: {s1['total_score']} điểm ({s1['grade_level']})\nLần 2: {s2['total_score']} điểm ({s2['grade_level']})\n"
                                  f"Đã khắc phục: {s2['closed_findings']}/{s2['r1_findings']} lỗi\nNgười xác nhận: {actor}")
            return self._json({'status': 'ok', 'data': slim(ws)})

        # ---------------- Edit current workspace ----------------
        if path == '/api/update':
            if not self._need(token, 'can_edit_checklist'):
                return
            uname, ws = self._ws(token)
            if not ws:
                return
            data = ws['data']
            if 'metadata' in body:
                md = dict(body['metadata'])
                for k in ('total_workers', 'permanent_workers', 'temp_workers', 'foreign_workers', 'subcontract_count', 'interview_count'):
                    if k in md:
                        try:
                            md[k] = int(float(md[k] or 0))
                        except (TypeError, ValueError):
                            md[k] = 0
                data['metadata'].update(md)
            if ws['mode'] == 'round1':
                for it in data['checklist']:
                    ov = (body.get('checklist_overrides') or {}).get(it['audit_id'])
                    if ov:
                        if ov.get('significance') in SEVERITIES and ov['significance'] != it.get('significance'):
                            auto_sig = it.get('auto_significance') or it.get('significance')
                            it['auto_significance'] = auto_sig
                            if not str(it.get('auto_reason', '')).startswith('Điều chỉnh thủ công'):
                                it['auto_reason_auto'] = it.get('auto_reason', '')
                            it['significance'] = ov['significance']
                            it['auto_reason'] = f"Điều chỉnh thủ công bởi {actor} (hệ thống đề xuất: {auto_sig})"
                            try:
                                learning.log_override(it, auto_sig, ov['significance'], actor, data['metadata'].get('vendor_short', ''))
                            except Exception as e:
                                print('Override log failed:', e)
                        if 'evidence_text' in ov:
                            it['evidence_text'] = ov['evidence_text']
                if 'doc_violations' in body:
                    data['doc_violations'] = body['doc_violations']
                if 'facility_violations' in body:
                    data['facility_violations'] = body['facility_violations']
                if 'key_issue_nos' in body:
                    by_no = {f['no']: f for f in data['findings']}
                    sig = {it['audit_id']: it['significance'] for it in data['checklist']}
                    valid_nos = [int(x) for x in (body['key_issue_nos'] or []) if x is not None and str(x).strip().isdigit()]
                    kis = [{'no': f['no'], 'excel_row': f['excel_row'], 'audit_id': f['audit_id'],
                            'significance': sig.get(f['audit_id'], 'Major'), 'issue_vn': f['issue_vn'], 'photos': f['photos']}
                           for f in (by_no.get(n) for n in valid_nos) if f]
                    if kis:
                        data['key_issues'] = kis
                recalculate_state(data)
            ws['dirty'] = True
            return self._json({'status': 'ok', 'data': slim(ws)})

        if path == '/api/finding/vietnamese':
            if not self._need(token, 'can_use_qa_autofix'):
                return
            uname, ws = self._ws(token)
            if not ws:
                return
            if ws['mode'] != 'round1':
                return self._err('Chỉ sửa được nội dung ở báo cáo lần 1.')
            vn = str(body.get('vn', '')).strip()
            if not vn:
                return self._err('Vui lòng nhập nội dung tiếng Việt.')
            try:
                en = set_finding_vietnamese(ws['data'], int(body.get('no', 0)), vn)
            except (TypeError, ValueError):
                en = None
            if en is None:
                return self._err('Không tìm thấy nhận định này.', 404)
            # Shared across all users, so only Admin wording goes into the translation memory
            if ctx['user']['role'] == 'admin':
                remember_translation(en, vn)
            recalculate_state(ws['data'])
            ws['dirty'] = True
            add_audit_log(actor, f"Sửa nội dung tiếng Việt của nhận định #{body.get('no')}")
            return self._json({'status': 'ok', 'data': slim(ws)})

        if path == '/api/qa/autofix':
            if not self._need(token, 'can_use_qa_autofix'):
                return
            uname, ws = self._ws(token)
            if not ws:
                return
            if ws['mode'] != 'round1':
                return self._err('Kiểm tra ngôn ngữ chỉ áp dụng cho báo cáo lần 1.')
            applied, _ = apply_qa_fixes_to_data(ws['data'], target_issue_ids=body.get('issue_ids'))
            recalculate_state(ws['data'])
            ws['dirty'] = True
            add_audit_log(actor, f"Tự động sửa {applied} lỗi chính tả/dấu câu/phụ đề")
            return self._json({'status': 'ok', 'applied_count': applied, 'data': slim(ws)})

        # ---------------- Report archive ----------------
        if path == '/api/storage/save_session':
            if not self._need(token, 'can_save_to_storage'):
                return
            uname, ws = self._ws(token)
            if not ws:
                return
            r2 = ws['data'].get('round2') if ws['mode'] == 'round2' else None
            if r2 and not r2.get('confirmed'):
                return self._err('Vui lòng xác nhận kết quả lần 2 trước khi lưu báo cáo.', 409)
            overwrite_id = None
            if body.get('overwrite') and ws.get('bound_record_id'):
                _, rec = find_record(ws['bound_record_id'])
                if not rec:
                    return self._err('Báo cáo gốc không còn tồn tại, vui lòng lưu thành báo cáo mới.')
                if not can_record(token, rec, 'edit'):
                    return self._err('Bạn không có quyền sửa báo cáo này (chỉ Admin hoặc người lưu có quyền Sửa).', 403)
                overwrite_id = rec['record_id']
            xlsx, docx, _, _ = build_outputs(ws, lang_mode=body.get('lang') or 'vi_ko')
            kwargs = dict(actor=actor, owner_username=uname, title=body.get('title', '').strip(),
                          note=body.get('note', '').strip(), overwrite_record_id=overwrite_id)
            if r2:
                _, parent = find_record(ws.get('parent_record_id') or r2.get('parent_record_id'))
                rec = archive_audit_session(ws['data'], ws['source_xlsm_path'], xlsx, docx, round_no=2,
                                            parent_record=parent or {'record_id': r2.get('parent_record_id')},
                                            bundle_payload={'round2': r2, 'r1_source_xlsm_path': ws.get('r1_source_xlsm_path')},
                                            summary_override=r2['summary2'], **kwargs)
            else:
                rec = archive_audit_session(ws['data'], ws['source_xlsm_path'], xlsx, docx, source_parts=ws.get('source_parts'), **kwargs)
            ws['bound_record_id'], ws['bound_title'] = rec['record_id'], rec.get('title', '')
            write_autosave(uname, ws)
            subj, nbody, nfiles = record_notice(rec, 'Cập nhật báo cáo' if overwrite_id else 'Báo cáo mới')
            notify.send_event('report_updated' if overwrite_id else 'report_saved', subj, nbody, nfiles)
            return self._json({'status': 'ok', 'record': rec, 'storage': storage_for_token(token), 'data': slim(ws)})

        if path == '/api/storage/load_session':
            repo, rec = find_record(body.get('record_id', ''))
            if not rec:
                return self._err('Không tìm thấy báo cáo!', 404)
            if not can_record(token, rec, 'view'):
                return self._err('Bạn không có quyền xem báo cáo này.', 403)
            edit = bool(body.get('edit'))
            if edit and not can_record(token, rec, 'edit'):
                return self._err('Bạn không có quyền sửa báo cáo này.', 403)
            ws = load_record_into_ws(rec)
            if ws['mode'] == 'round1':
                try:
                    detect_recurring(ws['data'], exclude_record_id=rec['record_id'], before=rec.get('created_at'),
                                     owner=None if ctx['user']['role'] == 'admin' else uname)
                except Exception as e:
                    print('Recurring detection failed:', e)
            if edit:
                ws['bound_record_id'], ws['bound_title'] = rec['record_id'], rec.get('title') or rec['record_id']
            ws['dirty'] = False
            WS[uname] = ws
            return self._json({'status': 'ok', 'data': slim(ws), 'loaded_record': rec, 'edit': edit})

        if path == '/api/storage/update_record':
            repo, rec = find_record(body.get('record_id', ''))
            if not rec:
                return self._err('Không tìm thấy báo cáo!', 404)
            if not can_record(token, rec, 'edit'):
                return self._err('Bạn không có quyền sửa báo cáo này.', 403)
            if 'title' in body:
                rec['title'] = str(body['title']).strip()[:200]
            if 'note' in body:
                rec['note'] = str(body['note']).strip()[:500]
            rec['updated_at'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            rec['updated_by'] = actor
            save_file_repository(repo)
            add_audit_log(actor, f"Sửa thông tin báo cáo '{rec['record_id']}'")
            return self._json({'status': 'ok', 'storage': storage_for_token(token)})

        if path == '/api/storage/revision_restore':
            repo, rec = find_record(body.get('record_id', ''))
            if not rec:
                return self._err('Không tìm thấy báo cáo!', 404)
            if not can_record(token, rec, 'edit'):
                return self._err('Bạn không có quyền sửa báo cáo này.', 403)
            try:
                rec = restore_record_revision(rec['record_id'], int(body.get('revision', 0)), actor=actor)
            except FileNotFoundError as e:
                return self._err(str(e), 404)
            for w in WS.values():
                if w.get('bound_record_id') == rec['record_id']:
                    w['bound_record_id'], w['bound_title'] = None, ''
            subj, nbody, nfiles = record_notice(rec, f"Khôi phục phiên bản {body.get('revision')}")
            notify.send_event('report_updated', subj, nbody, nfiles)
            return self._json({'status': 'ok', 'storage': storage_for_token(token)})

        if path == '/api/storage/delete_record':
            repo, rec = find_record(body.get('record_id', ''))
            if not rec:
                return self._err('Không tìm thấy báo cáo!', 404)
            if not can_record(token, rec, 'delete'):
                return self._err('Bạn không có quyền xóa báo cáo này.', 403)
            children = [r for r in repo['records'] if r.get('parent_record_id') == rec['record_id']]
            for c in children:
                if not can_record(token, c, 'delete'):
                    return self._err('Báo cáo này có kết quả lần 2 do người khác lưu — chỉ Admin mới xóa được.', 403)
            victims = [rec] + children
            for v in victims:
                for fm in (v.get('files') or {}).values():
                    if fm and fm.get('rel_path'):
                        p = os.path.join(STORAGE_DIR, fm['rel_path'])
                        if os.path.exists(p):
                            try:
                                os.remove(p)
                            except OSError:
                                pass
            ids = {v['record_id'] for v in victims}
            for v in victims:
                delete_record_revisions(v['record_id'])
            repo['records'] = [r for r in repo['records'] if r['record_id'] not in ids]
            save_file_repository(repo)
            add_audit_log(actor, f"Xóa báo cáo {', '.join(sorted(ids))}")
            notify.send_event('report_deleted', f"[RBA 8.0.1] Xóa báo cáo: {rec.get('vendor_short', '')} · {rec.get('title') or rec['record_id']}",
                              f"Báo cáo bị xóa: {', '.join(sorted(ids))}\nNgười xóa: {actor}")
            for w in WS.values():
                if w.get('bound_record_id') in ids:
                    w['bound_record_id'], w['bound_title'] = None, ''
            return self._json({'status': 'ok', 'storage': storage_for_token(token)})

        self.send_error(404, 'Not Found')


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    request_queue_size = 128  # default 5 drops connections when a page loads many photos at once


def _background_jobs():
    try:
        backup.ensure_startup_backup()
    except Exception as e:
        print('Startup backup failed:', e)
    while True:
        try:
            backup.ensure_daily_backup()
            cleanup_output_dir()
            persist_sessions()
        except Exception as e:
            print('Background job error:', e)
        time.sleep(600)


def _restart_watcher():
    trig = os.path.join(DB_DIR, '.restart_trigger')
    if os.path.exists(trig):
        try:
            os.remove(trig)
        except OSError:
            pass
    while True:
        time.sleep(2)
        if os.path.exists(trig):
            try:
                os.remove(trig)
            except OSError:
                pass
            if os.environ.get('RBA_SUPERVISED') == '1':
                os._exit(3)


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8801))
    try:
        server = ThreadedHTTPServer((BIND_HOST, port), RBAAuditHandler)
    except OSError as e:
        print(f"Không mở được cổng {port} ({e}). Có thể hệ thống đang chạy ở một cửa sổ khác.", flush=True)
        sys.exit(4)
    threading.Thread(target=_background_jobs, daemon=True).start()
    threading.Thread(target=_restart_watcher, daemon=True).start()
    print(f"RBA 8.0.1 Audit Automation Web Server running at http://{BIND_HOST}:{port}", flush=True)
    server.serve_forever()
