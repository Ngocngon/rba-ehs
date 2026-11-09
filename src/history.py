"""
(E) Recurring-finding detection.
When a new round-1 Findings file is analysed, every finding is compared with the findings of
earlier round-1 reports of the same vendor (same vendor code, or same vendor short name).
A finding is "recurring" when an earlier report has a finding with the same Audit ID and a
similar text (similarity >= 0.6). Items with recurring findings get a suggestion to raise the
severity one level — the auditor decides, nothing is changed automatically.
© NGUYỄN NGỌC NGÔN — RBA 8.0.1 EHS Automation Suite
"""
import os
import re
import json
import difflib

from system_core import STORAGE_DIR, load_file_repository, save_file_repository, build_finding_index

SIM_THRESHOLD = 0.6
NEXT_LEVEL = {'Minor': 'Major', 'Major': 'Priority'}


def _norm(txt):
    return re.sub(r'\s+', ' ', str(txt or '').strip().lower())[:240]


def _same_vendor(rec, vendor_short, vendor_code):
    code = str(vendor_code or '').strip().upper()
    if code and code not in ('CODE', 'L10PO5_DEFAULT') and str(rec.get('vendor_code', '')).strip().upper() == code:
        return True
    return _norm(rec.get('vendor_short')) == _norm(vendor_short) and bool(_norm(vendor_short))


def _index_for(rec, repo_dirty):
    if rec.get('finding_index') is not None:
        return rec['finding_index']
    rel = (rec.get('files', {}).get('bundle') or {}).get('rel_path', '')
    p = os.path.join(STORAGE_DIR, rel)
    idx = []
    if rel and os.path.exists(p):
        try:
            with open(p, 'r', encoding='utf-8') as f:
                idx = build_finding_index(json.load(f).get('data', {}))
        except Exception:
            idx = []
    rec['finding_index'] = idx
    repo_dirty[0] = True
    return idx


def detect_recurring(data, exclude_record_id=None, before=None, owner=None):
    """Adds data['recurring'] and returns it. With owner, only that user's reports are compared."""
    meta = data.get('metadata', {})
    repo = load_file_repository()
    dirty = [False]
    previous = [r for r in repo.get('records', [])
                if int(r.get('round', 1)) == 1 and r['record_id'] != exclude_record_id
                and (not before or str(r.get('created_at', '')) < before)
                and (owner is None or r.get('owner_username') == owner)
                and _same_vendor(r, meta.get('vendor_short'), meta.get('vendor_code'))]
    previous.sort(key=lambda r: str(r.get('created_at', '')), reverse=True)

    by_no, by_code = {}, {}
    for rec in previous:
        idx = _index_for(rec, dirty)
        for f in data.get('findings', []):
            if f.get('no') in by_no:
                continue
            txt = _norm(f.get('issue_vn') or f.get('issue_full'))
            best, best_sim = None, 0.0
            for g in idx:
                if g.get('audit_id') != f.get('audit_id'):
                    continue
                sim = difflib.SequenceMatcher(None, txt, g.get('issue_vn', '')).ratio()
                if sim > best_sim:
                    best, best_sim = g, sim
            if best and best_sim >= SIM_THRESHOLD:
                by_no[f['no']] = {
                    'record_id': rec['record_id'], 'title': rec.get('title') or rec['record_id'],
                    'date': rec.get('audit_date') or rec.get('created_at', ''), 'prev_no': best.get('no'),
                    'prev_issue': best.get('issue_vn', ''), 'similarity': round(best_sim, 2),
                }
                by_code[f['audit_id']] = by_code.get(f['audit_id'], 0) + 1
    if dirty[0]:
        save_file_repository(repo)

    suggestions = {}
    for it in data.get('checklist', []):
        n = by_code.get(it['audit_id'], 0)
        nxt = NEXT_LEVEL.get(it.get('significance'))
        if n and nxt:
            suggestions[it['audit_id']] = {'count': n, 'from': it.get('significance'), 'to': nxt}
    data['recurring'] = {
        'by_no': {str(k): v for k, v in by_no.items()},
        'by_code': by_code,
        'suggestions': suggestions,
        'count': len(by_no),
        'compared_records': [{'record_id': r['record_id'], 'title': r.get('title') or r['record_id'],
                              'date': r.get('audit_date') or r.get('created_at', '')} for r in previous[:10]],
    }
    return data['recurring']
