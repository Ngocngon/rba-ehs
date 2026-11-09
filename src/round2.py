"""
Round-2 (re-audit) engine for RBA 8.0.1.

Round 2 = the vendor sends back the Findings file with corrective actions
(Improvement Date / Complete Date / post-improvement photos). This module:
  1. Matches every round-2 finding against the round-1 finding list (NO + Audit ID,
     then Audit ID + text similarity).
  2. Proposes a status per round-1 finding (closed / open / missing) that the
     auditor must confirm.
  3. Re-scores the 41 items using only the findings that remain open, with the
     same 4-layer classifier and VLOOKUP score table as round 1.
  4. Builds the data used to export the round-2 Checklist (.xlsx) and the
     round-2 Word report (round-1 table + round-2 table).
© NGUYỄN NGỌC NGÔN — RBA 8.0.1 EHS Automation Suite
"""
import re
import copy
import difflib
import datetime

from engine import auto_classify_significance, compute_penalty_violation, build_summary_6_categories, select_top_violations

SEV_RANK = {'Conformance': 0, 'N/A': 0, 'Minor': 1, 'Major': 2, 'Priority': 3}


def _norm(txt):
    return re.sub(r'\s+', ' ', str(txt or '').strip().lower())


def _similarity(a, b):
    a, b = _norm(a), _norm(b)
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a, b).ratio()


def _is_auto_closed(f2):
    return bool(str(f2.get('complete_date', '')).strip()) or bool(f2.get('after_photos'))


def match_findings(r1_findings, r2_findings):
    """Returns (pairs: dict r1_no -> (r2_finding, method, score), unmatched_r2 list)."""
    used = set()
    pairs = {}
    r2_by_key = {}
    for idx, f2 in enumerate(r2_findings):
        r2_by_key.setdefault((f2.get('no'), f2.get('audit_id')), []).append(idx)

    # Pass 1: exact NO + Audit ID, confirmed by text similarity (or identical id when text is short)
    for f1 in r1_findings:
        for idx in r2_by_key.get((f1.get('no'), f1.get('audit_id')), []):
            if idx in used:
                continue
            sim = _similarity(f1.get('issue_vn') or f1.get('issue_full'), r2_findings[idx].get('issue_vn') or r2_findings[idx].get('issue_full'))
            if sim >= 0.45 or not _norm(f1.get('issue_vn')):
                pairs[f1['no']] = (r2_findings[idx], 'no+id', round(sim, 2))
                used.add(idx)
                break

    # Pass 2: same Audit ID + best text similarity
    for f1 in r1_findings:
        if f1['no'] in pairs:
            continue
        best, best_sim = None, 0.0
        for idx, f2 in enumerate(r2_findings):
            if idx in used or f2.get('audit_id') != f1.get('audit_id'):
                continue
            sim = _similarity(f1.get('issue_vn') or f1.get('issue_full'), f2.get('issue_vn') or f2.get('issue_full'))
            if sim > best_sim:
                best, best_sim = idx, sim
        if best is not None and best_sim >= 0.6:
            pairs[f1['no']] = (r2_findings[best], 'id+text', round(best_sim, 2))
            used.add(best)

    unmatched = [f2 for idx, f2 in enumerate(r2_findings) if idx not in used]
    return pairs, unmatched


def build_round2(r1_data, r2_parsed, parent_record, source_xlsm_path):
    """Creates the round-2 review object (statuses proposed, not yet confirmed)."""
    r1_findings = r1_data.get('findings', [])
    r2_findings = r2_parsed.get('findings', [])
    pairs, unmatched = match_findings(r1_findings, r2_findings)

    items = []
    for f1 in r1_findings:
        pr = pairs.get(f1['no'])
        if pr:
            f2, method, sim = pr
            auto_closed = _is_auto_closed(f2)
            status = 'closed' if auto_closed else 'open'
            items.append({
                'r1_no': f1['no'], 'r2_no': f2.get('no'), 'audit_id': f1['audit_id'],
                'issue_vn': f1.get('issue_vn', ''), 'location_vn': f1.get('location_vn', ''),
                'improvement_vn': f2.get('improvement_vn', '') or f1.get('improvement_vn', ''),
                'improvement_date': f2.get('improvement_date', ''), 'complete_date': f2.get('complete_date', ''),
                'after_photos': f2.get('after_photos', []),
                'match_method': method, 'match_score': sim,
                'auto_status': status, 'closed': auto_closed,
                'mandatory': f1.get('mandatory', ''),
            })
        else:
            items.append({
                'r1_no': f1['no'], 'r2_no': None, 'audit_id': f1['audit_id'],
                'issue_vn': f1.get('issue_vn', ''), 'location_vn': f1.get('location_vn', ''),
                'improvement_vn': '', 'improvement_date': '', 'complete_date': '', 'after_photos': [],
                'match_method': 'missing', 'match_score': 0,
                'auto_status': 'missing', 'closed': False,
                'mandatory': f1.get('mandatory', ''),
            })

    new_findings = [{
        'r2_no': f2.get('no'), 'audit_id': f2.get('audit_id'), 'issue_vn': f2.get('issue_vn', ''),
        'issue_en': f2.get('issue_en', ''), 'location_vn': f2.get('location_vn', ''),
        'mandatory': f2.get('mandatory', ''), 'complete_date': f2.get('complete_date', ''),
        'after_photos': f2.get('after_photos', []), 'photos': f2.get('photos', []),
        'include': False,
    } for f2 in unmatched]

    r2 = {
        'parent_record_id': parent_record.get('record_id'),
        'parent_title': parent_record.get('title') or parent_record.get('record_id'),
        'parent_year_month': parent_record.get('year_month'),
        'source_xlsm_path': source_xlsm_path,
        'r2_vendor_raw': r2_parsed.get('metadata', {}).get('vendor_raw', ''),
        'items': items,
        'new_findings': new_findings,
        'confirmed': False, 'confirmed_by': '', 'confirmed_at': '',
        'created_at': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    }
    rescore_round2(r1_data, r2)
    return r2


def rescore_round2(r1_data, r2, master_ref=None):
    """Re-classifies the 41 items from the findings still open (after user confirmation)."""
    triggers = (master_ref or {}).get('mandatory_triggers', ['mandatory', 'bắt buộc', 'hmbb', 'x', 'yes', '1'])
    thresholds = (master_ref or {}).get('grade_thresholds', {'A': 90, 'B': 80, 'C': 70})
    open_by_code, closed_by_code, total_by_code, new_by_code = {}, {}, {}, {}
    for it in r2['items']:
        total_by_code[it['audit_id']] = total_by_code.get(it['audit_id'], 0) + 1
        if it['closed']:
            closed_by_code[it['audit_id']] = closed_by_code.get(it['audit_id'], 0) + 1
        else:
            open_by_code.setdefault(it['audit_id'], []).append({
                'no': it['r1_no'], 'issue_vn': it['issue_vn'], 'issue_en': '', 'mandatory': it.get('mandatory', ''),
            })
    for nf in r2['new_findings']:
        if nf.get('include'):
            new_by_code.setdefault(nf['audit_id'], []).append({
                'no': nf['r2_no'], 'issue_vn': nf['issue_vn'], 'issue_en': nf.get('issue_en', ''), 'mandatory': nf.get('mandatory', ''),
            })

    rows = []
    total = 0
    counts = {'Conformance': 0, 'Minor': 0, 'Major': 0, 'Priority': 0, 'N/A': 0}
    for it in r1_data.get('checklist', []):
        code = it['audit_id']
        sig1 = it.get('significance', 'Conformance')
        open_list = open_by_code.get(code, []) + new_by_code.get(code, [])
        if sig1 == 'N/A' and not open_list:
            sig2, reason = 'N/A', 'N/A (giữ nguyên lần 1)'
        else:
            sig2, reason = auto_classify_significance(code, open_list, custom_rule=it.get('rule'), mandatory_triggers=triggers)
            # Corrective actions cannot make an item worse than round 1 unless new findings were added
            if not new_by_code.get(code) and SEV_RANK.get(sig2, 0) > SEV_RANK.get(sig1, 0):
                sig2, reason = sig1, f"Giữ mức lần 1 ({sig1}) — còn {len(open_list)} lỗi chưa khắc phục"
            if not open_list:
                reason = 'Đã khắc phục toàn bộ lỗi (➔ Conformance)'
        scores = it.get('scores_table', {})
        sc2 = scores.get(sig2, 0)
        total += sc2
        counts[sig2] = counts.get(sig2, 0) + 1
        rows.append({
            'audit_id': code, 'sub_category': it.get('sub_category', ''),
            'sig1': sig1, 'score1': it.get('score', 0),
            'sig2': sig2, 'score2': sc2, 'reason2': reason,
            'total': total_by_code.get(code, 0), 'closed': closed_by_code.get(code, 0),
            'open': len(open_by_code.get(code, [])), 'new': len(new_by_code.get(code, [])),
            'penalty_item': it.get('penalty_item', ''), 'penalty_criteria': it.get('penalty_criteria', ''),
        })

    total = round(total, 2)
    if isinstance(total, float) and total.is_integer():
        total = int(total)
    if total >= thresholds.get('A', 90):
        grade = 'A'
    elif total >= thresholds.get('B', 80):
        grade = 'B'
    elif total >= thresholds.get('C', 70):
        grade = 'C'
    else:
        grade = 'D'

    open_items = [i for i in r2['items'] if not i['closed']]
    mandatory_open = sum(1 for i in open_items if str(i.get('mandatory', '')).strip().lower() in triggers)
    mandatory_open += sum(1 for n in r2['new_findings'] if n.get('include') and str(n.get('mandatory', '')).strip().lower() in triggers)
    violated = counts['Minor'] + counts['Major'] + counts['Priority']
    penalty_cnt = sum(1 for r in rows if compute_penalty_violation(r['penalty_item'], r['penalty_criteria'], r['sig2']) == 'X')

    r2['checklist2'] = rows
    r2['summary2'] = {
        'total_score': total, 'grade_level': grade, 'counts': counts,
        'violated_items_count': violated, 'mandatory_count': mandatory_open,
        'penalty_violation_count': penalty_cnt, 'total_items': len(rows),
        'total_findings': len(open_items) + sum(1 for n in r2['new_findings'] if n.get('include')),
        'closed_findings': sum(1 for i in r2['items'] if i['closed']),
        'r1_findings': len(r2['items']),
        'missing_count': sum(1 for i in r2['items'] if i['auto_status'] == 'missing'),
        'new_count': len(r2['new_findings']),
        'compliance_rate': round(counts['Conformance'] / len(rows) * 100, 2) if rows else 0,
    }
    return r2


def build_round2_export_data(r1_data):
    """Data object for generate_checklist_xlsx() with round-2 results."""
    r2 = r1_data['round2']
    by_code = {r['audit_id']: r for r in r2['checklist2']}
    open_by_code = {}
    for i in r2['items']:
        if not i['closed']:
            open_by_code.setdefault(i['audit_id'], []).append(i['issue_vn'])
    for n in r2['new_findings']:
        if n.get('include'):
            open_by_code.setdefault(n['audit_id'], []).append(f"[Mới - Lần 2] {n['issue_vn']}")

    out = dict(r1_data)
    new_checklist = []
    for it in r1_data['checklist']:
        nit = dict(it)
        row = by_code.get(it['audit_id'])
        if row:
            nit['significance'] = row['sig2']
            nit['score'] = row['score2']
            opens = open_by_code.get(it['audit_id'], [])
            if opens:
                nit['evidence_text'] = "\n".join(f"{k}. {txt}" for k, txt in enumerate(opens, 1)) if len(opens) > 1 else opens[0]
            elif row['total']:
                nit['evidence_text'] = f"Lần 2: Đã khắc phục toàn bộ {row['total']} lỗi của lần 1"
        new_checklist.append(nit)
    out['checklist'] = new_checklist
    s2 = dict(r2['summary2'])
    s2['category_breakdown'] = build_summary_6_categories(
        [dict(c, finding_count=by_code.get(c['audit_id'], {}).get('open', 0)) for c in new_checklist]
    )
    out['summary'] = s2
    return out


def build_round2_docx_data(r1_data):
    """
    Data for the round-2 Word report.
    Section 1 keeps the round-1 summary (+ round-2 table inserted by the generator).
    Sections 2–4 list ONLY the findings still open after round 2:
      - 'Lỗi vi phạm Tài liệu' / 'Lỗi vi phạm Hiện trường' bullets
      - Table 3 grouped by the round-2 classification
      - Table 4 key issues (photos) chosen among the open findings, most severe first
    """
    r2 = r1_data['round2']
    by_code = {r['audit_id']: r for r in r2['checklist2']}
    open_nos = {i['r1_no'] for i in r2['items'] if not i['closed']}
    open_findings = [f for f in r1_data.get('findings', []) if f.get('no') in open_nos]
    new_included = [{
        'no': n['r2_no'], 'audit_id': n['audit_id'], 'issue_vn': n.get('issue_vn', ''), 'issue_full': n.get('issue_vn', ''),
        'location_vn': n.get('location_vn', ''), 'cause': 'facility', 'mandatory': n.get('mandatory', ''),
        'photos': n.get('photos', []), 'excel_row': 0, 'is_new': True,
    } for n in r2['new_findings'] if n.get('include')]
    remaining = open_findings + new_included

    out = dict(r1_data)
    remaining_by_code = {}
    for f in remaining:
        remaining_by_code.setdefault(f['audit_id'], []).append(f)
    new_cl = []
    for it in r1_data['checklist']:
        row = by_code.get(it['audit_id'], {})
        nit = dict(it)
        nit['significance'] = row.get('sig2', it.get('significance'))
        nit['findings'] = remaining_by_code.get(it['audit_id'], [])
        if not nit['findings'] and nit['significance'] not in ('Conformance', 'N/A'):
            nit['evidence_text'] = 'Còn tồn đọng (giữ mức lần 1)'
        new_cl.append(nit)
    out['checklist'] = new_cl

    doc_v, fac_v = select_top_violations(remaining, new_cl, max_per_type=3, max_total=5)
    out['doc_violations'] = doc_v or ['Đã khắc phục toàn bộ lỗi vi phạm tài liệu.']
    out['facility_violations'] = fac_v or ['Đã khắc phục toàn bộ lỗi vi phạm hiện trường.']

    with_photo = [f for f in remaining if f.get('photos')]
    with_photo.sort(key=lambda f: -SEV_RANK.get(by_code.get(f['audit_id'], {}).get('sig2', 'Minor'), 0))
    out['key_issues'] = [{
        'no': f['no'], 'excel_row': f.get('excel_row', 0), 'audit_id': f['audit_id'],
        'significance': by_code.get(f['audit_id'], {}).get('sig2', 'Minor'),
        'issue_vn': f['issue_vn'], 'photos': f['photos'], 'is_new': f.get('is_new', False),
    } for f in with_photo[:5]]
    out['empty_t3_text'] = 'Đã khắc phục toàn bộ các lỗi vi phạm sau đánh giá lần 2'
    out['empty_key_issue_text'] = 'Không còn vấn đề tồn đọng sau đánh giá lần 2'
    return out
