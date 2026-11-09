"""
(G) Learning from manual overrides.
Every time an auditor changes the severity proposed by the system, the event is logged.
When the same Audit ID is overridden in the same direction at least MIN_EVENTS times, the
system proposes a change to the master data (add a keyword, remove the keyword that caused
the wrong classification, or adjust the Major count threshold). The master data changes
only when the admin clicks "Apply".
© NGUYỄN NGỌC NGÔN — RBA 8.0.1 EHS Automation Suite
"""
import os
import re
import json
import datetime
from collections import Counter

from system_core import DB_DIR, MASTER_RULES_FILE, save_master_rules

LOG_FILE = os.path.join(DB_DIR, "override_log.json")
MIN_EVENTS = 2
RANK = {'Conformance': 0, 'N/A': 0, 'Minor': 1, 'Major': 2, 'Priority': 3}
STOP = set("""và các của cho có không được trong khi với tại là đã chưa bị theo để một những này đó
các từ như thì nhưng hoặc nên cần phải trên dưới ra vào lên xuống còn rất cũng đang sẽ về""".split())


def _load():
    if not os.path.exists(LOG_FILE):
        return {'events': [], 'dismissed': [], 'applied': []}
    with open(LOG_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)


def _save(d):
    d['events'] = d['events'][-2000:]
    with open(LOG_FILE + '.tmp', 'w', encoding='utf-8') as f:
        json.dump(d, f, ensure_ascii=False, indent=1)
    os.replace(LOG_FILE + '.tmp', LOG_FILE)


def log_override(item, auto_sig, manual_sig, actor, vendor):
    if not auto_sig or auto_sig == manual_sig:
        return
    d = _load()
    d['events'].append({
        'time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'actor': actor, 'vendor': vendor,
        'audit_id': item['audit_id'], 'auto': auto_sig, 'manual': manual_sig,
        'auto_reason': item.get('auto_reason_auto') or item.get('auto_reason', ''),
        'finding_count': item.get('finding_count', len(item.get('findings', []))),
        'issues': [str(f.get('issue_vn', ''))[:300] for f in item.get('findings', [])][:10],
    })
    _save(d)


def _phrases(text):
    words = [w for w in re.findall(r"[\wÀ-ỹ]+", text.lower()) if not w.isdigit()]
    out = set()
    for n in (2, 3):
        for i in range(len(words) - n + 1):
            chunk = words[i:i + n]
            if chunk[0] in STOP or chunk[-1] in STOP:
                continue
            out.add(' '.join(chunk))
    return out


def get_suggestions():
    d = _load()
    with open(MASTER_RULES_FILE, 'r', encoding='utf-8') as f:
        master = json.load(f)
    items = {it['audit_id']: it for it in master.get('items', [])}
    groups = {}
    for e in d['events']:
        direction = 'up' if RANK.get(e['manual'], 0) > RANK.get(e['auto'], 0) else 'down'
        groups.setdefault((e['audit_id'], direction, e['manual']), []).append(e)

    out = []
    for (code, direction, target), evs in groups.items():
        if len(evs) < MIN_EVENTS or code not in items:
            continue
        rule = items[code].get('rule', {})
        existing_kw = set(k.lower() for k in rule.get('priority_kw', []) + rule.get('major_kw', []))
        base = {'audit_id': code, 'direction': direction, 'target': target, 'events': len(evs),
                'examples': [{'time': e['time'], 'actor': e['actor'], 'vendor': e['vendor'], 'auto': e['auto'], 'manual': e['manual'],
                              'issue': (e['issues'] or [''])[0]} for e in evs[-3:]],
                'desc': rule.get('desc', items[code].get('sub_category', ''))}
        if direction == 'up':
            field = 'priority_kw' if target == 'Priority' else 'major_kw'
            # Count each phrase once per distinct finding text so repeated events of the same
            # report do not inflate junk phrases; keep phrases shared by >= 2 different findings.
            texts = {t.strip().lower() for e in evs for t in e['issues'] if t.strip()}
            cnt = Counter()
            for txt in texts:
                cnt.update(_phrases(txt))
            cands = []
            for p, c in cnt.most_common(60):
                if c < 2 or p in existing_kw or any(p in q for q in cands):
                    continue
                cands = [q for q in cands if q not in p] + [p]
                if len(cands) >= 3:
                    break
            for p in cands:
                out.append(dict(base, type='add_keyword', field=field, value=p,
                                text=f"Thêm từ khóa '{p}' vào {'Priority' if field == 'priority_kw' else 'Major'} của {code}"))
            if target == 'Major':
                counts = [e['finding_count'] for e in evs if e['finding_count']]
                thr = int(rule.get('major_min_count', 2))
                if counts and min(counts) < thr:
                    out.append(dict(base, type='set_threshold', field='major_min_count', value=max(1, min(counts)),
                                    text=f"Giảm ngưỡng Major của {code} từ {thr} xuống {max(1, min(counts))} lỗi"))
        else:
            kws = Counter()
            for e in evs:
                m = re.search(r"'([^']+)'", e.get('auto_reason', ''))
                if m:
                    kws[m.group(1)] += 1
            for kw, c in kws.items():
                if c >= MIN_EVENTS:
                    field = 'priority_kw' if kw in rule.get('priority_kw', []) else 'major_kw'
                    out.append(dict(base, type='remove_keyword', field=field, value=kw,
                                    text=f"Bỏ từ khóa '{kw}' khỏi {'Priority' if field == 'priority_kw' else 'Major'} của {code} (gây phân loại quá nặng)"))
            if not kws and evs[0]['auto'] == 'Major':
                counts = [e['finding_count'] for e in evs]
                thr = int(rule.get('major_min_count', 2))
                if counts and max(counts) >= thr:
                    out.append(dict(base, type='set_threshold', field='major_min_count', value=max(counts) + 1,
                                    text=f"Tăng ngưỡng Major của {code} từ {thr} lên {max(counts) + 1} lỗi"))
    for s in out:
        s['key'] = f"{s['audit_id']}|{s['type']}|{s.get('field')}|{s['value']}"
    hidden = set(d.get('dismissed', [])) | set(a['key'] for a in d.get('applied', []))
    return [s for s in out if s['key'] not in hidden]


def apply_suggestion(key, actor):
    sug = next((s for s in get_suggestions() if s['key'] == key), None)
    if not sug:
        raise KeyError('Gợi ý không còn hiệu lực')
    with open(MASTER_RULES_FILE, 'r', encoding='utf-8') as f:
        master = json.load(f)
    it = next(i for i in master['items'] if i['audit_id'] == sug['audit_id'])
    rule = it.setdefault('rule', {})
    if sug['type'] == 'add_keyword':
        rule.setdefault(sug['field'], []).append(sug['value'])
    elif sug['type'] == 'remove_keyword':
        rule[sug['field']] = [k for k in rule.get(sug['field'], []) if k != sug['value']]
    elif sug['type'] == 'set_threshold':
        rule['major_min_count'] = int(sug['value'])
    save_master_rules(master, actor=actor)
    d = _load()
    d.setdefault('applied', []).append({'key': key, 'text': sug['text'], 'by': actor,
                                        'time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')})
    _save(d)
    return sug


def dismiss_suggestion(key):
    d = _load()
    if key not in d.setdefault('dismissed', []):
        d['dismissed'].append(key)
    _save(d)


def summary():
    d = _load()
    return {'events': d['events'][-30:][::-1], 'applied': d.get('applied', [])[-20:][::-1], 'total_events': len(d['events'])}
