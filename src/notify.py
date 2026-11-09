"""
(H) Notifications by Email (SMTP), Zalo OA and a generic webhook.
Configured by the admin; events are sent in a background thread so the UI never waits.
© NGUYỄN NGỌC NGÔN — RBA 8.0.1 EHS Automation Suite
"""
import os
import json
import ssl
import smtplib
import datetime
import threading
import mimetypes
import urllib.request
from email.message import EmailMessage

from system_core import DB_DIR

CONFIG_FILE = os.path.join(DB_DIR, "notify_config.json")
EVENTS = ['report_saved', 'report_updated', 'round2_confirmed', 'report_deleted', 'system_restore']
DEFAULT = {
    'email': {'enabled': False, 'host': 'smtp.gmail.com', 'port': 587, 'security': 'starttls', 'username': '',
              'password': '', 'sender': '', 'recipients': [], 'attach_files': True},
    'zalo': {'enabled': False, 'access_token': '', 'user_ids': []},
    'webhook': {'enabled': False, 'url': ''},
    'events': {'report_saved': True, 'report_updated': True, 'round2_confirmed': True, 'report_deleted': True, 'system_restore': True},
    'log': [],
}
_lock = threading.Lock()


def load_config():
    cfg = json.loads(json.dumps(DEFAULT))
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            saved = json.load(f)
        for k, v in saved.items():
            if isinstance(v, dict) and isinstance(cfg.get(k), dict):
                cfg[k].update(v)
            else:
                cfg[k] = v
    return cfg


def _save(cfg):
    with open(CONFIG_FILE + '.tmp', 'w', encoding='utf-8') as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    os.replace(CONFIG_FILE + '.tmp', CONFIG_FILE)


def public_config():
    cfg = load_config()
    cfg['email'] = dict(cfg['email'], password='••••••' if cfg['email'].get('password') else '')
    cfg['zalo'] = dict(cfg['zalo'], access_token='••••••' if cfg['zalo'].get('access_token') else '')
    cfg['log'] = cfg.get('log', [])[:40]
    return cfg


def save_config(new):
    with _lock:
        cfg = load_config()
        for sec in ('email', 'zalo', 'webhook', 'events'):
            if sec in new and isinstance(new[sec], dict):
                upd = dict(new[sec])
                if upd.get('password') == '••••••':
                    upd.pop('password')
                if upd.get('access_token') == '••••••':
                    upd.pop('access_token')
                for lk in ('recipients', 'user_ids'):
                    if lk in upd and isinstance(upd[lk], str):
                        upd[lk] = [x.strip() for x in upd[lk].replace(';', ',').replace('\n', ',').split(',') if x.strip()]
                if 'port' in upd:
                    upd['port'] = int(upd['port'] or 587)
                cfg[sec].update(upd)
        _save(cfg)
    return public_config()


def _log(channel, event, ok, detail):
    with _lock:
        cfg = load_config()
        cfg.setdefault('log', []).insert(0, {'time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                             'channel': channel, 'event': event, 'ok': ok, 'detail': str(detail)[:300]})
        cfg['log'] = cfg['log'][:100]
        _save(cfg)


def _send_email(cfg, subject, body, attachments):
    e = cfg['email']
    if not e.get('recipients'):
        raise ValueError('Chưa có người nhận')
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = e.get('sender') or e.get('username')
    msg['To'] = ', '.join(e['recipients'])
    msg.set_content(body + "\n\n—\nRBA 8.0.1 EHS Automation Suite · © NGUYỄN NGỌC NGÔN")
    if e.get('attach_files'):
        for path, name in attachments or []:
            if path and os.path.exists(path) and os.path.getsize(path) < 20 * 1024 * 1024:
                ctype = mimetypes.guess_type(name)[0] or 'application/octet-stream'
                maintype, subtype = ctype.split('/', 1)
                with open(path, 'rb') as f:
                    msg.add_attachment(f.read(), maintype=maintype, subtype=subtype, filename=name)
    port = int(e.get('port') or 587)
    if e.get('security') == 'ssl':
        server = smtplib.SMTP_SSL(e['host'], port, context=ssl.create_default_context(), timeout=30)
    else:
        server = smtplib.SMTP(e['host'], port, timeout=30)
        if e.get('security', 'starttls') == 'starttls':
            server.starttls(context=ssl.create_default_context())
    with server:
        if e.get('username'):
            server.login(e['username'], e.get('password', ''))
        server.send_message(msg)


def _post_json(url, payload, headers=None):
    req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'),
                                 headers=dict({'Content-Type': 'application/json'}, **(headers or {})), method='POST')
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.read().decode('utf-8', 'replace')


def _send_zalo(cfg, text):
    z = cfg['zalo']
    if not z.get('access_token') or not z.get('user_ids'):
        raise ValueError('Thiếu access token hoặc user_id Zalo')
    results = []
    for uid in z['user_ids']:
        resp = _post_json('https://openapi.zalo.me/v3.0/oa/message/cs',
                          {'recipient': {'user_id': uid}, 'message': {'text': text[:2000]}},
                          {'access_token': z['access_token']})
        data = json.loads(resp or '{}')
        if data.get('error') not in (0, None):
            raise RuntimeError(f"Zalo {uid}: {data.get('message')}")
        results.append(uid)
    return results


def _dispatch(event, subject, body, attachments, force=False):
    cfg = load_config()
    if not force and not cfg['events'].get(event, False):
        return
    text = f"{subject}\n{body}"
    for ch, enabled, fn in (
        ('email', cfg['email'].get('enabled'), lambda: _send_email(cfg, subject, body, attachments)),
        ('zalo', cfg['zalo'].get('enabled'), lambda: _send_zalo(cfg, text)),
        ('webhook', cfg['webhook'].get('enabled') and cfg['webhook'].get('url'), lambda: _post_json(cfg['webhook']['url'], {'event': event, 'title': subject, 'text': body})),
    ):
        if not enabled:
            continue
        try:
            fn()
            _log(ch, event, True, 'Đã gửi')
        except Exception as ex:
            _log(ch, event, False, ex)


def send_event(event, subject, body, attachments=None, force=False):
    threading.Thread(target=_dispatch, args=(event, subject, body, attachments, force), daemon=True).start()


def send_test(actor):
    _dispatch('test', '[RBA 8.0.1] Thông báo thử', f'Đây là thông báo thử do {actor} gửi từ hệ thống RBA 8.0.1.', [], force=True)
    return public_config()
