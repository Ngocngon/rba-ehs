"""
RBA 8.0.1 — Web bridge (chạy trong trình duyệt bằng Pyodide).
Gọi trực tiếp RBAAuditHandler của server.py mà không cần socket/HTTP server:
mỗi request từ Service Worker được chuyển thành một lần gọi do_GET/do_POST.
© NGUYỄN NGỌC NGÔN — RBA 8.0.1 EHS Automation Suite
"""
import email.message
import io
import json
import os
import sys
import urllib.parse
import zipfile

APP = '/app'
PERSIST_DIRS = ('database', 'storage', 'backups', 'templates')


def unpack_app(zip_path):
    """Giải nén mã nguồn + mẫu. File dữ liệu người dùng (trong PERSIST_DIRS) không bị ghi đè."""
    added = 0
    with zipfile.ZipFile(zip_path) as z:
        for info in z.infolist():
            if info.is_dir():
                continue
            target = os.path.join(APP, info.filename)
            top = info.filename.split('/', 1)[0]
            if top in PERSIST_DIRS and os.path.exists(target):
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, 'wb') as f:
                f.write(z.read(info))
            added += 1
    return added


_server = None


def _no_pdf(*a, **k):
    raise RuntimeError('Bản web không tạo PDF trên máy chủ — dùng nút PDF (In → Lưu thành PDF).')


def boot():
    global _server
    os.chdir(APP)
    if APP not in sys.path:
        sys.path.insert(0, APP)
    os.environ['RBA_WEB'] = '1'
    import notify
    notify.send_event = lambda *a, **k: None  # trình duyệt không gửi email/Zalo trực tiếp
    import report_pdf
    web_engine = lambda: {'engine': 'browser-print', 'path': '', 'label': 'Trình duyệt (In → Lưu thành PDF)'}
    report_pdf.make_pdf = _no_pdf
    report_pdf.pdf_engine = web_engine
    import server
    server.make_pdf = _no_pdf
    server.pdf_engine = web_engine
    _server = server
    try:
        server.cleanup_output_dir()
    except Exception:
        pass
    return 'ok'


def _make_handler(method, path, headers, body):
    S = _server
    h = S.RBAAuditHandler.__new__(S.RBAAuditHandler)
    h.rfile = io.BytesIO(body or b'')
    h.wfile = io.BytesIO()
    h.client_address = ('127.0.0.1', 0)
    h.server = None
    h.request = None
    h.command = method
    h.path = path
    h.request_version = 'HTTP/1.1'
    h.requestline = f'{method} {path} HTTP/1.1'
    h.close_connection = True
    msg = email.message.Message()
    for k, v in (headers or {}).items():
        lk = k.lower()
        if lk in ('host', 'content-length', 'x-forwarded-for', 'cf-connecting-ip', 'x-real-ip', 'forwarded', 'tailscale-funnel-request', 'cookie'):
            continue
        msg[k] = v
    msg['Host'] = '127.0.0.1:8801'
    msg['Content-Length'] = str(len(body or b''))
    h.headers = msg
    return h


def _parse_raw(raw):
    head, _, body = raw.partition(b'\r\n\r\n')
    lines = head.decode('iso-8859-1').split('\r\n')
    # A handler may emit several header blocks only on errors; keep the first status line
    try:
        status = int(lines[0].split(' ')[1])
    except Exception:
        status = 500
    hdrs = []
    for ln in lines[1:]:
        if ':' in ln:
            k, v = ln.split(':', 1)
            hdrs.append([k.strip(), v.strip()])
    return status, hdrs, body


def _pdf_html(h, parsed):
    """HTML bản in của báo cáo (thay cho PDF): trình duyệt sẽ In → Lưu thành PDF."""
    S = _server
    qs = urllib.parse.parse_qs(parsed.query)
    token = h._token(parsed)
    rid = qs.get('record_id', [''])[0]
    if rid:
        if not h._need(token, 'can_view_storage'):
            return
        repo, rec = S.find_record(rid)
        if not rec:
            return h._err('Không tìm thấy báo cáo!', 404)
        if not S.can_record(token, rec, 'view'):
            return h._err('Bạn không có quyền xem báo cáo này.', 403)
        with S.LOCK:
            ws = S.load_record_into_ws(rec)
    else:
        if not h._need(token, 'can_export_word'):
            return
        uname, ws = h._ws(token)
        if not ws:
            return
        if ws['mode'] == 'round2' and not ws['data']['round2'].get('confirmed'):
            return h._err('Kết quả lần 2 chưa được xác nhận. Vui lòng xác nhận trước khi xuất file.', 409)
    data = ws['data']
    r2s = data['round2']['summary2'] if ws['mode'] == 'round2' else None
    title = S.report_title(data.get('metadata', {}), 2 if r2s else 1)
    lang = qs.get('lang', ['vi_ko'])[0]
    html_text = S.build_report_html(S.docx_view_data(ws), r2s, title, lang_mode=lang)
    html_text = html_text.replace('<head>', f'<head><title>{title}</title>', 1) if '<title>' not in html_text else html_text
    payload = html_text.encode('utf-8')
    h.send_response(200)
    h.send_header('Content-Type', 'text/html; charset=utf-8')
    h.send_header('Content-Length', str(len(payload)))
    h.send_header('Cache-Control', 'no-store')
    h.end_headers()
    h.wfile.write(payload)


def handle(method, path, headers_json, body_js=None):
    """Trả về (status, headers_json, body_bytes)."""
    headers = json.loads(headers_json or '{}')
    body = body_js.to_bytes() if body_js is not None and hasattr(body_js, 'to_bytes') else (body_js or b'')
    if not path.startswith('/'):
        path = '/' + path
    h = _make_handler(method, path, headers, body)
    parsed = urllib.parse.urlparse(path)
    try:
        if parsed.path == '/api/web/pdf_html':
            _pdf_html(h, parsed)
        elif method == 'POST':
            h.do_POST()
        elif method == 'HEAD':
            h.do_HEAD()
        else:
            h.do_GET()
    except Exception as e:  # never break the page: report as JSON error
        import traceback
        traceback.print_exc()
        h.wfile = io.BytesIO()
        payload = json.dumps({'status': 'error', 'message': f'Lỗi xử lý: {e}'}, ensure_ascii=False).encode('utf-8')
        return 500, json.dumps([['Content-Type', 'application/json; charset=utf-8']]), payload
    status, hdrs, out = _parse_raw(h.wfile.getvalue())
    h.wfile = None
    if parsed.path.startswith(('/api/download/', '/api/storage/')):
        try:
            _server.cleanup_output_dir(-1)
            import gc
            gc.collect()
        except Exception:
            pass
    ctype = next((v for k, v in hdrs if k.lower() == 'content-type'), '')
    if 'json' in ctype:
        # đường dẫn tương đối để chạy được dưới /rba-ehs/ trên GitHub Pages
        out = out.replace(b'"/api/', b'"api/')
        hdrs = [[k, (str(len(out)) if k.lower() == 'content-length' else v)] for k, v in hdrs]
    hdrs = [[k, v] for k, v in hdrs if k.lower() not in ('content-security-policy', 'set-cookie', 'connection', 'server', 'date')]
    return status, json.dumps(hdrs), out
