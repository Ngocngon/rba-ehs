"""
Đóng gói bản web (GitHub Pages) của RBA 8.0.1 vào thư mục docs/.
    python3 build_web.py
- src/   : mã nguồn gốc (chạy được như server Python bình thường)
- web/   : phần bổ sung cho trình duyệt (Pyodide bridge, worker, service worker)
- docs/  : kết quả, GitHub Pages phục vụ thư mục này
© NGUYỄN NGỌC NGÔN — RBA 8.0.1 EHS Automation Suite
"""
import hashlib
import io
import os
import re
import shutil
import zipfile

ROOT = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(ROOT, 'src')
WEB = os.path.join(ROOT, 'web')
OUT = os.path.join(ROOT, 'docs')

PY_SKIP = {'build_css.py', 'build_offline.py', 'start_server.py', 'restore_backup.py'}
DB_SKIP = {'file_repository.json', 'sessions.json', 'auth_config.json'}


def build_app_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        for fn in sorted(os.listdir(SRC)):
            if fn.endswith('.py') and fn not in PY_SKIP:
                z.write(os.path.join(SRC, fn), fn)
        for d in ('templates', 'database'):
            for cur, dirs, files in os.walk(os.path.join(SRC, d)):
                dirs[:] = [x for x in dirs if x not in ('autosave', '__pycache__')]
                for fn in sorted(files):
                    if fn.startswith('.') or fn.endswith('.tmp') or (d == 'database' and fn in DB_SKIP):
                        continue
                    p = os.path.join(cur, fn)
                    z.write(p, os.path.relpath(p, SRC).replace(os.sep, '/'))
    return buf.getvalue()


def patch_index(html, build):
    html = re.sub(r'''(['"`(])/api/''', r'\1api/', html)
    html = re.sub(r'''(['"`(])/static/''', r'\1static/', html)
    html = html.replace('</head>', f'  <script src="web-boot.js?v={build}"></script>\n</head>', 1)
    tail = html.rfind('boot();')
    assert tail > 0, 'boot() call not found'
    html = html[:tail] + 'window.__rbaReady.then(boot);' + html[tail + len('boot();'):]
    return html


def main():
    app_zip = build_app_zip()
    with open(os.path.join(SRC, 'index.html'), encoding='utf-8') as f:
        index = f.read()
    h = hashlib.sha256(app_zip + index.encode('utf-8'))
    for fn in ('web-boot.js', 'engine-worker.js', 'sw.js', 'bridge.py'):
        with open(os.path.join(WEB, fn), 'rb') as f:
            h.update(f.read())
    build = h.hexdigest()[:10]

    if os.path.isdir(OUT):
        shutil.rmtree(OUT)
    os.makedirs(os.path.join(OUT, 'static'))
    with open(os.path.join(OUT, 'app.zip'), 'wb') as f:
        f.write(app_zip)
    with open(os.path.join(OUT, 'index.html'), 'w', encoding='utf-8') as f:
        f.write(patch_index(index, build))
    for fn in os.listdir(os.path.join(SRC, 'static')):
        if fn != 'tailwind.js':
            shutil.copy2(os.path.join(SRC, 'static', fn), os.path.join(OUT, 'static', fn))
    for fn in ('web-boot.js', 'engine-worker.js', 'sw.js', 'bridge.py'):
        with open(os.path.join(WEB, fn), encoding='utf-8') as f:
            s = f.read().replace('__BUILD__', build)
        with open(os.path.join(OUT, fn), 'w', encoding='utf-8') as f:
            f.write(s)
    open(os.path.join(OUT, '.nojekyll'), 'w').close()
    print(f'Build {build}: docs/ ({len(app_zip) / 1024 / 1024:.1f} MB app.zip)')


if __name__ == '__main__':
    main()
