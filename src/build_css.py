"""
Pre-compiles the Tailwind classes used by index.html into static/tailwind.css, so the
browser does not have to run the Tailwind compiler on every page load.
    python3 build_css.py
Run it again after changing class names in index.html. Works offline: it uses
static/tailwind.js with the Chrome or Edge already installed on this machine.
© NGUYỄN NGỌC NGÔN — RBA 8.0.1 EHS Automation Suite
"""
import hashlib
import html
import os
import pathlib
import re
import shutil
import subprocess
import tempfile

from report_pdf import BROWSER_CANDIDATES, _which

BASE = os.path.dirname(os.path.abspath(__file__))
INDEX = os.path.join(BASE, "index.html")
TAILWIND_JS = os.path.join(BASE, "static", "tailwind.js")
OUTPUT = os.path.join(BASE, "static", "tailwind.css")


def compile_css(source, browser):
    # Every word of index.html is offered as a class: Tailwind keeps only the real ones
    tokens = sorted(set(re.findall(r"[^\s\"'`<>=${}]+", source)))
    page = (f'<!DOCTYPE html><html><head><script src="{pathlib.Path(TAILWIND_JS).as_uri()}"></script></head>'
            f'<body><div class="{html.escape(" ".join(tokens))}"></div></body></html>')
    tmpdir = tempfile.mkdtemp(prefix="rba_css_")
    try:
        src = os.path.join(tmpdir, "page.html")
        with open(src, "w", encoding="utf-8") as f:
            f.write(page)
        dom = subprocess.run([browser, "--headless=new", "--disable-gpu", f"--user-data-dir={os.path.join(tmpdir, 'profile')}",
                              "--no-first-run", "--virtual-time-budget=15000", "--dump-dom", pathlib.Path(src).as_uri()],
                             check=True, timeout=120, capture_output=True, text=True, encoding="utf-8").stdout
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    css = max(re.findall(r"<style[^>]*>(.*?)</style>", dom, re.S), key=len, default="")
    if "tailwindcss" not in css:
        raise RuntimeError("Trình duyệt không tạo được CSS từ Tailwind.")
    return css


def build():
    browser = _which(BROWSER_CANDIDATES)
    if not browser:
        raise RuntimeError("Cần Google Chrome hoặc Microsoft Edge để biên dịch CSS.")
    with open(INDEX, "r", encoding="utf-8") as f:
        source = f.read()
    css = compile_css(source, browser)
    with open(OUTPUT, "w", encoding="utf-8") as f:
        f.write(css)
    # Static files are cached for a week: a new version needs a new URL
    version = hashlib.sha256(css.encode("utf-8")).hexdigest()[:10]
    with open(INDEX, "w", encoding="utf-8") as f:
        f.write(re.sub(r"/static/tailwind\.css(\?v=\w+)?", f"/static/tailwind.css?v={version}", source))
    return len(css), version


if __name__ == "__main__":
    size, ver = build()
    print(f"Đã tạo static/tailwind.css ({size / 1024:.1f} KB, phiên bản {ver})")
