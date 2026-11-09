"""
Builds the offline installation package:  dist/RBA_8.0.1_Offline_<date>.zip
    python3 build_offline.py
The package contains the application, local UI assets, master data and the Word/Excel
templates — but no personal data (accounts, reports, autosaves, notification secrets).
© NGUYỄN NGỌC NGÔN — RBA 8.0.1 EHS Automation Suite
"""
import os
import re
import stat
import zipfile
import datetime
import unicodedata

BASE = os.path.dirname(os.path.abspath(__file__))
ROOT = "RBA_8.0.1_Full_Setup"
CODE = ["engine.py", "server.py", "system_core.py", "round2.py", "backup.py", "history.py", "learning.py",
        "notify.py", "report_pdf.py", "start_server.py", "restore_backup.py", "build_offline.py", "build_css.py", "index.html",
        "autostart_mac.sh", "requirements.txt", "Dockerfile", "Procfile", "render.yaml"]
DIRS = ["static", "templates"]
DATA = ["database/rba_801_master_rules.json"]
EMPTY_DIRS = ["storage", "storage/01_Master_Templates", "output", "backups", "database/autosave", "logs"]
LAUNCHERS = ["Khoi_dong_RBA.command", "Khoi_dong_RBA.bat", "Khoi_phuc_ban_on_dinh.command",
             "Khoi_phuc_ban_on_dinh.bat", "HUONG_DAN_CAI_DAT.txt"]
MANUAL = "TAI_LIEU_RBA_8.0.1.pdf"   # built from docs/TAI_LIEU_RBA_8.0.1.html


def _add(z, src, arc, executable=False):
    arc = unicodedata.normalize('NFC', arc)
    info = zipfile.ZipInfo.from_file(src, arc)
    mode = 0o755 if executable else 0o644
    info.external_attr = (stat.S_IFREG | mode) << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    data = open(src, "rb").read()
    if arc.endswith(".txt") and not data.startswith(b"\xef\xbb\xbf"):
        data = b"\xef\xbb\xbf" + data  # UTF-8 BOM so Windows Notepad shows Vietnamese correctly
    if arc.endswith("HUONG_DAN_CAI_DAT.txt"):
        # The Internet section describes this machine's own link and launcher
        data = re.sub("IV-B\\..*?(?=V\\. DỮ LIỆU)".encode("utf-8"), b"", data, flags=re.S)
    z.writestr(info, data)


def build():
    os.makedirs(os.path.join(BASE, "dist"), exist_ok=True)
    out = os.path.join(BASE, "dist", f"{ROOT}_{datetime.datetime.now().strftime('%Y%m%d')}.zip")
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for f in CODE:
            _add(z, os.path.join(BASE, f), f"{ROOT}/{f}", executable=f.endswith(".sh"))
        for d in DIRS:
            for cur, _, files in os.walk(os.path.join(BASE, d)):
                for fn in files:
                    if fn.startswith(".") or fn.endswith((".zip", ".sh")):
                        continue
                    p = os.path.join(cur, fn)
                    _add(z, p, f"{ROOT}/{os.path.relpath(p, BASE)}")
        for cur, _, files in os.walk(os.path.join(BASE, "templates")):
            for fn in files:
                if fn.startswith("."):
                    continue
                p = os.path.join(cur, fn)
                _add(z, p, f"{ROOT}/storage/01_Master_Templates/{fn}")
        for f in DATA:
            _add(z, os.path.join(BASE, f), f"{ROOT}/{f}")
        for d in EMPTY_DIRS:
            zi = zipfile.ZipInfo(f"{ROOT}/{d}/", date_time=datetime.datetime.now().timetuple()[:6])
            zi.external_attr = ((stat.S_IFDIR | 0o755) << 16) | 0x10  # rwxr-xr-x directory
            z.writestr(zi, "")
        for f in LAUNCHERS:
            _add(z, os.path.join(BASE, f), f"{ROOT}/{f}", executable=f.endswith(".command"))
        _add(z, os.path.join(BASE, "docs", MANUAL), f"{ROOT}/{MANUAL}")
    return out


if __name__ == "__main__":
    path = build()
    print(f"Đã tạo gói cài đặt offline: {path} ({os.path.getsize(path) / 1024 / 1024:.1f} MB)")
