"""
Backup & restore for the RBA 8.0.1 system.

- Code + database backups are small and created automatically:
    * at every successful server start when the code changed ("startup" = known-good version)
    * once a day ("daily")
    * before any restore ("pre_restore")
- Full backups (including the storage/ report archive) can be created manually by the admin.
- start_server.py uses latest_good_backup() to roll back automatically if an update
  prevents the server from starting.
© NGUYỄN NGỌC NGÔN — RBA 8.0.1 EHS Automation Suite
"""
import os
import json
import shutil
import zipfile
import hashlib
import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BACKUP_DIR = os.path.join(BASE_DIR, "backups")
CODE_FILES = ["engine.py", "server.py", "system_core.py", "round2.py", "backup.py", "index.html",
              "start_server.py", "restore_backup.py", "history.py", "learning.py", "notify.py", "report_pdf.py", "build_offline.py", "build_css.py", "autostart_mac.sh"]
DATA_DIRS = ["database", "templates", "static"]
STORAGE_DIRNAME = "storage"
KEEP_AUTO = 20


def _ensure():
    os.makedirs(BACKUP_DIR, exist_ok=True)


def code_hash():
    h = hashlib.sha256()
    for f in CODE_FILES:
        p = os.path.join(BASE_DIR, f)
        if os.path.exists(p):
            with open(p, "rb") as fh:
                h.update(f.encode() + fh.read())
    return h.hexdigest()[:16]


def _iter_dir(rel_dir, skip_autosave=False):
    root = os.path.join(BASE_DIR, rel_dir)
    for cur, _, files in os.walk(root):
        for fn in files:
            if fn.startswith(".") or fn.endswith(".tmp"):
                continue
            abs_p = os.path.join(cur, fn)
            rel = os.path.relpath(abs_p, BASE_DIR)
            if skip_autosave and rel.startswith(os.path.join("database", "autosave")):
                continue
            yield abs_p, rel


def create_backup(kind="manual", include_storage=False, actor="system", note=""):
    """kind: manual | startup | daily | pre_restore"""
    _ensure()
    now = datetime.datetime.now()
    name = f"backup_{now.strftime('%Y%m%d_%H%M%S')}_{kind}{'_full' if include_storage else ''}.zip"
    path = os.path.join(BACKUP_DIR, name)
    manifest = {
        "name": name, "kind": kind, "include_storage": include_storage,
        "created_at": now.strftime("%Y-%m-%d %H:%M:%S"), "created_by": actor, "note": note,
        "code_hash": code_hash(), "known_good": kind == "startup",
        "standard": "RBA 8.0.1", "copyright": "NGUYỄN NGỌC NGÔN",
    }
    tmp = path + ".tmp"
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as z:
        for f in CODE_FILES:
            p = os.path.join(BASE_DIR, f)
            if os.path.exists(p):
                z.write(p, f)
        for d in DATA_DIRS:
            for abs_p, rel in _iter_dir(d, skip_autosave=True):
                z.write(abs_p, rel)
        if include_storage:
            for abs_p, rel in _iter_dir(STORAGE_DIRNAME):
                z.write(abs_p, rel)
        z.writestr("backup_manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))
    os.replace(tmp, path)
    manifest["size_mb"] = round(os.path.getsize(path) / 1024 / 1024, 2)
    _prune()
    return manifest


def _read_manifest(path):
    try:
        with zipfile.ZipFile(path) as z:
            m = json.loads(z.read("backup_manifest.json"))
        m["name"] = os.path.basename(path)
        m["size_mb"] = round(os.path.getsize(path) / 1024 / 1024, 2)
        return m
    except Exception:
        return None


def list_backups():
    _ensure()
    out = []
    for fn in sorted(os.listdir(BACKUP_DIR), reverse=True):
        if fn.endswith(".zip"):
            m = _read_manifest(os.path.join(BACKUP_DIR, fn))
            if m:
                out.append(m)
    return out


def _prune():
    auto = [b for b in list_backups() if b["kind"] in ("startup", "daily", "pre_restore")]
    for b in auto[KEEP_AUTO:]:
        try:
            os.remove(os.path.join(BACKUP_DIR, b["name"]))
        except OSError:
            pass


def latest_good_backup(exclude_hash=None):
    for b in list_backups():
        if b.get("known_good") and b.get("code_hash") != exclude_hash:
            return b
    return None


def ensure_startup_backup():
    """Called after the server started successfully: snapshot this known-good version if new."""
    cur = code_hash()
    last = next((b for b in list_backups() if b["kind"] == "startup"), None)
    if not last or last.get("code_hash") != cur:
        return create_backup("startup", actor="system", note="Phiên bản khởi động thành công")
    return None


def ensure_daily_backup():
    today = datetime.datetime.now().strftime("%Y%m%d")
    if not any(b["kind"] == "daily" and b["name"].startswith(f"backup_{today}") for b in list_backups()):
        return create_backup("daily", actor="system", note="Sao lưu tự động hằng ngày")
    return None


def safe_backup_path(name):
    p = os.path.abspath(os.path.join(BACKUP_DIR, os.path.basename(name)))
    if not p.startswith(os.path.abspath(BACKUP_DIR)) or not os.path.isfile(p):
        return None
    return p


def restore_backup(name, restore_code=True, restore_data=True, restore_storage=True, actor="system"):
    """Restores a backup. A 'pre_restore' snapshot of the current state is taken first."""
    path = safe_backup_path(name)
    if not path:
        raise FileNotFoundError(name)
    m = _read_manifest(path) or {}
    create_backup("pre_restore", include_storage=bool(m.get("include_storage") and restore_storage),
                  actor=actor, note=f"Trước khi khôi phục {name}")
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        if restore_data:
            for d in DATA_DIRS:
                members = [n for n in names if n.startswith(d + "/")]
                if members:
                    for n in members:
                        if n.startswith("database/autosave/"):
                            continue
                        target = os.path.join(BASE_DIR, n)
                        os.makedirs(os.path.dirname(target), exist_ok=True)
                        with z.open(n) as src, open(target + ".tmp", "wb") as dst:
                            shutil.copyfileobj(src, dst)
                        os.replace(target + ".tmp", target)
        if restore_storage and m.get("include_storage"):
            for n in [n for n in names if n.startswith(STORAGE_DIRNAME + "/")]:
                target = os.path.join(BASE_DIR, n)
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with z.open(n) as src, open(target, "wb") as dst:
                    shutil.copyfileobj(src, dst)
        if restore_code:
            for f in CODE_FILES:
                if f in names:
                    target = os.path.join(BASE_DIR, f)
                    with z.open(f) as src, open(target + ".tmp", "wb") as dst:
                        shutil.copyfileobj(src, dst)
                    os.replace(target + ".tmp", target)
    return m


def delete_backup(name):
    path = safe_backup_path(name)
    if path:
        os.remove(path)
        return True
    return False
