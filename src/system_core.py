import os
import re
import json
import copy
import shutil
import hashlib
import secrets
import time
import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_DIR = os.path.join(BASE_DIR, "database")
STORAGE_DIR = os.path.join(BASE_DIR, "storage")

# Structured storage categories
STORAGE_FOLDERS = {
    "templates": "01_Master_Templates",
    "findings": "02_Uploaded_Findings",
    "checklists": "03_Generated_Checklists",
    "reports": "04_Generated_Word_Reports",
    "bundles": "05_Archived_Bundles",
    "revisions": "06_Revisions",
}

MASTER_RULES_FILE = os.path.join(DB_DIR, "rba_801_master_rules.json")
AUTH_CONFIG_FILE = os.path.join(DB_DIR, "auth_config.json")
REPOSITORY_FILE = os.path.join(DB_DIR, "file_repository.json")
TRANSLATION_MEMORY_FILE = os.path.join(DB_DIR, "translation_memory.json")

# In-memory active session tokens: token -> user_dict
ACTIVE_SESSIONS = {}


def ensure_directories():
    os.makedirs(DB_DIR, exist_ok=True)
    os.makedirs(STORAGE_DIR, exist_ok=True)
    for folder_name in STORAGE_FOLDERS.values():
        os.makedirs(os.path.join(STORAGE_DIR, folder_name), exist_ok=True)


PBKDF2_ITERATIONS = 200_000
DEFAULT_PASSWORDS = {"ngocngon": "Abc1234@@", "khach": "123456"}
SECURITY_DEFAULTS = {"session_idle_minutes": 60, "session_max_hours": 12, "max_failed_logins": 5, "lock_minutes": 15}
FAILED_LOGINS = {}   # (username, ip) -> [timestamps]
LOCKED_UNTIL = {}    # (username, ip) -> epoch seconds


def _legacy_hash(password: str) -> str:
    return hashlib.sha256(f"RBA801_NNN_SALT::{password}".encode("utf-8")).hexdigest()


def _hash_password(password: str) -> str:
    """PBKDF2-SHA256 with a random per-user salt."""
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", (password or "").encode("utf-8"), salt.encode("ascii"), PBKDF2_ITERATIONS).hex()
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt}${digest}"


def verify_password(password: str, stored: str) -> bool:
    stored = stored or ""
    if stored.startswith("pbkdf2_sha256$"):
        try:
            _, iters, salt, digest = stored.split("$", 3)
            calc = hashlib.pbkdf2_hmac("sha256", (password or "").encode("utf-8"), salt.encode("ascii"), int(iters)).hex()
            return secrets.compare_digest(calc, digest)
        except (ValueError, TypeError):
            return False
    return secrets.compare_digest(_legacy_hash(password or ""), stored)


def security_settings():
    cfg = load_auth_config()
    out = dict(SECURITY_DEFAULTS)
    out.update({k: v for k, v in (cfg.get("security") or {}).items() if k in SECURITY_DEFAULTS})
    return out


def password_policy_error(username: str, new_password: str):
    pw = new_password or ""
    if len(pw) < 8:
        return "Mật khẩu mới phải có ít nhất 8 ký tự."
    if not any(c.isalpha() for c in pw) or not any(c.isdigit() for c in pw):
        return "Mật khẩu mới phải có cả chữ và số."
    if pw.lower() == (username or "").lower():
        return "Mật khẩu không được trùng tên đăng nhập."
    if pw in DEFAULT_PASSWORDS.values():
        return "Không được dùng lại mật khẩu mặc định."
    return None


# ==============================================================================
# 1. AUTHENTICATION & ROLE-BASED ACCESS CONTROL (ADMIN / GUEST)
# ==============================================================================

DEFAULT_GUEST_PERMISSIONS = {
    "can_upload_findings": True,
    "can_edit_checklist": False,
    "can_use_qa_autofix": True,
    "can_export_excel": True,
    "can_export_word": True,
    "can_view_storage": True,
    "can_save_to_storage": True,
    "can_edit_storage": False,
    "can_delete_storage": False,
    "can_upload_round2": True,
}

PERMISSION_LABELS = {
    "can_upload_findings": {
        "title": "Nạp & Phân tích File Audit Findings (.xlsm/.xlsx)",
        "desc": "Cho phép Khách tải file Finding mới lên để hệ thống tự động chấm điểm và phân loại."
    },
    "can_edit_checklist": {
        "title": "Chỉnh sửa Kết quả 41 mã Checklist & Nội dung Báo cáo Word",
        "desc": "Cho phép Khách thay đổi mức độ lỗi (Conformance/Minor/Major/Priority) hoặc sửa câu chữ báo cáo."
    },
    "can_use_qa_autofix": {
        "title": "Sử dụng Bộ Kiểm tra & Tự động Sửa lỗi Chính tả / Dấu câu / Phụ đề",
        "desc": "Cho phép Khách chạy công cụ tự động chuẩn hóa chính tả, dấu câu và phụ đề song ngữ."
    },
    "can_export_excel": {
        "title": "Xuất & Tải xuống RBA 8.0.1 Audit Checklist (.xlsx)",
        "desc": "Cho phép Khách tải về file Excel RBA 8.0.1 Checklist đã điền đầy đủ công thức VLOOKUP."
    },
    "can_export_word": {
        "title": "Xuất & Tải xuống Báo cáo Tóm tắt RBA 8.0.1 (.docx)",
        "desc": "Cho phép Khách tải về file Word Báo cáo Tóm tắt Kết quả Đánh giá Định kỳ RBA 8.0.1."
    },
    "can_view_storage": {
        "title": "Truy cập & Tải file từ Kho Lưu trữ Hệ thống",
        "desc": "Cho phép Khách xem danh mục hồ sơ đã lưu trữ và tải lại các file báo cáo cũ."
    },
    "can_save_to_storage": {
        "title": "Lưu Hồ sơ Đánh giá vào Kho Lưu trữ Hệ thống",
        "desc": "Cho phép Khách đóng gói và lưu đợt đánh giá hiện tại vào thư mục phân loại trên server."
    },
    "can_edit_storage": {
        "title": "Sửa báo cáo trong Kho (chỉ báo cáo do mình lưu)",
        "desc": "Sửa tiêu đề, ghi chú và cập nhật nội dung báo cáo đã lưu."
    },
    "can_delete_storage": {
        "title": "Xóa báo cáo trong Kho (chỉ báo cáo do mình lưu)",
        "desc": "Xóa vĩnh viễn báo cáo và các tệp đính kèm."
    },
    "can_upload_round2": {
        "title": "Nạp & xác nhận kết quả đánh giá lần 2",
        "desc": "Nạp file Finding lần 2, đối chiếu với lần 1 và xác nhận kết quả."
    },
}


def init_auth_config():
    ensure_directories()
    if not os.path.exists(AUTH_CONFIG_FILE):
        default_auth = {
            "copyright_owner": "NGUYỄN NGỌC NGÔN",
            "updated_at": datetime.datetime.now().isoformat(),
            "users": [
                {
                    "username": "ngocngon",
                    "password_hash": _hash_password("Abc1234@@"),
                    "role": "admin",
                    "display_name": "NGUYỄN NGỌC NGÔN (Admin)",
                    "active": True,
                    "must_change_password": True,
                    "created_at": datetime.datetime.now().isoformat(),
                },
                {
                    "username": "khach",
                    "password_hash": _hash_password("123456"),
                    "role": "guest",
                    "display_name": "Khách truy cập (Guest)",
                    "active": True,
                    "created_at": datetime.datetime.now().isoformat(),
                },
            ],
            "allow_quick_guest_login": True,
            "guest_permissions": copy.deepcopy(DEFAULT_GUEST_PERMISSIONS),
            "audit_logs": [
                {
                    "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "actor": "SYSTEM",
                    "action": "Khởi tạo hệ thống bảo mật & tài khoản Admin mặc định (ngocngon)",
                }
            ],
        }
        with open(AUTH_CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(default_auth, f, ensure_ascii=False, indent=2)
    return load_auth_config()


def load_auth_config():
    if not os.path.exists(AUTH_CONFIG_FILE):
        return init_auth_config()
    with open(AUTH_CONFIG_FILE, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    # Ensure admin 'ngocngon' always exists
    has_admin = any(u.get("username") == "ngocngon" for u in cfg.get("users", []))
    if not has_admin:
        cfg.setdefault("users", []).insert(0, {
            "username": "ngocngon",
            "password_hash": _hash_password("Abc1234@@"),
            "role": "admin",
            "display_name": "NGUYỄN NGỌC NGÔN (Admin)",
            "active": True,
            "created_at": datetime.datetime.now().isoformat(),
        })
    for k, v in DEFAULT_GUEST_PERMISSIONS.items():
        cfg.setdefault("guest_permissions", {}).setdefault(k, v)
    return cfg


def save_auth_config(cfg):
    cfg["updated_at"] = datetime.datetime.now().isoformat()
    tmp = AUTH_CONFIG_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    os.replace(tmp, AUTH_CONFIG_FILE)   # readers never see a half-written file


def add_audit_log(actor: str, action: str):
    cfg = load_auth_config()
    logs = cfg.setdefault("audit_logs", [])
    logs.insert(0, {
        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "actor": actor,
        "action": action,
    })
    cfg["audit_logs"] = logs[:100]
    save_auth_config(cfg)


def _lock_key(username, ip):
    return ((username or "").strip().lower(), ip or "-")


def authenticate_user(username: str, password: str, is_quick_guest: bool = False, ip: str = ""):
    cfg = load_auth_config()
    sec = security_settings()
    now_iso = datetime.datetime.now().isoformat()
    if is_quick_guest:
        if not cfg.get("allow_quick_guest_login", True):
            return None, "Quản trị viên đã tắt tính năng đăng nhập Khách nhanh. Vui lòng dùng tài khoản được cấp."
        token = secrets.token_hex(24)
        session_user = {"username": "khach", "display_name": "Khách (Guest)", "role": "guest",
                        "login_at": now_iso, "last_seen": now_iso, "quick_guest": True}
        ACTIVE_SESSIONS[token] = session_user
        add_audit_log("Khách (Guest)", "Đăng nhập hệ thống với quyền Khách")
        return {"token": token, "user": session_user,
                "permissions": cfg.get("guest_permissions", DEFAULT_GUEST_PERMISSIONS)}, None

    uname = (username or "").strip()
    key = _lock_key(uname, ip)
    now = time.time()
    if LOCKED_UNTIL.get(key, 0) > now:
        mins = int((LOCKED_UNTIL[key] - now) // 60) + 1
        return None, f"Tài khoản tạm khóa do nhập sai mật khẩu nhiều lần. Vui lòng thử lại sau {mins} phút."

    user = next((u for u in cfg.get("users", []) if u.get("username", "").lower() == uname.lower()), None)
    if user and verify_password(password, user.get("password_hash")):
        if not user.get("active", True):
            return None, "Tài khoản này đang bị tạm khóa bởi Admin."
        FAILED_LOGINS.pop(key, None)
        LOCKED_UNTIL.pop(key, None)
        changed = False
        if not str(user.get("password_hash", "")).startswith("pbkdf2_sha256$"):
            user["password_hash"] = _hash_password(password)   # upgrade old hash transparently
            changed = True
        if changed:
            save_auth_config(cfg)
        token = secrets.token_hex(24)
        role = user.get("role", "guest")
        session_user = {"username": user["username"], "display_name": user.get("display_name", user["username"]),
                        "role": role, "login_at": now_iso, "last_seen": now_iso,
                        "must_change_password": bool(user.get("must_change_password"))}
        ACTIVE_SESSIONS[token] = session_user
        perms = ({k: True for k in DEFAULT_GUEST_PERMISSIONS} if role == "admin"
                 else cfg.get("guest_permissions", DEFAULT_GUEST_PERMISSIONS))
        add_audit_log(session_user["display_name"], f"Đăng nhập thành công ({role.upper()}) từ {ip or 'máy chủ'}")
        return {"token": token, "user": session_user, "permissions": perms}, None

    # failed attempt
    window = sec["lock_minutes"] * 60
    attempts = [t for t in FAILED_LOGINS.get(key, []) if now - t < window] + [now]
    FAILED_LOGINS[key] = attempts
    left = sec["max_failed_logins"] - len(attempts)
    if left <= 0:
        LOCKED_UNTIL[key] = now + window
        FAILED_LOGINS.pop(key, None)
        add_audit_log("SECURITY", f"Tạm khóa đăng nhập '{uname}' từ {ip or '-'} sau {sec['max_failed_logins']} lần sai")
        return None, f"Nhập sai quá {sec['max_failed_logins']} lần. Tài khoản tạm khóa {sec['lock_minutes']} phút."
    return None, f"Tên đăng nhập hoặc mật khẩu không đúng. Còn {left} lần thử trước khi bị tạm khóa."


def change_password(token: str, old_password: str, new_password: str):
    sess = ACTIVE_SESSIONS.get(token)
    if not sess or sess.get("quick_guest"):
        return "Phiên đăng nhập không hợp lệ để đổi mật khẩu."
    cfg = load_auth_config()
    user = next((u for u in cfg.get("users", []) if u["username"] == sess["username"]), None)
    if not user or not verify_password(old_password, user.get("password_hash")):
        return "Mật khẩu hiện tại không đúng."
    err = password_policy_error(user["username"], new_password)
    if err:
        return err
    if verify_password(new_password, user.get("password_hash")):
        return "Mật khẩu mới phải khác mật khẩu hiện tại."
    user["password_hash"] = _hash_password(new_password)
    user["must_change_password"] = False
    user["password_changed_at"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    save_auth_config(cfg)
    for t, s_ in list(ACTIVE_SESSIONS.items()):
        if s_.get("username") == user["username"]:
            if t == token:
                s_["must_change_password"] = False
            else:
                del ACTIVE_SESSIONS[t]      # sign out other devices
    add_audit_log(sess.get("display_name", user["username"]), "Đổi mật khẩu")
    return None


def _session_expired(sess, sec):
    if sess.get("no_expire"):   # only the host machine's own session
        return False
    now = datetime.datetime.now()
    try:
        last = datetime.datetime.fromisoformat(sess.get("last_seen") or sess.get("login_at"))
        start = datetime.datetime.fromisoformat(sess.get("login_at"))
    except (TypeError, ValueError):
        return True
    return (now - last).total_seconds() > sec["session_idle_minutes"] * 60 or \
           (now - start).total_seconds() > sec["session_max_hours"] * 3600


def get_or_create_local_admin_session():
    """Return or create a persistent passwordless Admin session token for this Mac."""
    cfg = load_auth_config()
    now_iso = datetime.datetime.now().isoformat()
    for t, s in list(ACTIVE_SESSIONS.items()):
        if s.get("local_mac_auto"):
            s["last_seen"] = now_iso
            s["no_expire"] = True
            s["must_change_password"] = False
            return t
    admin_user = next((u for u in cfg.get("users", []) if u.get("username") == "ngocngon"), None)
    display_name = (admin_user or {}).get("display_name", "NGUYỄN NGỌC NGÔN (Admin)")
    token = secrets.token_hex(24)
    ACTIVE_SESSIONS[token] = {
        "username": "ngocngon",
        "display_name": display_name,
        "role": "admin",
        "login_at": now_iso,
        "last_seen": now_iso,
        "no_expire": True,
        "local_mac_auto": True,
        "must_change_password": False,
    }
    return token


def get_session_context(token: str, touch: bool = True):
    cfg = load_auth_config()
    if token and token in ACTIVE_SESSIONS:
        user = ACTIVE_SESSIONS[token]
        sec = security_settings()
        account = next((u for u in cfg.get("users", []) if u["username"] == user.get("username")), None)
        if _session_expired(user, sec) or (not user.get("quick_guest") and (account is None or not account.get("active", True))):
            ACTIVE_SESSIONS.pop(token, None)
            return {
                "authenticated": False, "user": None, "expired": True,
                "permissions": cfg.get("guest_permissions", DEFAULT_GUEST_PERMISSIONS),
                "permission_labels": PERMISSION_LABELS,
                "allow_quick_guest_login": cfg.get("allow_quick_guest_login", True),
            }
        if touch:
            user["last_seen"] = datetime.datetime.now().isoformat()
        role = user.get("role", "guest")
        perms = (
            {k: True for k in DEFAULT_GUEST_PERMISSIONS}
            if role == "admin"
            else cfg.get("guest_permissions", DEFAULT_GUEST_PERMISSIONS)
        )
        return {
            "authenticated": True,
            "user": user,
            "permissions": perms,
            "permission_labels": PERMISSION_LABELS,
            "allow_quick_guest_login": cfg.get("allow_quick_guest_login", True),
            "security": sec,
        }
    return {
        "authenticated": False,
        "user": None,
        "permissions": cfg.get("guest_permissions", DEFAULT_GUEST_PERMISSIONS),
        "permission_labels": PERMISSION_LABELS,
        "allow_quick_guest_login": cfg.get("allow_quick_guest_login", True),
    }


def check_permission(token: str, perm_key: str):
    ctx = get_session_context(token)
    if not ctx["authenticated"]:
        return False, "Vui lòng đăng nhập để sử dụng hệ thống!"
    if ctx["user"]["role"] == "admin":
        return True, None
    if ctx["permissions"].get(perm_key, False):
        return True, None
    label = PERMISSION_LABELS.get(perm_key, {}).get("title", perm_key)
    return False, f"Tài khoản Khách chưa được Admin cấp quyền: '{label}'."


# ==============================================================================
# 2. MASTER DATABASE FOR RBA 8.0.1 CLASSIFICATION, VLOOKUP SCORING & 41 AUDIT IDs
# ==============================================================================

def init_or_load_master_rules(default_rule_matrix, default_category_groups, template_checklist_ref):
    """
    Ensures the persistent Master Rules & VLOOKUP Database exists on disk at
    database/rba_801_master_rules.json. If it doesn't exist yet, seeds it from
    the RBA 8.0.1 template and 41-code rule matrix.
    """
    ensure_directories()
    if os.path.exists(MASTER_RULES_FILE):
        try:
            with open(MASTER_RULES_FILE, "r", encoding="utf-8") as f:
                master_db = json.load(f)
            if master_db.get("items") and len(master_db["items"]) == 41:
                return master_db
        except Exception:
            pass

    return reset_master_rules_to_factory(default_rule_matrix, default_category_groups, template_checklist_ref)


def reset_master_rules_to_factory(default_rule_matrix, default_category_groups, template_checklist_ref):
    ensure_directories()
    items_master = []
    for it in template_checklist_ref.get("items", []):
        code = it["audit_id"]
        rule_entry = copy.deepcopy(default_rule_matrix.get(code, {
            "desc": it.get("sub_category", ""),
            "priority_kw": [],
            "major_kw": [],
            "major_min_count": 2,
        }))
        items_master.append({
            "row_num": it["row_num"],
            "provision": it["provision"],
            "audit_id": code,
            "audit_item": it.get("audit_item", "O"),
            "template_significance": it.get("template_significance", "Conformance"),
            "penalty_item": it.get("penalty_item", ""),
            "penalty_criteria": it.get("penalty_criteria", ""),
            "sub_category": it.get("sub_category", ""),
            "conformance_statement": it.get("conformance_statement", ""),
            "criteria_vn": it.get("criteria_vn", ""),
            "criteria_en": it.get("criteria_en", ""),
            "section": it.get("section", "EHS"),
            "scores": copy.deepcopy(it.get("scores", {
                "Conformance": 2, "Minor": 1, "Major": 0, "Priority": -2, "N/A": 2
            })),
            "rule": {
                "desc": rule_entry.get("desc", it.get("sub_category", "")),
                "priority_kw": list(rule_entry.get("priority_kw", [])),
                "major_kw": list(rule_entry.get("major_kw", [])),
                "major_min_count": int(rule_entry.get("major_min_count", 2)),
            }
        })

    master_db = {
        "standard_version": "RBA 8.0.1",
        "copyright_owner": "NGUYỄN NGỌC NGÔN",
        "updated_at": datetime.datetime.now().isoformat(),
        "updated_by": "ngocngon",
        "mandatory_triggers": ["mandatory", "bắt buộc", "hmbb", "x", "yes", "1"],
        "grade_thresholds": {
            "A": 90,
            "B": 80,
            "C": 70,
            "D": 0,
            "priority_downgrade_note": "Nếu phát sinh ≥ 1 lỗi Priority, hạ 1 cấp xếp hạng đối tác."
        },
        "category_groups": copy.deepcopy(default_category_groups),
        "items": items_master,
        "general_info_defaults": copy.deepcopy(template_checklist_ref.get("general_info_defaults", {})),
    }

    with open(MASTER_RULES_FILE, "w", encoding="utf-8") as f:
        json.dump(master_db, f, ensure_ascii=False, indent=2)

    return master_db


def save_master_rules(master_db, actor="ngocngon"):
    ensure_directories()
    master_db["updated_at"] = datetime.datetime.now().isoformat()
    master_db["updated_by"] = actor
    with open(MASTER_RULES_FILE, "w", encoding="utf-8") as f:
        json.dump(master_db, f, ensure_ascii=False, indent=2)
    add_audit_log(actor, "Cập nhật Dữ liệu gốc & Bộ quy tắc chấm điểm RBA 8.0.1")
    return master_db


# ==============================================================================
# 3. LOGIC ENGINE FOR SPELLING, PUNCTUATION & BILINGUAL SUBTITLE QA
# ==============================================================================

# Curated Vietnamese EHS spelling & terminology corrections (case-preserving where appropriate)
VN_SPELLING_RULES = [
    {
        "pattern": r"\bkhấp cấp\b",
        "replacement": "khẩn cấp",
        "reason": "Sai chính tả từ 'khấp cấp' ➔ chuẩn là 'khẩn cấp'",
    },
    {
        "pattern": r"\btrong phong\b",
        "replacement": "trong phòng",
        "reason": "Thiếu dấu thanh từ 'trong phong' ➔ chuẩn là 'trong phòng'",
    },
    {
        "pattern": r"\bnguyên tăc\b",
        "replacement": "nguyên tắc",
        "reason": "Thiếu dấu sắc từ 'nguyên tăc' ➔ chuẩn là 'nguyên tắc'",
    },
    {
        "pattern": r"\btháo tác\b",
        "replacement": "thao tác",
        "reason": "Sai dấu thanh từ 'tháo tác' ➔ chuẩn là 'thao tác'",
    },
    {
        "pattern": r"\btrong để kho\b",
        "replacement": "để trong kho",
        "reason": "Đảo ngược trật tự từ 'trong để kho' ➔ chuẩn là 'để trong kho'",
    },
    {
        "pattern": r"\btiếng việt\b",
        "replacement": "tiếng Việt",
        "reason": "Danh từ riêng 'Việt' chưa viết hoa ➔ chuẩn là 'tiếng Việt'",
    },
    {
        "pattern": r"\bhàn quốc\b",
        "replacement": "Hàn Quốc",
        "reason": "Danh từ riêng 'Hàn Quốc' chưa viết hoa ➔ chuẩn là 'Hàn Quốc'",
    },
    {
        "pattern": r"\bPhân Loại\b",
        "replacement": "Phân loại",
        "reason": "Viết hoa giữa cụm từ 'Phân Loại' không chuẩn ➔ 'Phân loại'",
    },
    {
        "pattern": r"\bchửa cháy\b|\bchữa chay\b",
        "replacement": "chữa cháy",
        "reason": "Sai chính tả cụm từ 'chữa cháy'",
    },
    {
        "pattern": r"\bdò rỉ\b|\brò dỉ\b",
        "replacement": "rò rỉ",
        "reason": "Sai chính tả từ 'rò rỉ'",
    },
    {
        "pattern": r"\bkhay khử khuẫn\b|\bkhử khuẫn\b",
        "replacement": "khử khuẩn",
        "reason": "Sai dấu ngã/hỏi từ 'khử khuẩn'",
    },
    {
        "pattern": r"\bsơ cấp cữu\b",
        "replacement": "sơ cấp cứu",
        "reason": "Sai chính tả từ 'sơ cấp cứu'",
    },
]

# Bilingual English subtitle / machine-translation corrections common in EHS findings
EN_SUBTITLE_RULES = [
    {
        "pattern": r"into the English language",
        "vn_trigger": "tiếng việt",
        "replacement": "into the Vietnamese language",
        "reason": "Phụ đề tiếng Anh ghi 'English language' bị ngược nghĩa với bản tiếng Việt 'tiếng Việt'",
    },
    {
        "pattern": r"October 13,\s*1925",
        "vn_trigger": "2025",
        "replacement": "October 13, 2025",
        "reason": "Lệch số năm giữa phụ đề tiếng Anh ('1925') và tiếng Việt ('2025')",
    },
    {
        "pattern": r"\bin the MM maple\b",
        "vn_trigger": "",
        "replacement": "in the MM room",
        "reason": "Lỗi dịch phụ đề tiếng Anh: 'MM maple' ➔ chuẩn là 'MM room' (Phòng MM)",
    },
    {
        "pattern": r"\bsea of management responsibilities\b",
        "vn_trigger": "",
        "replacement": "management responsibility signboard",
        "reason": "Lỗi dịch máy phụ đề: dịch chữ 'biển (báo)' thành 'sea' (biển cả) ➔ chuẩn là 'signboard'",
    },
    {
        "pattern": r"\bseas of responsibility\b|\bsea management\b|\bsea manages responsibility\b",
        "vn_trigger": "",
        "replacement": "management responsibility signs",
        "reason": "Lỗi dịch máy phụ đề: dịch chữ 'biển quản lý' thành 'sea' ➔ chuẩn là 'management responsibility signs'",
    },
    {
        "pattern": r"\bsea height limit\b",
        "vn_trigger": "",
        "replacement": "height limit sign",
        "reason": "Lỗi dịch máy phụ đề: 'biển giới hạn chiều cao' dịch nhầm thành 'sea height limit' ➔ chuẩn là 'height limit sign'",
    },
    {
        "pattern": r"\bPrices for rusty fire extinguishers\b",
        "vn_trigger": "",
        "replacement": "Rusty fire extinguisher racks",
        "reason": "Lỗi dịch máy phụ đề: 'Giá để bình chữa cháy' dịch nhầm thành 'Prices' (giá tiền) ➔ chuẩn là 'racks'",
    },
    {
        "pattern": r"\breplace price to flask\b",
        "vn_trigger": "",
        "replacement": "replace fire extinguisher rack",
        "reason": "Lỗi dịch máy phụ đề: 'thay thế giá để bình' dịch nhầm thành 'replace price to flask'",
    },
    {
        "pattern": r"\bMany designs on the device\b",
        "vn_trigger": "",
        "replacement": "Many pressure gauges on the equipment",
        "reason": "Lỗi dịch máy phụ đề: 'Nhiều áp kế' dịch nhầm thành 'Many designs' ➔ chuẩn là 'Many pressure gauges'",
    },
]

_VN_CHAR_RE = re.compile(
    r"[àáạảãâầấậẩẫăằắặẳẵèéẹẻẽêềếệểễìíịỉĩòóọỏõôồốộổỗơờớợởỡùúụủũưừứựửữỳýỵỷỹđ]",
    re.IGNORECASE,
)
_VN_WORD_RE = re.compile(
    r"\b(chưa|không|công ty|nhà máy|khu vực|quy trình|hồ sơ|thiết bị|an toàn|môi trường|nhân viên|người lao động|phòng cháy|chất thải|kiểm định|đào tạo|huấn luyện|nhà xưởng|tủ điện|bình chữa cháy)\b",
    re.IGNORECASE,
)

# Exact & phrase-level RBA 8.0.1 EHS bilingual dictionary (Vietnamese <-> English)
VN_TO_EN_EXACT = {
    "nhà máy": "Factory",
    "hồ sơ": "Document",
    "xưởng sản xuất": "Production workshop",
    "kho hóa chất": "Chemical warehouse",
    "kho hoá chất": "Chemical warehouse",
    "kho chất thải nguy hại": "Hazardous waste storage",
    "kho rác thải nguy hại": "Hazardous waste storage",
    "kho nguyên vật liệu": "Raw material warehouse",
    "kho thành phẩm": "Finished goods warehouse",
    "nhà ăn": "Canteen",
    "phòng y tế": "Medical room",
    "trạm xử lý nước thải": "Wastewater treatment plant",
}


def is_vietnamese_text(text: str) -> bool:
    s = str(text or "").strip()
    if not s:
        return False
    if _VN_CHAR_RE.search(s):
        return True
    if _VN_WORD_RE.search(s):
        return True
    return False


def auto_translate_vn_to_en(vn_text: str) -> str:
    """
    Translates a Vietnamese EHS finding/location/improvement text into English
    for bilingual RBA 8.0.1 reporting.
    """
    tm = _load_translation_memory()["vn_en"]
    exact = {_tm_key(vn): en for vn, en in VN_TO_EN_EXACT.items()}
    return _translate_lines(vn_text, lambda key: tm.get(key) or exact.get(key))


def auto_translate_en_to_vn(en_text: str) -> str:
    """
    Translates an English EHS finding/location/improvement text into Vietnamese
    when only English is provided.
    """
    tm = _load_translation_memory()["en_vn"]
    exact = {_tm_key(en): vn[:1].upper() + vn[1:] for vn, en in VN_TO_EN_EXACT.items()}
    return _translate_lines(en_text, lambda key: tm.get(key) or exact.get(key))


def _translate_lines(text, lookup):
    """
    Whole-sentence lookup of vetted translations, all lines or nothing. Returns "" when a line
    is unknown: word-by-word substitution produced text that contradicted the audit findings.
    """
    lines = [ln.strip() for ln in str(text or "").split("\n") if ln.strip()]
    found = [lookup(_tm_key(ln)) for ln in lines]
    return "\n".join(found) if lines and all(found) else ""


def _tm_key(text):
    return re.sub(r"\s+", " ", str(text or "").lower()).strip(" .,;:")


_TM_CACHE = {"mtime": None, "en_vn": {}, "vn_en": {}, "items": {}}


def _load_translation_memory():
    try:
        mtime = os.path.getmtime(TRANSLATION_MEMORY_FILE)
    except OSError:
        return _TM_CACHE
    if _TM_CACHE["mtime"] != mtime:
        with open(TRANSLATION_MEMORY_FILE, "r", encoding="utf-8") as f:
            items = json.load(f).get("items", [])
        _TM_CACHE.update(mtime=mtime, en_vn={_tm_key(i["en"]): i["vn"] for i in items},
                         vn_en={_tm_key(i["vn"]): i["en"] for i in items},
                         items={_tm_key(i["en"]): i for i in items})
    return _TM_CACHE


def reviewed_english(en_text):
    """The English text with the spelling corrections recorded for known sentences."""
    known = _load_translation_memory()["items"]
    lines = [ln.strip() for ln in str(en_text or "").split("\n") if ln.strip()]
    return "\n".join(known.get(_tm_key(ln), {}).get("en_fixed", ln) for ln in lines)


def draft_improvement_plan(issue_en):
    """(English, Vietnamese) improvement plan recorded for a known finding, or ("", "")."""
    item = _load_translation_memory()["items"].get(_tm_key(issue_en), {})
    return item.get("plan_en", ""), item.get("plan_vn", "")


def findings_cell_text(en_text, vn_text, field, finding_no, audit_id):
    """English then Vietnamese, as auditors lay out the Findings file, with spelling corrected."""
    _, en, vn = inspect_and_fix_field(en_text, vn_text, field, finding_no, audit_id)
    en = reviewed_english(en)
    return f"{en}\n{vn}" if en and vn and en != vn else (en or vn)


def remember_translation(en_text, vn_text):
    """Saves a vetted translation, line by line, for reuse on exact sentence matches."""
    en_lines = [ln.strip() for ln in str(en_text or "").split("\n") if ln.strip()]
    vn_lines = [ln.strip() for ln in str(vn_text or "").split("\n") if ln.strip()]
    if not en_lines or len(en_lines) != len(vn_lines) or any(is_vietnamese_text(ln) for ln in en_lines):
        return
    doc = {"items": []}
    if os.path.exists(TRANSLATION_MEMORY_FILE):
        with open(TRANSLATION_MEMORY_FILE, "r", encoding="utf-8") as f:
            doc = json.load(f)
    known = {_tm_key(i["en"]): i for i in doc.setdefault("items", [])}
    for en, vn in zip(en_lines, vn_lines):
        if _tm_key(en) in known:
            known[_tm_key(en)]["vn"] = vn
        else:
            doc["items"].append({"en": en, "vn": vn})
    tmp = TRANSLATION_MEMORY_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    os.replace(tmp, TRANSLATION_MEMORY_FILE)


def format_bilingual_vn_first(vn_text: str, en_text: str) -> str:
    """
    Always formats bilingual text with Vietnamese FIRST and English SECOND.
    """
    vn = str(vn_text or "").strip()
    en = str(en_text or "").strip()
    if vn and en and vn.lower() != en.lower():
        return f"{vn}\n{en}"
    return vn or en


def _clean_line_punctuation(line: str):
    """
    Checks and cleans punctuation, spacing, and capitalization on a single text line.
    Returns (cleaned_line, list_of_reasons).
    """
    if not line:
        return line, []
    reasons = []
    curr = line

    # 1. Multiple consecutive spaces
    if re.search(r"  +", curr):
        curr = re.sub(r"  +", " ", curr)
        reasons.append("Thừa nhiều khoảng trắng liên tiếp ('  ')")

    # 2. Space before punctuation (, . ; : ! ? ))
    if re.search(r"\s+([,.;:!?\)])", curr):
        curr = re.sub(r"\s+([,.;:!?\)])", r"\1", curr)
        reasons.append("Thừa khoảng trắng trước dấu câu (' ,' hoặc ' .')")

    # 3. Missing space after comma or semicolon (excluding numbers like 1,000)
    if re.search(r"([,;])([^\s\d])", curr):
        curr = re.sub(r"([,;])([^\s\d])", r"\1 \2", curr)
        reasons.append("Thiếu khoảng trắng sau dấu phẩy/chấm phẩy")

    # 4. Asymmetric space around slash in words like 'đóng/ mở'
    if re.search(r"(\w)\s+/\s*(\w)|(\w)\s*/\s+(\w)", curr):
        curr = re.sub(r"(\w)\s*/\s*(\w)", r"\1/\2", curr)
        reasons.append("Khoảng trắng không đồng nhất quanh dấu gạch chéo '/'")

    # 5. Repeated punctuation (.. ,,) excluding ellipsis (...)
    if re.search(r"(?<!\.)\.\.(?!\.)|,,+", curr):
        curr = re.sub(r"(?<!\.)\.\.(?!\.)", ".", curr)
        curr = re.sub(r",,+", ",", curr)
        reasons.append("Dấu chấm/dấu phẩy bị lặp kép")

    # 6. Capitalize first letter of sentence
    stripped = curr.strip()
    if stripped and stripped[0].isalpha() and stripped[0].islower():
        curr = stripped[0].upper() + stripped[1:]
        reasons.append(f"Chữ cái đầu dòng chưa viết hoa ('{stripped[:15]}...')")

    return curr.strip(), reasons


def inspect_and_fix_field(en_text: str, vn_text: str, field_name: str, finding_no: int, audit_id: str, photos_count: int = 0):
    """
    Inspects a bilingual field (Location / Finding Issue / Improvement Plan)
    and returns a list of detected QA issues with exact suggested fixes.
    """
    issues = []
    new_en = (en_text or "").strip()
    new_vn = (vn_text or "").strip()

    # A. Check Vietnamese spelling & terminology
    vn_spell_reasons = []
    for rule in VN_SPELLING_RULES:
        if re.search(rule["pattern"], new_vn):
            new_vn = re.sub(rule["pattern"], rule["replacement"], new_vn)
            vn_spell_reasons.append(rule["reason"])

    if vn_spell_reasons:
        issues.append({
            "id": f"F{finding_no}_{field_name}_SPELL",
            "finding_no": finding_no,
            "audit_id": audit_id,
            "field": field_name,
            "category": "SPELLING",
            "category_label": "Lỗi Chính tả Tiếng Việt",
            "severity": "high",
            "original_en": en_text,
            "original_vn": vn_text,
            "suggested_en": new_en,
            "suggested_vn": new_vn,
            "reasons": vn_spell_reasons,
        })

    # B. Check Punctuation & Capitalization on both EN and VN
    cleaned_vn, vn_punct_reasons = _clean_line_punctuation(new_vn)
    cleaned_en, en_punct_reasons = _clean_line_punctuation(new_en)
    all_punct_reasons = vn_punct_reasons + [f"[Phụ đề EN] {r}" for r in en_punct_reasons]

    # Check unbalanced parentheses
    if cleaned_vn.count("(") != cleaned_vn.count(")"):
        all_punct_reasons.append("Dấu ngoặc đơn '(' và ')' trong câu tiếng Việt chưa đóng/mở khớp nhau")

    if all_punct_reasons:
        issues.append({
            "id": f"F{finding_no}_{field_name}_PUNCT",
            "finding_no": finding_no,
            "audit_id": audit_id,
            "field": field_name,
            "category": "PUNCTUATION",
            "category_label": "Lỗi Dấu câu & Trình bày",
            "severity": "medium",
            "original_en": en_text,
            "original_vn": vn_text,
            "suggested_en": cleaned_en,
            "suggested_vn": cleaned_vn,
            "reasons": all_punct_reasons,
        })
        new_vn = cleaned_vn
        new_en = cleaned_en

    # C. Check Bilingual Subtitle / Translation Consistency
    sub_reasons = []
    sub_en = new_en
    for rule in EN_SUBTITLE_RULES:
        if re.search(rule["pattern"], sub_en, flags=re.IGNORECASE):
            if not rule["vn_trigger"] or rule["vn_trigger"] in (vn_text or "").lower():
                sub_en = re.sub(rule["pattern"], rule["replacement"], sub_en, flags=re.IGNORECASE)
                sub_reasons.append(rule["reason"])

    # Also check if bilingual line is missing one language -> fill it from vetted translations only
    if (en_text or vn_text) and (not en_text or not vn_text or en_text.strip() == vn_text.strip()):
        base_txt = new_vn or new_en
        if is_vietnamese_text(base_txt):
            translated_en = auto_translate_vn_to_en(base_txt)
            if translated_en:
                sub_en = translated_en
            sub_reasons.append("Thiếu phụ đề tiếng Anh" + (" ➔ Bổ sung từ bản dịch đã kiểm duyệt" if translated_en else ""))
        else:
            translated_vn = auto_translate_en_to_vn(base_txt)
            if translated_vn:
                new_vn = translated_vn
            sub_reasons.append("Chưa có bản tiếng Việt" + (" ➔ Bổ sung từ bản dịch đã kiểm duyệt" if translated_vn
                                                           else ": báo cáo đang giữ nguyên câu gốc, vui lòng nhập bản dịch"))

    # Check numeric mismatch between EN and VN (if not already caught by specific rules)
    if not sub_reasons and new_en and new_vn:
        nums_en = set(re.findall(r"\b\d+\b", new_en))
        nums_vn = set(re.findall(r"\b\d+\b", new_vn))
        # Ignore common date month conversions like 'April 25' -> {'25'} vs '25/4' -> {'25','4'}
        diff_nums = (nums_en - nums_vn)
        if diff_nums and nums_vn:
            sub_reasons.append(
                f"Số liệu trong phụ đề tiếng Anh ({', '.join(sorted(nums_en))}) lệch với bản tiếng Việt ({', '.join(sorted(nums_vn))})"
            )

    if sub_reasons:
        issues.append({
            "id": f"F{finding_no}_{field_name}_SUB",
            "finding_no": finding_no,
            "audit_id": audit_id,
            "field": field_name,
            "category": "SUBTITLE_BILINGUAL",
            "category_label": "Lỗi Phụ đề & Song ngữ",
            "severity": "high",
            "original_en": en_text,
            "original_vn": vn_text,
            "suggested_en": sub_en,
            "suggested_vn": new_vn,
            "reasons": sub_reasons,
        })
        new_en = sub_en

    return issues, new_en, new_vn


def run_qa_checks(parsed_data):
    """
    Runs full Spelling, Punctuation, and Bilingual Subtitle verification across
    all Findings and Word Report photo captions.
    Returns a structured QA report dictionary.
    """
    findings = parsed_data.get("findings", [])
    all_issues = []

    field_titles = {
        "location": "Vị trí / Khu vực (Col F)",
        "issue": "Nội dung Lỗi & Phụ đề Ảnh (Col G)",
        "improvement": "Kế hoạch Cải thiện (Col M)",
    }

    for f in findings:
        fno = f.get("no", 0)
        aid = f.get("audit_id", "")
        photos_cnt = len(f.get("photos", []))

        for fkey in ("location", "issue", "improvement"):
            en_val = f.get(f"{fkey}_en", "")
            vn_val = f.get(f"{fkey}_vn", "")
            found_issues, final_en, final_vn = inspect_and_fix_field(
                en_val, vn_val, fkey, fno, aid, photos_cnt
            )
            for iss in found_issues:
                iss["field_label"] = field_titles[fkey]
                iss["final_en"] = final_en
                iss["final_vn"] = final_vn
                iss["photos_count"] = photos_cnt
                all_issues.append(iss)

        # Check if a facility finding has 0 photos attached
        if str(f.get("cause", "")).strip().lower() == "facility" and photos_cnt == 0:
            all_issues.append({
                "id": f"F{fno}_PHOTO_MISSING",
                "finding_no": fno,
                "audit_id": aid,
                "field": "photo",
                "field_label": "Ảnh hiện trường (Col J/K/L)",
                "category": "SUBTITLE_BILINGUAL",
                "category_label": "Cảnh báo Ảnh & Phụ đề",
                "severity": "low",
                "original_en": f.get("issue_en", ""),
                "original_vn": f.get("issue_vn", ""),
                "suggested_en": f.get("issue_en", ""),
                "suggested_vn": f.get("issue_vn", ""),
                "final_en": f.get("issue_en", ""),
                "final_vn": f.get("issue_vn", ""),
                "photos_count": 0,
                "reasons": ["Lỗi hiện trường (facility) nhưng chưa có ảnh chụp đính kèm trong cột Problem Photo"],
                "auto_fixable": False,
            })

    for iss in all_issues:
        if "auto_fixable" not in iss:
            iss["auto_fixable"] = (
                iss["original_en"] != iss["final_en"] or iss["original_vn"] != iss["final_vn"]
            )

    counts_by_cat = {
        "SPELLING": sum(1 for i in all_issues if i["category"] == "SPELLING"),
        "PUNCTUATION": sum(1 for i in all_issues if i["category"] == "PUNCTUATION"),
        "SUBTITLE_BILINGUAL": sum(1 for i in all_issues if i["category"] == "SUBTITLE_BILINGUAL"),
    }
    fixable_count = sum(1 for i in all_issues if i.get("auto_fixable"))

    return {
        "total_issues": len(all_issues),
        "fixable_count": fixable_count,
        "counts_by_category": counts_by_cat,
        "issues": all_issues,
        "checked_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def apply_qa_fixes_to_data(parsed_data, target_issue_ids=None):
    """
    Applies auto-fixes for either specific issue IDs or all fixable issues,
    updating findings, checklist evidence_text, doc_violations, facility_violations,
    and key_issues subtitles in-place.
    """
    qa_report = run_qa_checks(parsed_data)
    issues_to_apply = [
        iss for iss in qa_report["issues"]
        if iss.get("auto_fixable") and (target_issue_ids is None or iss["id"] in target_issue_ids)
    ]

    finding_map = {f["no"]: f for f in parsed_data.get("findings", [])}
    old_vn_to_new_vn = {}

    applied_count = 0
    for iss in issues_to_apply:
        f_obj = finding_map.get(iss["finding_no"])
        if not f_obj:
            continue
        fkey = iss["field"]
        if fkey in ("location", "issue", "improvement"):
            old_vn = f_obj.get(f"{fkey}_vn", "")
            new_en = iss["final_en"]
            new_vn = iss["final_vn"]
            f_obj[f"{fkey}_en"] = new_en
            f_obj[f"{fkey}_vn"] = new_vn
            f_obj[f"{fkey}_full"] = format_bilingual_vn_first(new_vn, new_en)
            if fkey == "issue" and old_vn:
                old_vn_to_new_vn[old_vn] = new_vn
            applied_count += 1

    _sync_report_texts(parsed_data, old_vn_to_new_vn)
    return applied_count, parsed_data["qa_report"]


def set_finding_vietnamese(parsed_data, finding_no, new_vn):
    """
    Stores the auditor's Vietnamese wording for a finding and updates every report text using it.
    Returns the finding's English sentence, or None when there is no such finding.
    """
    f_obj = next((f for f in parsed_data.get("findings", []) if f.get("no") == finding_no), None)
    if f_obj is None:
        return None
    old_vn, en = f_obj.get("issue_vn", ""), f_obj.get("issue_en", "")
    if en == old_vn and is_vietnamese_text(en):
        en = new_vn     # Vietnamese-only source: there is no English sentence to keep
        f_obj["issue_en"] = en
    f_obj["issue_vn"] = new_vn
    f_obj["issue_full"] = format_bilingual_vn_first(new_vn, en)
    _sync_report_texts(parsed_data, {old_vn: new_vn} if old_vn else {})
    return en


def _sync_report_texts(parsed_data, old_vn_to_new_vn):
    """Rebuilds checklist evidence, Word summary lists and key issues from the findings."""
    finding_map = {f["no"]: f for f in parsed_data.get("findings", [])}

    # Rebuild evidence_text on all 41 checklist items from updated findings
    findings_by_code = {}
    for f in parsed_data.get("findings", []):
        findings_by_code.setdefault(f["audit_id"], []).append(f)

    for it in parsed_data.get("checklist", []):
        code = it["audit_id"]
        f_list = findings_by_code.get(code, [])
        it["findings"] = f_list
        if not f_list:
            it["evidence_text"] = "1:\n2:\n3:"
        elif len(f_list) == 1:
            it["evidence_text"] = f_list[0]["issue_full"]
        else:
            it["evidence_text"] = "\n".join(
                f"{idx}. {f_obj['issue_full']}" for idx, f_obj in enumerate(f_list, 1)
            )

    def synced(txt):
        # Summary lines may hold a shortened copy ending in "..."
        for old, new in old_vn_to_new_vn.items():
            flat = re.sub(r"\s+", " ", old)
            if txt == old or txt == flat or (txt.endswith("...") and flat.startswith(txt[:-3])):
                return new
        return txt

    # Sync Word summary lists (doc_violations, facility_violations, key_issues)
    parsed_data["doc_violations"] = [synced(txt) for txt in parsed_data.get("doc_violations", [])]
    parsed_data["facility_violations"] = [synced(txt) for txt in parsed_data.get("facility_violations", [])]
    for ki in parsed_data.get("key_issues", []):
        f_match = finding_map.get(ki.get("no"))
        if f_match:
            ki["issue_vn"] = f_match["issue_vn"]

    parsed_data["qa_report"] = run_qa_checks(parsed_data)


# ==============================================================================
# 4. STRUCTURED FILE STORAGE & REPOSITORY MANAGEMENT
# ==============================================================================

def _safe_slug(text: str) -> str:
    cleaned = re.sub(r"[^\w\-. ]+", "_", str(text or "").strip())
    return re.sub(r"\s+", "_", cleaned) or "UNKNOWN"


def init_file_repository(default_findings_path, default_checklist_template, default_docx_template):
    ensure_directories()
    # Copy master templates into 01_Master_Templates if not already there
    tpl_dir = os.path.join(STORAGE_DIR, STORAGE_FOLDERS["templates"])
    for src_path in (default_findings_path, default_checklist_template, default_docx_template):
        if src_path and os.path.exists(src_path):
            dst_path = os.path.join(tpl_dir, os.path.basename(src_path))
            if not os.path.exists(dst_path):
                shutil.copy2(src_path, dst_path)

    if not os.path.exists(REPOSITORY_FILE):
        repo = {
            "updated_at": datetime.datetime.now().isoformat(),
            "records": [],
        }
        with open(REPOSITORY_FILE, "w", encoding="utf-8") as f:
            json.dump(repo, f, ensure_ascii=False, indent=2)
    return load_file_repository()


def load_file_repository():
    ensure_directories()
    if not os.path.exists(REPOSITORY_FILE):
        return {"updated_at": datetime.datetime.now().isoformat(), "records": []}
    with open(REPOSITORY_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_file_repository(repo):
    repo["updated_at"] = datetime.datetime.now().isoformat()
    with open(REPOSITORY_FILE, "w", encoding="utf-8") as f:
        json.dump(repo, f, ensure_ascii=False, indent=2)


def archive_audit_session(parsed_data, source_xlsm_path, generated_xlsx_path, generated_docx_path, actor="ngocngon",
                          note="", owner_username=None, title="", round_no=1, parent_record=None,
                          overwrite_record_id=None, bundle_payload=None, summary_override=None, source_parts=None):
    """
    Organizes and stores all files of an audit session into the structured storage tree:
    - storage/02_Uploaded_Findings/<YYYY-MM>/<VENDOR>/
    - storage/03_Generated_Checklists/<YYYY-MM>/<VENDOR>/
    - storage/04_Generated_Word_Reports/<YYYY-MM>/<VENDOR>/
    - storage/05_Archived_Bundles/<YYYY-MM>/<VENDOR>/

    round_no=2 + parent_record: the round-2 files are stored side by side with the round-1
    files (same <YYYY-MM>/<VENDOR> folders, suffix '_Lan2').
    overwrite_record_id: updates an existing record in place (same record id, new revision).
    """
    ensure_directories()
    now = datetime.datetime.now()
    # Random part: two users saving the same vendor in the same second must not share files
    timestamp_tag = f'{now.strftime("%Y%m%d_%H%M%S")}_{secrets.token_hex(3)}'
    repo = load_file_repository()
    existing = None
    if overwrite_record_id:
        existing = next((r for r in repo.get("records", []) if r["record_id"] == overwrite_record_id), None)

    meta = parsed_data.get("metadata", {})
    summary = summary_override or parsed_data.get("summary", {})
    vendor_short = _safe_slug(meta.get("vendor_short", "VENDOR"))
    vendor_code = _safe_slug(meta.get("vendor_code", "CODE"))

    if existing:
        ym_folder = existing.get("year_month") or now.strftime("%Y-%m")
        record_id = existing["record_id"]
        vendor_folder = existing.get("vendor_folder") or _safe_slug(existing.get("vendor_short", vendor_short))
    elif parent_record:
        ym_folder = parent_record.get("year_month") or now.strftime("%Y-%m")
        vendor_folder = parent_record.get("vendor_folder") or _safe_slug(parent_record.get("vendor_short", vendor_short))
        record_id = f"AUD_{timestamp_tag}_{vendor_short}_L{round_no}"
    else:
        ym_folder = now.strftime("%Y-%m")
        vendor_folder = vendor_short
        record_id = f"AUD_{timestamp_tag}_{vendor_short}"

    f_dir = os.path.join(STORAGE_DIR, STORAGE_FOLDERS["findings"], ym_folder, vendor_folder)
    c_dir = os.path.join(STORAGE_DIR, STORAGE_FOLDERS["checklists"], ym_folder, vendor_folder)
    r_dir = os.path.join(STORAGE_DIR, STORAGE_FOLDERS["reports"], ym_folder, vendor_folder)
    b_dir = os.path.join(STORAGE_DIR, STORAGE_FOLDERS["bundles"], ym_folder, vendor_folder)
    for d in (f_dir, c_dir, r_dir, b_dir):
        os.makedirs(d, exist_ok=True)

    suffix = f"_Lan{round_no or 1}"
    ext_src = os.path.splitext(source_xlsm_path or "")[1] or ".xlsm"
    if existing and existing.get("files"):
        def _old(key, default_dir, default_name):
            fm = existing["files"].get(key)
            return os.path.join(STORAGE_DIR, fm["rel_path"]) if fm and fm.get("rel_path") else os.path.join(default_dir, default_name)
        dst_finding = _old("finding", f_dir, f"{timestamp_tag}_{vendor_short}_EHS_Audit_Findings{suffix}{ext_src}")
        dst_checklist = _old("checklist", c_dir, f"{timestamp_tag}_{vendor_short}_RBA_8.0.1_Checklist{suffix}.xlsx")
        dst_report = _old("report", r_dir, f"{timestamp_tag}_{vendor_short}_Bao_Cao_Tom_Tat_RBA_8.0.1{suffix}.docx")
        dst_bundle = _old("bundle", b_dir, f"{timestamp_tag}_{vendor_short}_Session_State{suffix}.json")
    else:
        dst_finding = os.path.join(f_dir, f"{timestamp_tag}_{vendor_short}_EHS_Audit_Findings{suffix}{ext_src}")
        dst_checklist = os.path.join(c_dir, f"{timestamp_tag}_{vendor_short}_RBA_8.0.1_Checklist{suffix}.xlsx")
        dst_report = os.path.join(r_dir, f"{timestamp_tag}_{vendor_short}_Bao_Cao_Tom_Tat_RBA_8.0.1{suffix}.docx")
        dst_bundle = os.path.join(b_dir, f"{timestamp_tag}_{vendor_short}_Session_State{suffix}.json")

    revision_entry = None
    if existing:
        revision_entry = snapshot_record_revision(existing)

    if source_xlsm_path and os.path.exists(source_xlsm_path) and os.path.abspath(source_xlsm_path) != os.path.abspath(dst_finding):
        shutil.copy2(source_xlsm_path, dst_finding)
    # Two-slot upload: keep File hiện trường / File tài liệu so a missing one can be added later
    part_dst = {}
    for slot, tag in (("field", "HIEN_TRUONG"), ("doc", "TAI_LIEU")):
        src_p = (source_parts or {}).get(slot)
        if not src_p or not os.path.exists(src_p):
            continue
        old_fm = ((existing or {}).get("files") or {}).get(f"finding_{slot}")
        base_name = re.sub(r"^upload_\d+_[0-9a-f]+_(?:field|doc)_", "", os.path.basename(src_p))
        base_name = re.sub(r"^.*?_(?:HIEN_TRUONG|TAI_LIEU)_", "", base_name)
        if old_fm and old_fm.get("rel_path") and os.path.abspath(os.path.join(STORAGE_DIR, old_fm["rel_path"])) == os.path.abspath(src_p):
            dst_p = src_p
        else:
            dst_p = os.path.join(f_dir, f"{timestamp_tag}_{vendor_short}_{tag}_{_safe_slug(base_name)}")
            shutil.copy2(src_p, dst_p)
            if old_fm and old_fm.get("rel_path"):
                old_abs = os.path.join(STORAGE_DIR, old_fm["rel_path"])
                if os.path.exists(old_abs) and os.path.abspath(old_abs) != os.path.abspath(dst_p):
                    try:
                        os.remove(old_abs)
                    except OSError:
                        pass
        part_dst[slot] = dst_p
    if generated_xlsx_path and os.path.exists(generated_xlsx_path):
        shutil.copy2(generated_xlsx_path, dst_checklist)
    if generated_docx_path and os.path.exists(generated_docx_path):
        shutil.copy2(generated_docx_path, dst_report)

    payload = {
        "record_id": record_id,
        "round": round_no,
        "parent_record_id": parent_record.get("record_id") if parent_record else (existing or {}).get("parent_record_id"),
        "saved_at": now.isoformat(),
        "saved_by": actor,
        "source_xlsm_path": dst_finding,
        "source_parts": {k: os.path.relpath(v, STORAGE_DIR) for k, v in part_dst.items()},
    }
    if bundle_payload is not None:
        payload.update(bundle_payload)
    else:
        payload["data"] = parsed_data
    tmp_bundle = dst_bundle + ".tmp"
    with open(tmp_bundle, "w", encoding="utf-8") as bf:
        json.dump(payload, bf, ensure_ascii=False)
    os.replace(tmp_bundle, dst_bundle)

    def _file_meta(p, cat_key):
        if not os.path.exists(p):
            return None
        sz = os.path.getsize(p)
        return {
            "filename": os.path.basename(p),
            "rel_path": os.path.relpath(p, STORAGE_DIR),
            "category": STORAGE_FOLDERS[cat_key],
            "size_bytes": sz,
            "size_kb": round(sz / 1024, 1),
        }

    qa_rep = parsed_data.get("qa_report") or {}
    fields = {
        "year_month": ym_folder,
        "vendor_folder": vendor_folder,
        "vendor_short": meta.get("vendor_short", "VENDOR"),
        "vendor_full": meta.get("vendor_full", ""),
        "vendor_code": meta.get("vendor_code", vendor_code),
        "audit_date": meta.get("audit_date_raw", ""),
        "auditor": meta.get("auditor_raw", ""),
        "standard_version": "RBA 8.0.1",
        "round": round_no,
        "total_score": summary.get("total_score", 0),
        "grade_level": summary.get("grade_level", "D"),
        "total_findings": summary.get("total_findings", 0),
        "violated_items_count": summary.get("violated_items_count", 0),
        "counts": summary.get("counts", {}),
        "qa_issues_count": qa_rep.get("total_issues", 0),
        "files": {
            "finding": _file_meta(dst_finding, "findings"),
            "checklist": _file_meta(dst_checklist, "checklists"),
            "report": _file_meta(dst_report, "reports"),
            "bundle": _file_meta(dst_bundle, "bundles"),
        },
        "sources": {"field": "field" in part_dst, "doc": "doc" in part_dst} if part_dst else None,
    }
    for slot, p in part_dst.items():
        fields["files"][f"finding_{slot}"] = _file_meta(p, "findings")

    if round_no == 1:
        fields["finding_index"] = build_finding_index(parsed_data)
    if existing:
        if revision_entry:
            existing.setdefault("revisions", []).insert(0, revision_entry)
        existing.update(fields)
        existing.pop("files_pdf_stale", None)
        if existing.get("files", {}).get("pdf") is None:
            existing["files"].pop("pdf", None)
        existing["revision"] = int(existing.get("revision", 1)) + 1
        existing["updated_at"] = now.strftime("%Y-%m-%d %H:%M:%S")
        existing["updated_by"] = actor
        if title:
            existing["title"] = title[:200]
        if note:
            existing["note"] = note[:500]
        record = existing
        save_file_repository(repo)
        add_audit_log(actor, f"Cập nhật nội dung báo cáo '{record_id}' (phiên bản {record['revision']})")
        return record

    record = {
        "record_id": record_id,
        "title": (title or "")[:200],
        "parent_record_id": parent_record.get("record_id") if parent_record else None,
        "created_at": now.strftime("%Y-%m-%d %H:%M:%S"),
        "created_by": actor,
        "owner_username": owner_username or "ngocngon",
        "revision": 1,
        "note": note or ("Kết quả đánh giá lại lần 2" if round_no > 1 else "Lưu trữ từ hệ thống RBA 8.0.1"),
    }
    record.update(fields)
    repo.setdefault("records", []).insert(0, record)
    save_file_repository(repo)
    add_audit_log(actor, f"Lưu báo cáo {'lần ' + str(round_no) + ' ' if round_no > 1 else ''}'{record_id}' ({record['vendor_short']} - {record['total_score']} điểm)")
    return record


def get_storage_overview():
    """
    Returns full directory tree statistics and categorized records for the File Storage UI.
    """
    ensure_directories()
    repo = load_file_repository()
    folder_stats = []
    total_bytes = 0
    total_files = 0

    folder_descriptions = {
        "01_Master_Templates": "Chứa bộ file mẫu gốc chuẩn RBA 8.0.1 (Checklist Excel, Mẫu Word & File Finding mẫu)",
        "02_Uploaded_Findings": "Lưu trữ các file EHS Audit Findings (.xlsm/.xlsx) đầu vào theo Tháng & Nhà máy",
        "03_Generated_Checklists": "Lưu trữ các file RBA 8.0.1 Audit Checklist (.xlsx) đã chấm điểm tự động",
        "04_Generated_Word_Reports": "Lưu trữ các file Báo cáo Tóm tắt Kết quả Đánh giá RBA 8.0.1 (.docx)",
        "05_Archived_Bundles": "Lưu trữ gói dữ liệu phiên làm việc (.json) để nạp lại bất kỳ lúc nào",
        "06_Revisions": "Các phiên bản cũ của báo cáo (trước mỗi lần cập nhật)",
    }

    for key, folder_name in STORAGE_FOLDERS.items():
        f_path = os.path.join(STORAGE_DIR, folder_name)
        f_count = 0
        f_bytes = 0
        files_list = []
        for root, _, files in os.walk(f_path):
            for fn in sorted(files, reverse=True):
                if fn.startswith("."):
                    continue
                abs_p = os.path.join(root, fn)
                sz = os.path.getsize(abs_p)
                mtime = datetime.datetime.fromtimestamp(os.path.getmtime(abs_p)).strftime("%Y-%m-%d %H:%M:%S")
                f_count += 1
                f_bytes += sz
                files_list.append({
                    "filename": fn,
                    "rel_path": os.path.relpath(abs_p, STORAGE_DIR),
                    "subfolder": os.path.relpath(root, f_path) if root != f_path else "",
                    "size_kb": round(sz / 1024, 1),
                    "modified_at": mtime,
                })
        total_files += f_count
        total_bytes += f_bytes
        folder_stats.append({
            "key": key,
            "folder_name": folder_name,
            "description": folder_descriptions.get(folder_name, ""),
            "file_count": f_count,
            "size_kb": round(f_bytes / 1024, 1),
            "size_mb": round(f_bytes / (1024 * 1024), 2),
            "files": files_list[:50],
        })

    return {
        "storage_root": STORAGE_DIR,
        "total_files": total_files,
        "total_size_mb": round(total_bytes / (1024 * 1024), 2),
        "folders": folder_stats,
        "records": repo.get("records", []),
    }


# ==============================================================================
# REVISION HISTORY (A) & FINDING INDEX (E)
# ==============================================================================

def _norm_text(txt):
    return re.sub(r"\s+", " ", str(txt or "").strip().lower())[:240]


def build_finding_index(parsed_data):
    """Compact list of findings kept in the repository for recurring-finding detection."""
    return [{"no": f.get("no"), "audit_id": f.get("audit_id"), "issue_vn": _norm_text(f.get("issue_vn") or f.get("issue_full"))}
            for f in (parsed_data or {}).get("findings", [])]


def snapshot_record_revision(rec):
    """Copies the current files of a record into storage/06_Revisions/<record_id>/v<rev>/ and returns the entry."""
    rev = int(rec.get("revision", 1))
    rev_dir = os.path.join(STORAGE_DIR, STORAGE_FOLDERS["revisions"], rec["record_id"], f"v{rev}")
    os.makedirs(rev_dir, exist_ok=True)
    files = {}
    for key, fm in (rec.get("files") or {}).items():
        if not fm or not fm.get("rel_path"):
            continue
        src = os.path.join(STORAGE_DIR, fm["rel_path"])
        if os.path.exists(src):
            dst = os.path.join(rev_dir, os.path.basename(src))
            shutil.copy2(src, dst)
            files[key] = {"filename": os.path.basename(dst), "rel_path": os.path.relpath(dst, STORAGE_DIR),
                          "size_kb": round(os.path.getsize(dst) / 1024, 1)}
    return {
        "revision": rev,
        "saved_at": rec.get("updated_at") or rec.get("created_at"),
        "saved_by": rec.get("updated_by") or rec.get("created_by"),
        "title": rec.get("title", ""), "note": rec.get("note", ""),
        "total_score": rec.get("total_score"), "grade_level": rec.get("grade_level"),
        "violated_items_count": rec.get("violated_items_count"), "total_findings": rec.get("total_findings"),
        "counts": rec.get("counts", {}), "finding_index": rec.get("finding_index"),
        "files": files,
    }


def restore_record_revision(record_id, revision, actor="system"):
    """Restores an older revision: the current version is snapshotted first, so nothing is lost."""
    repo = load_file_repository()
    rec = next((r for r in repo.get("records", []) if r["record_id"] == record_id), None)
    if not rec:
        raise FileNotFoundError("Không tìm thấy báo cáo")
    entry = next((e for e in rec.get("revisions", []) if int(e["revision"]) == int(revision)), None)
    if not entry:
        raise FileNotFoundError("Không tìm thấy phiên bản")
    current = snapshot_record_revision(rec)
    for key, fm in entry.get("files", {}).items():
        src = os.path.join(STORAGE_DIR, fm["rel_path"])
        cur = (rec.get("files") or {}).get(key)
        if os.path.exists(src) and cur and cur.get("rel_path"):
            shutil.copy2(src, os.path.join(STORAGE_DIR, cur["rel_path"]))
            cur["size_kb"] = round(os.path.getsize(src) / 1024, 1)
    if "pdf" in rec.get("files", {}) and "pdf" not in entry.get("files", {}):
        rec["files"].pop("pdf", None)
    for k in ("title", "note", "total_score", "grade_level", "violated_items_count", "total_findings", "counts", "finding_index"):
        if entry.get(k) is not None:
            rec[k] = entry[k]
    rec.setdefault("revisions", []).insert(0, current)
    rec["revision"] = int(rec.get("revision", 1)) + 1
    rec["updated_at"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rec["updated_by"] = actor
    rec["restored_from_revision"] = int(revision)
    save_file_repository(repo)
    add_audit_log(actor, f"Khôi phục báo cáo '{record_id}' về phiên bản {revision}")
    return rec


def delete_record_revisions(record_id):
    d = os.path.join(STORAGE_DIR, STORAGE_FOLDERS["revisions"], record_id)
    if os.path.isdir(d):
        shutil.rmtree(d, ignore_errors=True)
