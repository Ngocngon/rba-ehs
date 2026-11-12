"""
Multi-language EHS Translation & Bilingual Formatting Engine for RBA 8.0.1 Exports.
Supports 4 export language modes:
  - 'vi_ko': Song ngữ Việt – Hàn (Vietnamese + Korean)
  - 'vi_en': Song ngữ Việt – Anh (Vietnamese + English)
  - 'vi_zh': Song ngữ Việt – Trung (Vietnamese + Simplified Chinese)
  - 'vi'   : Mỗi tiếng Việt (Vietnamese only)

Works both in local Python server (urllib.request) and in browser Pyodide Web Worker
(via synchronous XMLHttpRequest bridge `js.rbaHttpPost`), with persistent caching in
`database/translation_memory_multi.json` (synced to IndexedDB on web) and an offline
RBA 8.0.1 EHS terminology fallback when network is unavailable.
© NGUYỄN NGỌC NGÔN — RBA 8.0.1 EHS Automation Suite
"""
import copy
import json
import os
import re
import urllib.parse
import urllib.request

from system_core import (
    DB_DIR,
    TRANSLATION_MEMORY_FILE,
    VN_TO_EN_EXACT,
    _clean_line_punctuation,
    _tm_key,
    is_vietnamese_text,
)

MULTI_TM_FILE = os.path.join(DB_DIR, "translation_memory_multi.json")

EXPORT_LANG_MODES = {
    "vi_ko": {"label_vi": "Song ngữ Việt – Hàn", "short_vi": "Việt – Hàn", "target": "ko", "gtx": "ko"},
    "vi_en": {"label_vi": "Song ngữ Việt – Anh", "short_vi": "Việt – Anh", "target": "en", "gtx": "en"},
    "vi_zh": {"label_vi": "Song ngữ Việt – Trung", "short_vi": "Việt – Trung", "target": "zh", "gtx": "zh-CN"},
    "vi":    {"label_vi": "Mỗi tiếng Việt", "short_vi": "Mỗi tiếng Việt", "target": None, "gtx": None},
}

_HANGUL_RE = re.compile(r"[\uac00-\ud7af\u1100-\u11ff\u3130-\u318f]")
_CJK_RE = re.compile(r"[\u4e00-\u9fff]")

# Exact location & common short EHS terms (instant 0ms lookup + offline support)
EXACT_GLOSSARY = {
    "nhà máy": {"en": "Factory", "ko": "공장 (현장)", "zh": "工厂（现场）"},
    "hồ sơ": {"en": "Document / Records", "ko": "문서 / 기록", "zh": "文件 / 记录"},
    "tài liệu": {"en": "Document", "ko": "문서", "zh": "文件"},
    "hiện trường": {"en": "On-site / Facility", "ko": "현장", "zh": "现场"},
    "xưởng sản xuất": {"en": "Production workshop", "ko": "생산 작업장", "zh": "生产车间"},
    "kho hóa chất": {"en": "Chemical warehouse", "ko": "화학물질 창고", "zh": "化学品仓库"},
    "kho hoá chất": {"en": "Chemical warehouse", "ko": "화학물질 창고", "zh": "化学品仓库"},
    "kho chất thải nguy hại": {"en": "Hazardous waste storage", "ko": "유해폐기물 보관소", "zh": "危险废物仓库"},
    "kho rác thải nguy hại": {"en": "Hazardous waste storage", "ko": "유해폐기물 보관소", "zh": "危险废物仓库"},
    "kho chất thải": {"en": "Waste storage area", "ko": "폐기물 보관소", "zh": "废物仓库"},
    "kho nguyên vật liệu": {"en": "Raw material warehouse", "ko": "원자재 창고", "zh": "原材料仓库"},
    "kho thành phẩm": {"en": "Finished goods warehouse", "ko": "완제품 창고", "zh": "成品仓库"},
    "nhà ăn": {"en": "Cafeteria / Canteen", "ko": "구내식당", "zh": "食堂"},
    "bếp ăn": {"en": "Kitchen / Canteen", "ko": "주방 / 식당", "zh": "厨房 / 食堂"},
    "ký túc xá": {"en": "Dormitory", "ko": "기숙사", "zh": "宿舍"},
    "phòng y tế": {"en": "Medical room", "ko": "의무실", "zh": "医务室"},
    "trạm xử lý nước thải": {"en": "Wastewater treatment plant", "ko": "폐수처리장", "zh": "污水处理站"},
    "khu xử lý nước thải": {"en": "Wastewater treatment area", "ko": "폐수처리 구역", "zh": "污水处理区"},
    "phòng máy nén khí": {"en": "Air compressor room", "ko": "공기압축기실", "zh": "空压机房"},
    "phòng điện": {"en": "Electrical room", "ko": "전기실", "zh": "配电室"},
    "tủ điện": {"en": "Electrical cabinet", "ko": "분전함 (전기 캐비닛)", "zh": "配电箱"},
    "phòng bơm pccc": {"en": "Fire pump room", "ko": "소방펌프실", "zh": "消防泵房"},
    "lối thoát hiểm": {"en": "Emergency exit", "ko": "비상구", "zh": "紧急出口"},
    "không có lỗi vi phạm": {"en": "No violations found", "ko": "위반 사항 없음", "zh": "无违规项"},
    "không có vấn đề tồn đọng": {"en": "No outstanding issues", "ko": "미결 문제 없음", "zh": "无遗留问题"},
    "không phát hiện điểm không phù hợp trong đợt đánh giá này.": {
        "en": "No non-conformances were identified during this audit.",
        "ko": "이번 심사에서 부적합 사항이 발견되지 않았습니다.",
        "zh": "本次审核未发现不符合项。",
    },
}

# Pre-translation Vietnamese EHS abbreviation normalizer (used only on the copy sent to translator
# so Vietnamese abbreviations/typos translate into accurate EHS terminology)
_VN_PRE_NORM = [
    (re.compile(r"\bđường\s+ghom\b", re.IGNORECASE), "đường gom"),
    (re.compile(r"\bATVSLĐ\b"), "an toàn vệ sinh lao động"),
    (re.compile(r"\bATVS\b"), "an toàn vệ sinh"),
    (re.compile(r"\bPCCC\b"), "phòng cháy chữa cháy"),
    (re.compile(r"\bCNCH\b"), "cứu nạn cứu hộ"),
    (re.compile(r"\bCTNH\b"), "chất thải nguy hại"),
    (re.compile(r"\bCTRSH\b"), "chất thải rắn sinh hoạt"),
    (re.compile(r"\bCTCN\b"), "chất thải công nghiệp"),
    (re.compile(r"\bXLNT\b"), "xử lý nước thải"),
    (re.compile(r"\bNLĐ\b"), "người lao động"),
    (re.compile(r"\bCBCNV\b"), "cán bộ công nhân viên"),
    (re.compile(r"\bCNV\b"), "công nhân viên"),
    (re.compile(r"\bBHLĐ\b"), "bảo hộ lao động"),
    (re.compile(r"\bPTBVCN\b"), "phương tiện bảo vệ cá nhân"),
    (re.compile(r"\bKĐKTAT\b"), "kiểm định kỹ thuật an toàn"),
    (re.compile(r"\bQTMT\b"), "quan trắc môi trường"),
    (re.compile(r"\bQTMTR\b"), "quan trắc môi trường"),
    (re.compile(r"\bĐGRR\b"), "đánh giá rủi ro"),
    (re.compile(r"\bKTSK\b"), "kiểm tra sức khỏe"),
    (re.compile(r"\bKSK\b"), "khám sức khỏe"),
    (re.compile(r"\bBNN\b"), "bệnh nghề nghiệp"),
    (re.compile(r"\bGPMT\b"), "giấy phép môi trường"),
    (re.compile(r"\bĐTM\b"), "đánh giá tác động môi trường"),
    (re.compile(r"\bHMBB\b"), "hạng mục bắt buộc"),
    # Disambiguate Vietnamese words that generic MT often mistranslates
    (re.compile(r"\bgiá\s+để\s+bình\s+chữa\s+cháy\b", re.IGNORECASE), "kệ giá đỡ bình chữa cháy"),
    (re.compile(r"\bbiển\s+trách\s+nhiệm\b", re.IGNORECASE), "bảng biển hiệu trách nhiệm"),
    (re.compile(r"\bbiển\s+cảnh\s+báo\b", re.IGNORECASE), "bảng biển hiệu cảnh báo"),
    (re.compile(r"\bbiển\s+báo\b", re.IGNORECASE), "bảng biển hiệu cảnh báo"),
    (re.compile(r"\bbiển\s+chỉ\s+dẫn\b", re.IGNORECASE), "bảng biển hiệu chỉ dẫn"),
]

# Post-translation EHS domain fixes per target language
_POST_FIXES = {
    "en": [
        (re.compile(r"\bsea of responsibility\b|\bsea of management\b", re.I), "management responsibility sign"),
        (re.compile(r"\bwarning sea\b", re.I), "warning sign"),
        (re.compile(r"\bfire extinguisher price(s)?\b", re.I), r"fire extinguisher rack\1"),
    ],
    "ko": [
        (re.compile(r"Circular\s+(\d+/\d+/TT-[A-ZĐ\-]+)", re.I), r"시행규칙(Thông tư) \1"),
        (re.compile(r"Decree\s+(\d+/\d+/NĐ-CP)", re.I), r"의정(Nghị định) \1"),
    ],
    "zh": [
        (re.compile(r"Circular\s+(\d+/\d+/TT-[A-ZĐ\-]+)", re.I), r"第 \1 号通知"),
        (re.compile(r"Decree\s+(\d+/\d+/NĐ-CP)", re.I), r"第 \1 号议定"),
    ],
}

# Offline clause & vocabulary fallback when no internet connection is available
_OFFLINE_PATTERNS = [
    (re.compile(r"^công ty chưa tiến hành\s+", re.I), {
        "en": "The company has not conducted ",
        "ko": "회사는 다음 사항을 실시하지 않음: ",
        "zh": "公司尚未开展：",
    }),
    (re.compile(r"^công ty chưa có\s+", re.I), {
        "en": "The company does not have ",
        "ko": "회사는 다음 사항을 구비하지 않음: ",
        "zh": "公司尚未具备：",
    }),
    (re.compile(r"^công ty không có\s+", re.I), {
        "en": "The company lacks ",
        "ko": "회사는 다음 사항이 없음: ",
        "zh": "公司缺少：",
    }),
    (re.compile(r"^công ty chưa\s+", re.I), {
        "en": "The company has not yet ",
        "ko": "회사는 아직 이행하지 않음: ",
        "zh": "公司尚未：",
    }),
    (re.compile(r"^chưa tiến hành\s+", re.I), {
        "en": "Has not conducted ",
        "ko": "미실시: ",
        "zh": "未进行：",
    }),
    (re.compile(r"^không tiến hành\s+", re.I), {
        "en": "Did not conduct ",
        "ko": "미이행: ",
        "zh": "未执行：",
    }),
    (re.compile(r"^chưa trang bị\s+", re.I), {
        "en": "Not equipped with ",
        "ko": "미비치: ",
        "zh": "未配备：",
    }),
    (re.compile(r"^chưa lắp đặt\s+", re.I), {
        "en": "Not installed: ",
        "ko": "미설치: ",
        "zh": "未安装：",
    }),
    (re.compile(r"^thiếu\s+", re.I), {
        "en": "Missing ",
        "ko": "누락/부족: ",
        "zh": "缺少：",
    }),
]

_OFFLINE_TERMS = [
    ("đánh giá phân loại điều kiện lao động", "working condition assessment and classification", "근로조건 평가 및 분류", "工作条件评估与分类"),
    ("quan trắc môi trường lao động", "workplace environment monitoring", "작업환경측정", "工作场所环境监测"),
    ("kiểm tra sức khỏe đặc biệt", "special occupational health examination", "특수건강진단", "特殊职业健康检查"),
    ("khám sức khỏe định kỳ", "periodic health checkup", "정기 건강검진", "定期健康体检"),
    ("bệnh nghề nghiệp", "occupational disease", "직업병", "职业病"),
    ("giấy phép môi trường", "environmental permit", "환경허가서", "环境许可证"),
    ("chất thải nguy hại", "hazardous waste", "유해폐기물", "危险废物"),
    ("chất thải", "waste", "폐기물", "废物"),
    ("nước thải", "wastewater", "폐수", "废水"),
    ("khí thải", "air emissions", "대기배출가스", "废气"),
    ("hóa chất", "chemicals", "화학물질", "化学品"),
    ("bảng dữ liệu an toàn hóa chất", "MSDS/SDS", "물질안전보건자료(MSDS)", "化学品安全技术说明书(MSDS)"),
    ("khay chống tràn", "spill containment tray", "유출방지 트레이(방유턱)", "防泄漏托盘"),
    ("bình chữa cháy", "fire extinguisher", "소화기", "灭火器"),
    ("hệ thống báo cháy", "fire alarm system", "화재경보 시스템", "火灾报警系统"),
    ("đèn chiếu sáng khẩn cấp", "emergency lighting", "비상조명등", "应急照明灯"),
    ("đèn chỉ dẫn thoát nạn", "exit sign light", "비상구 유도등", "安全出口指示灯"),
    ("lối thoát hiểm", "emergency exit", "비상구", "紧急出口"),
    ("diễn tập phòng cháy chữa cháy", "fire drill", "소방훈련", "消防演练"),
    ("diễn tập ứng phó khẩn cấp", "emergency response drill", "비상대응 훈련", "应急演练"),
    ("kiểm định kỹ thuật an toàn", "safety technical inspection", "안전기술검사", "安全技术检验"),
    ("máy nén khí", "air compressor", "공기압축기", "空压机"),
    ("bình chịu áp lực", "pressure vessel", "압력용기", "压力容器"),
    ("xe nâng", "forklift", "지게차", "叉车"),
    ("tủ điện", "electrical cabinet", "분전함", "配电箱"),
    ("phương tiện bảo vệ cá nhân", "personal protective equipment (PPE)", "개인보호구(PPE)", "个人防护用品(PPE)"),
    ("đánh giá rủi ro", "risk assessment", "위험성평가", "风险评估"),
    ("đánh giá nội bộ", "internal audit", "내부심사", "内部审核"),
    ("huấn luyện an toàn", "safety training", "안전교육", "安全培训"),
    ("quy trình", "procedure", "절차서", "程序文件"),
    ("người lao động", "workers", "근로자", "员工"),
]


def normalize_export_lang(lang):
    """Canonicalizes export language code to one of ('vi_ko', 'vi_en', 'vi_zh', 'vi')."""
    s = str(lang or "").strip().lower().replace("-", "_")
    if s in EXPORT_LANG_MODES:
        return s
    alias = {"ko": "vi_ko", "kr": "vi_ko", "en": "vi_en", "zh": "vi_zh", "cn": "vi_zh", "vn": "vi"}
    return alias.get(s, "vi_ko")


_MEM_CACHE = {"loaded": False, "data": {}}  # key -> {'vi': ..., 'en': ..., 'ko': ..., 'zh': ...}


def _load_mem():
    if _MEM_CACHE["loaded"]:
        return _MEM_CACHE["data"]
    store = {}
    # Seed from legacy EN <-> VN translation memory
    if os.path.exists(TRANSLATION_MEMORY_FILE):
        try:
            with open(TRANSLATION_MEMORY_FILE, "r", encoding="utf-8") as f:
                for it in json.load(f).get("items", []):
                    vn = str(it.get("vn") or "").strip()
                    en = str(it.get("en_fixed") or it.get("en") or "").strip()
                    if vn and en:
                        store.setdefault(_tm_key(vn), {})["vi"] = vn
                        store[_tm_key(vn)]["en"] = en
                        store.setdefault(_tm_key(en), {})["vi"] = vn
                        store[_tm_key(en)]["en"] = en
        except Exception:
            pass
    # Seed exact glossary
    for vn, mp in EXACT_GLOSSARY.items():
        k = _tm_key(vn)
        store.setdefault(k, {})["vi"] = vn[:1].upper() + vn[1:]
        store[k].update(mp)
        for lg, val in mp.items():
            lk = _tm_key(val)
            store.setdefault(lk, {})["vi"] = vn[:1].upper() + vn[1:]
            store[lk].update(mp)
    for vn, en in VN_TO_EN_EXACT.items():
        k = _tm_key(vn)
        store.setdefault(k, {}).setdefault("en", en)
    # Load multi-language persistent cache
    if os.path.exists(MULTI_TM_FILE):
        try:
            with open(MULTI_TM_FILE, "r", encoding="utf-8") as f:
                saved = json.load(f)
            if isinstance(saved, dict):
                for k, v in saved.items():
                    if isinstance(v, dict):
                        store.setdefault(k, {}).update(v)
        except Exception:
            pass
    _MEM_CACHE["loaded"] = True
    _MEM_CACHE["data"] = store
    return store


def _save_mem():
    if not _MEM_CACHE["loaded"]:
        return
    try:
        os.makedirs(DB_DIR, exist_ok=True)
        tmp = MULTI_TM_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(_MEM_CACHE["data"], f, ensure_ascii=False, indent=1)
        os.replace(tmp, MULTI_TM_FILE)
    except Exception:
        pass


def detect_text_lang(text):
    s = str(text or "").strip()
    if not s:
        return "vi"
    if _HANGUL_RE.search(s):
        return "ko"
    if _CJK_RE.search(s):
        return "zh"
    if is_vietnamese_text(s):
        return "vi"
    return "en"


def _pre_normalize_vn(text):
    out = str(text or "").strip()
    for rx, rep in _VN_PRE_NORM:
        out = rx.sub(rep, out)
    return out


def _post_fix(text, target_lang):
    out = re.sub(r"\s+", " ", str(text or "")).strip()
    for rx, rep in _POST_FIXES.get(target_lang, ()):
        out = rx.sub(rep, out)
    return out


def _offline_translate(text, target_lang):
    """Deterministic EHS glossary translation used only if network translation is unreachable."""
    s = str(text or "").strip()
    if not s or target_lang == "vi":
        return s
    k = _tm_key(s)
    if k in EXACT_GLOSSARY and target_lang in EXACT_GLOSSARY[k]:
        return EXACT_GLOSSARY[k][target_lang]
    idx = {"en": 1, "ko": 2, "zh": 3}.get(target_lang, 1)
    work = _pre_normalize_vn(s)
    prefix = ""
    for rx, mp in _OFFLINE_PATTERNS:
        m = rx.match(work)
        if m:
            prefix = mp[target_lang]
            work = work[m.end():]
            break
    for vn_term, en_t, ko_t, zh_t in _OFFLINE_TERMS:
        rep = (en_t, ko_t, zh_t)[idx - 1]
        work = re.sub(re.escape(vn_term), rep, work, flags=re.IGNORECASE)
    res = (prefix + work).strip()
    return res if res.lower() != s.lower() else ""


def _http_post_gtx(sl, tl_gtx, query_text):
    """Calls Google Translate GTX endpoint in either local Python or Pyodide Web Worker."""
    url = (
        "https://translate.googleapis.com/translate_a/single"
        f"?client=gtx&sl={urllib.parse.quote(sl)}&tl={urllib.parse.quote(tl_gtx)}&dt=t"
    )
    body_str = urllib.parse.urlencode({"q": query_text})
    raw = ""
    if os.environ.get("RBA_WEB") == "1":
        try:
            import js
            if hasattr(js, "rbaHttpPost"):
                raw = str(js.rbaHttpPost(url, body_str) or "")
        except Exception:
            raw = ""
    else:
        try:
            req = urllib.request.Request(
                url,
                data=body_str.encode("utf-8"),
                headers={
                    "User-Agent": "Mozilla/5.0",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                },
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
        except Exception:
            raw = ""
    if not raw:
        return None
    try:
        arr = json.loads(raw)
        if not arr or not isinstance(arr[0], list):
            return None
        return "".join(seg[0] for seg in arr[0] if seg and seg[0])
    except Exception:
        return None


def translate_batch(texts, target_lang, source_lang="vi"):
    """
    Translates a list of strings into `target_lang` ('ko', 'en', 'zh', 'vi'),
    using persistent cache first, batched GTX translation second, and offline EHS glossary fallback third.
    Returns dict {original_stripped_text: translated_text}.
    """
    if not texts or not target_lang:
        return {}
    mem = _load_mem()
    gtx_tl = {"ko": "ko", "en": "en", "zh": "zh-CN", "vi": "vi"}.get(target_lang, target_lang)

    unique = []
    seen = set()
    result = {}
    for raw in texts:
        for ln in str(raw or "").split("\n"):
            s = ln.strip()
            if not s or re.match(r"^\d+\s*[:.]?\s*$", s):
                continue
            if detect_text_lang(s) == target_lang:
                result[s] = s
                continue
            k = _tm_key(s)
            cached = mem.get(k, {}).get(target_lang)
            if cached:
                result[s] = cached
                continue
            if s not in seen:
                seen.add(s)
                unique.append(s)

    if unique:
        changed = False
        # Group into chunks of ~3500 chars so each HTTP POST stays fast and reliable
        chunks = []
        cur_chunk, cur_len = [], 0
        for s in unique:
            prep = _pre_normalize_vn(s) if source_lang == "vi" else s
            if cur_chunk and cur_len + len(prep) + 12 > 3500:
                chunks.append(cur_chunk)
                cur_chunk, cur_len = [], 0
            cur_chunk.append((s, prep))
            cur_len += len(prep) + 12
        if cur_chunk:
            chunks.append(cur_chunk)

        for chunk in chunks:
            payload = "\n".join(f"⟦{idx}⟧ {prep}" for idx, (_, prep) in enumerate(chunk))
            sl = "auto" if source_lang == "auto" else source_lang
            translated_blob = _http_post_gtx(sl, gtx_tl, payload)
            parsed_map = {}
            if translated_blob:
                # Match markers ⟦0⟧, [0], 【0】, etc. in case fullwidth brackets are used in CJK
                parts = re.split(r"(?:^|\n)\s*[⟦\[【]\s*(\d+)\s*[⟧\]】]\s*", translated_blob)
                for i in range(1, len(parts) - 1, 2):
                    try:
                        p_idx = int(parts[i])
                        parsed_map[p_idx] = parts[i + 1].strip()
                    except ValueError:
                        pass
            for idx, (orig, _) in enumerate(chunk):
                tr = parsed_map.get(idx, "")
                if tr:
                    tr = _post_fix(tr, target_lang)
                    k = _tm_key(orig)
                    mem.setdefault(k, {})[source_lang if source_lang != "auto" else detect_text_lang(orig)] = orig
                    mem[k][target_lang] = tr
                    result[orig] = tr
                    changed = True
                else:
                    fb = _offline_translate(orig, target_lang)
                    result[orig] = fb
        if changed:
            _save_mem()

    return result


def translate_multiline(text, target_lang, lookup_map=None):
    """Translates a (possibly multi-line) string line by line using lookup_map or translate_batch."""
    s = str(text or "").strip()
    if not s or not target_lang:
        return ""
    lines = [ln.strip() for ln in s.split("\n") if ln.strip()]
    if not lines:
        return ""
    if lookup_map is None:
        lookup_map = translate_batch(lines, target_lang)
    out = []
    for ln in lines:
        tr = lookup_map.get(ln)
        if tr is None:
            k = _tm_key(ln)
            tr = _load_mem().get(k, {}).get(target_lang, "")
        out.append(tr or "")
    return "\n".join(x for x in out if x)


def auto_draft_improvement_vn(issue_vn, audit_id=""):
    """
    Drafts a concise, professional Vietnamese corrective action plan when a finding
    (e.g. extracted from RBA Checklist Column L) does not yet include an Improvement Plan.
    """
    s = str(issue_vn or "").strip().rstrip(".")
    if not s:
        return ""
    # Clean leading numbering if any
    s_clean = re.sub(r"^\d+\s*[:.)]\s*", "", s).strip()
    rules = [
        (r"^(?:công ty|nhà máy)\s+chưa\s+tiến\s+hành\s+(.+)$", lambda m: f"Tiến hành {m.group(1)} đầy đủ theo quy định."),
        (r"^(?:công ty|nhà máy)\s+không\s+tiến\s+hành\s+(.+)$", lambda m: f"Thực hiện {m.group(1)} định kỳ đầy đủ theo quy định."),
        (r"^chưa\s+tiến\s+hành\s+(.+)$", lambda m: f"Tiến hành {m.group(1)} đầy đủ theo quy định."),
        (r"^không\s+tiến\s+hành\s+(.+)$", lambda m: f"Thực hiện {m.group(1)} đầy đủ theo quy định."),
        (r"^(?:công ty|nhà máy)\s+chưa\s+xuất\s+trình\s+được\s+(.+)$", lambda m: f"Hoàn thiện và cung cấp đầy đủ {m.group(1)} theo quy định pháp luật."),
        (r"^(?:công ty|nhà máy)\s+chưa\s+có\s+quy\s+trình\s+(.+)$", lambda m: f"Xây dựng, ban hành và áp dụng quy trình {m.group(1)}."),
        (r"^(?:công ty|nhà máy)\s+không\s+có\s+quy\s+trình\s+(.+)$", lambda m: f"Xây dựng, ban hành và thực hiện quy trình {m.group(1)}."),
        (r"^(?:công ty|nhà máy)\s+chưa\s+có\s+(.+)$", lambda m: f"Bổ sung và thiết lập đầy đủ {m.group(1)} theo quy định."),
        (r"^(?:công ty|nhà máy)\s+không\s+có\s+(.+)$", lambda m: f"Trang bị và bổ sung đầy đủ {m.group(1)} theo quy định."),
        (r"^(?:công ty|nhà máy)\s+chưa\s+(.+)$", lambda m: f"Thực hiện {m.group(1)} đầy đủ theo yêu cầu RBA 8.0.1."),
        (r"^chưa\s+trang\s+bị\s+(.+)$", lambda m: f"Trang bị bổ sung đầy đủ {m.group(1)}."),
        (r"^chưa\s+lắp\s+đặt\s+(.+)$", lambda m: f"Lắp đặt bổ sung đầy đủ {m.group(1)}."),
        (r"^chưa\s+có\s+(.+)$", lambda m: f"Bổ sung đầy đủ {m.group(1)} theo quy định."),
        (r"^không\s+có\s+(.+)$", lambda m: f"Bổ sung và duy trì đầy đủ {m.group(1)} theo quy định."),
        (r"^không\s+(.+)$", lambda m: f"Khắc phục và thực hiện đúng quy định: {m.group(1)}."),
        (r"^thiếu\s+(.+)$", lambda m: f"Bổ sung đầy đủ {m.group(1)}."),
    ]
    for pat, fn in rules:
        m = re.match(pat, s_clean, flags=re.IGNORECASE)
        if m:
            txt = fn(m)
            return txt[:1].upper() + txt[1:]
    return f"Khắc phục triệt để và duy trì tuân thủ đối với nội dung: {s_clean}."


def format_pair(vn_text, second_text, lang_mode="vi_ko", sep="\n"):
    """Formats Vietnamese + optional target language text cleanly without duplicating identical lines."""
    mode = normalize_export_lang(lang_mode)
    vn = str(vn_text or "").strip()
    if mode == "vi":
        return vn
    tr = str(second_text or "").strip()
    if vn and tr and _tm_key(vn) != _tm_key(tr):
        return f"{vn}{sep}{tr}"
    return vn or tr


def apply_export_lang_to_data(parsed_data, lang_mode="vi_ko"):
    """
    Returns a deep copy of `parsed_data` enriched with formatted fields for `lang_mode`
    ('vi_ko', 'vi_en', 'vi_zh', 'vi') across:
      - Checklist (.xlsx) Column L (`evidence_text`)
      - Findings (.xlsm/.xlsx) Columns F, G, M (`export_location_cell`, `export_issue_cell`, `export_improvement_cell`)
      - Word (.docx) & PDF/HTML (`doc_violations`, `facility_violations`, `export_t3_lines`, `key_issues`, `export_overall`)
    """
    from engine import _compact_violation_text, _extract_checklist_evidence_lines, cap_violations_pair, overall_assessment

    mode = normalize_export_lang(lang_mode)
    target = EXPORT_LANG_MODES[mode]["target"]
    data = copy.deepcopy(parsed_data)
    data["export_lang"] = mode

    # 1. Ensure every finding has Vietnamese text (if source was English-only, translate EN -> VI)
    en_only = []
    for f in data.get("findings", []):
        iss_vn = str(f.get("issue_vn") or "").strip()
        iss_en = str(f.get("issue_en") or "").strip()
        if iss_en and (not iss_vn or (iss_vn == iss_en and not is_vietnamese_text(iss_vn))):
            en_only.append(iss_en)
        loc_vn = str(f.get("location_vn") or "").strip()
        loc_en = str(f.get("location_en") or "").strip()
        if loc_en and (not loc_vn or (loc_vn == loc_en and not is_vietnamese_text(loc_vn))):
            en_only.append(loc_en)
    if en_only:
        en_to_vi = translate_batch(en_only, "vi", source_lang="en")
        for f in data.get("findings", []):
            iss_vn = str(f.get("issue_vn") or "").strip()
            iss_en = str(f.get("issue_en") or "").strip()
            if iss_en and (not iss_vn or (iss_vn == iss_en and not is_vietnamese_text(iss_vn))):
                f["issue_vn"] = translate_multiline(iss_en, "vi", en_to_vi) or iss_vn or iss_en
            loc_vn = str(f.get("location_vn") or "").strip()
            loc_en = str(f.get("location_en") or "").strip()
            if loc_en and (not loc_vn or (loc_vn == loc_en and not is_vietnamese_text(loc_vn))):
                f["location_vn"] = translate_multiline(loc_en, "vi", en_to_vi) or loc_vn or loc_en

    # Sync checklist item findings references by `no`
    by_no = {f.get("no"): f for f in data.get("findings", [])}
    for it in data.get("checklist", []):
        it["findings"] = [by_no.get(f.get("no"), f) for f in (it.get("findings") or [])]

    # Ensure every finding has an improvement_vn (drafted if missing)
    for f in data.get("findings", []):
        f["issue_vn"], _ = _clean_line_punctuation(str(f.get("issue_vn") or "").strip())
        f["location_vn"], _ = _clean_line_punctuation(str(f.get("location_vn") or "").strip() or (
            "Hồ sơ" if str(f.get("cause", "")).lower() == "administrative" else "Nhà máy"
        ))
        imp_vn = str(f.get("improvement_vn") or "").strip()
        if not imp_vn or (imp_vn == str(f.get("improvement_en") or "").strip() and not is_vietnamese_text(imp_vn)):
            imp_vn = auto_draft_improvement_vn(f.get("issue_vn", ""), f.get("audit_id", ""))
        f["improvement_vn"], _ = _clean_line_punctuation(imp_vn)

    overall_vn = overall_assessment(data)
    doc_v_vn, fac_v_vn = cap_violations_pair(
        data.get("doc_violations"), data.get("facility_violations"), max_per_type=3, max_total=5
    )

    # Collect Table 3 compact Vietnamese bullets & fallback checklist lines
    t3_vn_by_code = {}
    ev_fallback_by_code = {}
    for it in data.get("checklist", []):
        code = it["audit_id"]
        fs = it.get("findings") or []
        if fs:
            vn_list = [_compact_violation_text(f.get("issue_vn", ""), 140) for f in fs[:2]]
            if len(fs) > 2 and vn_list:
                vn_list[-1] = vn_list[-1].rstrip(".") + "..."
            t3_vn_by_code[code] = vn_list
        else:
            ev_lines = _extract_checklist_evidence_lines(it.get("evidence_text", ""))
            clean_ev = []
            for ln in ev_lines:
                # If evidence_text already had bilingual lines, keep Vietnamese line
                vn_only = [x.strip() for x in ln.split("\n") if is_vietnamese_text(x)]
                clean_ev.append(vn_only[0] if vn_only else ln)
            ev_fallback_by_code[code] = clean_ev
            if it.get("significance") in ("Priority", "Major", "Minor"):
                t3_vn_by_code[code] = (
                    [_compact_violation_text(clean_ev[0], 140)] if clean_ev else [it.get("sub_category") or code]
                )

    ki_vn_list = []
    for ki in data.get("key_issues") or []:
        f_match = by_no.get(ki.get("no"))
        ki_vn = (f_match.get("issue_vn") if f_match else ki.get("issue_vn")) or ""
        ki["issue_vn"] = ki_vn
        ki["issue_compact_vn"] = _compact_violation_text(ki_vn, 160)
        ki_vn_list.append(ki["issue_compact_vn"])

    # 2. Batch-translate everything in ONE pass if bilingual mode is active
    tr_map = {}
    if target:
        pool = [overall_vn] + doc_v_vn + fac_v_vn + ki_vn_list
        for f in data.get("findings", []):
            # If target == 'en' and finding already has a clean English translation, keep/seed it
            if target == "en":
                iss_en = str(f.get("issue_en") or "").strip()
                if iss_en and not is_vietnamese_text(iss_en) and iss_en.lower() != f["issue_vn"].lower():
                    tr_map[f["issue_vn"]] = iss_en
                else:
                    pool.append(f["issue_vn"])
                loc_en = str(f.get("location_en") or "").strip()
                if loc_en and not is_vietnamese_text(loc_en) and loc_en.lower() != f["location_vn"].lower():
                    tr_map[f["location_vn"]] = loc_en
                else:
                    pool.append(f["location_vn"])
                imp_en = str(f.get("improvement_en") or "").strip()
                if imp_en and not is_vietnamese_text(imp_en) and imp_en.lower() != f["improvement_vn"].lower():
                    tr_map[f["improvement_vn"]] = imp_en
                else:
                    pool.append(f["improvement_vn"])
            else:
                pool.extend([f["issue_vn"], f["location_vn"], f["improvement_vn"]])
        for lst in t3_vn_by_code.values():
            pool.extend(lst)
        for lst in ev_fallback_by_code.values():
            pool.extend(lst)
        if data.get("empty_t3_text"):
            pool.append(data["empty_t3_text"])
        if data.get("empty_key_issue_text"):
            pool.append(data["empty_key_issue_text"])
        fetched = translate_batch(pool, target, source_lang="vi")
        fetched.update(tr_map)
        tr_map = fetched

    # 3. Populate formatted fields on findings, checklist, and report summary
    for f in data.get("findings", []):
        loc_tr = translate_multiline(f["location_vn"], target, tr_map) if target else ""
        iss_tr = translate_multiline(f["issue_vn"], target, tr_map) if target else ""
        imp_tr = translate_multiline(f["improvement_vn"], target, tr_map) if target else ""
        f["export_location_cell"] = format_pair(f["location_vn"], loc_tr, mode, sep="\n")
        f["export_issue_cell"] = format_pair(f["issue_vn"], iss_tr, mode, sep="\n")
        f["export_improvement_cell"] = format_pair(f["improvement_vn"], imp_tr, mode, sep="\n")

    for it in data.get("checklist", []):
        code = it["audit_id"]
        fs = it.get("findings") or []
        if fs:
            if len(fs) == 1:
                it["evidence_text"] = fs[0]["export_issue_cell"]
            else:
                blocks = []
                for idx, f_obj in enumerate(fs, 1):
                    vn_ln = f_obj["issue_vn"]
                    if target:
                        tr_ln = translate_multiline(vn_ln, target, tr_map)
                        blocks.append(f"{idx}. {vn_ln}\n   {tr_ln}" if tr_ln and _tm_key(tr_ln) != _tm_key(vn_ln) else f"{idx}. {vn_ln}")
                    else:
                        blocks.append(f"{idx}. {vn_ln}")
                it["evidence_text"] = "\n".join(blocks)
        else:
            ev_lines = ev_fallback_by_code.get(code) or []
            if not ev_lines:
                it["evidence_text"] = "1:\n2:\n3:"
            elif len(ev_lines) == 1:
                tr_ln = translate_multiline(ev_lines[0], target, tr_map) if target else ""
                it["evidence_text"] = format_pair(ev_lines[0], tr_ln, mode, sep="\n")
            else:
                blocks = []
                for idx, vn_ln in enumerate(ev_lines, 1):
                    tr_ln = translate_multiline(vn_ln, target, tr_map) if target else ""
                    blocks.append(f"{idx}. {vn_ln}\n   {tr_ln}" if (target and tr_ln and _tm_key(tr_ln) != _tm_key(vn_ln)) else f"{idx}. {vn_ln}")
                it["evidence_text"] = "\n".join(blocks)

        if code in t3_vn_by_code:
            it["export_t3_lines"] = [
                format_pair(v_ln, translate_multiline(v_ln, target, tr_map) if target else "", mode, sep="\n")
                for v_ln in t3_vn_by_code[code]
            ]

    data["export_overall"] = format_pair(
        overall_vn, translate_multiline(overall_vn, target, tr_map) if target else "", mode, sep="\n"
    )
    data["doc_violations_export"] = [
        format_pair(v, translate_multiline(v, target, tr_map) if target else "", mode, sep="\n")
        for v in doc_v_vn
    ]
    data["facility_violations_export"] = [
        format_pair(v, translate_multiline(v, target, tr_map) if target else "", mode, sep="\n")
        for v in fac_v_vn
    ]
    for ki in data.get("key_issues") or []:
        v_c = ki.get("issue_compact_vn") or _compact_violation_text(ki.get("issue_vn", ""), 160)
        tr_c = translate_multiline(v_c, target, tr_map) if target else ""
        ki["export_issue_text"] = format_pair(v_c, tr_c, mode, sep="\n")

    if data.get("empty_t3_text") and target:
        data["empty_t3_text"] = format_pair(
            data["empty_t3_text"], translate_multiline(data["empty_t3_text"], target, tr_map), mode, sep=" / "
        )
    if data.get("empty_key_issue_text") and target:
        data["empty_key_issue_text"] = format_pair(
            data["empty_key_issue_text"], translate_multiline(data["empty_key_issue_text"], target, tr_map), mode, sep=" / "
        )

    return data
