import os
import re
import json
import copy
import base64
import zipfile
import datetime
import xml.etree.ElementTree as ET
from system_core import (
    MASTER_RULES_FILE,
    _tm_key,
    draft_improvement_plan,
    findings_cell_text,
    init_or_load_master_rules,
    reset_master_rules_to_factory,
    save_master_rules,
    run_qa_checks,
    init_file_repository,
    is_vietnamese_text,
    auto_translate_vn_to_en,
    auto_translate_en_to_vn,
    format_bilingual_vn_first,
)

# Register standard OpenXML namespaces so serialized XML remains clean
NAMESPACES = {
    '': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main',
    'r': 'http://schemas.openxmlformats.org/officeDocument/2006/relationships',
    'mc': 'http://schemas.openxmlformats.org/markup-compatibility/2006',
    'x14ac': 'http://schemas.microsoft.com/office/spreadsheetml/2009/9/ac',
    'xr': 'http://schemas.microsoft.com/office/spreadsheetml/2014/revision',
    'xr2': 'http://schemas.microsoft.com/office/spreadsheetml/2015/revision2',
    'xr3': 'http://schemas.microsoft.com/office/spreadsheetml/2016/revision3',
    'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main',
    'w14': 'http://schemas.microsoft.com/office/word/2010/wordml',
    'wp': 'http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing',
    'a': 'http://schemas.openxmlformats.org/drawingml/2006/main',
    'pic': 'http://schemas.openxmlformats.org/drawingml/2006/picture',
}

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
os.makedirs(OUTPUT_DIR, exist_ok=True)

DEFAULT_FINDINGS_PATH = os.path.join(TEMPLATE_DIR, "YOUSUNG EHS Audit Findings (1).xlsm")
DEFAULT_CHECKLIST_TEMPLATE = os.path.join(TEMPLATE_DIR, "20260422_YOUSUNG VINA_RBA Audit checklist.xlsx")
DEFAULT_DOCX_TEMPLATE = os.path.join(TEMPLATE_DIR, "20260422_YOUSUNG_Tóm tắt kết quả đánh giá định kỳ RBA 8.0_Lần 1.2026 (1).docx")

def _resolve_template(path):
    """Finds a template even if the file name uses another Unicode normalization (macOS NFD vs Windows NFC)."""
    if os.path.exists(path):
        return path
    import unicodedata
    want = unicodedata.normalize('NFC', os.path.basename(path)).lower()
    folder = os.path.dirname(path)
    if os.path.isdir(folder):
        for fn in os.listdir(folder):
            if unicodedata.normalize('NFC', fn).lower() == want:
                return os.path.join(folder, fn)
    return path


DEFAULT_FINDINGS_PATH = _resolve_template(DEFAULT_FINDINGS_PATH)
DEFAULT_CHECKLIST_TEMPLATE = _resolve_template(DEFAULT_CHECKLIST_TEMPLATE)
DEFAULT_DOCX_TEMPLATE = _resolve_template(DEFAULT_DOCX_TEMPLATE)

XL_NS = '{http://schemas.openxmlformats.org/spreadsheetml/2006/main}'
REL_NS = '{http://schemas.openxmlformats.org/officeDocument/2006/relationships}'
W_NS = '{http://schemas.openxmlformats.org/wordprocessingml/2006/main}'
A_NS = '{http://schemas.openxmlformats.org/drawingml/2006/main}'
XDR_NS = '{http://schemas.openxmlformats.org/drawingml/2006/spreadsheetDrawing}'
MC_NS = '{http://schemas.openxmlformats.org/markup-compatibility/2006}'

# Official 41 EHS Audit ID grouping structure matching Sheet 'Summary' of Audit Findings.xlsm
SUMMARY_CATEGORY_GROUPS = [
    {
        'category': 'Safety',
        'standard_items': 5,
        'codes': ['BH101', 'BH102', 'BH103', 'BH501', 'BH601'],
        'note': 'F16:F18 (BH101-BH103) + F26:F27 (BH501-BH601)'
    },
    {
        'category': 'Firefighting',
        'standard_items': 4,
        'codes': ['BH201', 'BH202', 'BH203', 'BH204'],
        'note': 'F19:F22 (BH201-BH204)'
    },
    {
        'category': 'Chemical',
        'standard_items': 5,
        'codes': ['BH301', 'BH302', 'BH401', 'BH701', 'BH702'],
        'note': 'F23:F25 (BH301-BH401) + F28:F29 (BH701-BH702)'
    },
    {
        'category': 'Safety System',
        'standard_items': 10,
        'codes': ['BM101', 'BM102', 'BM201', 'BM202', 'BM203', 'BM301', 'BM302', 'BM401', 'BM402', 'BM403'],
        'note': 'F30:F39 (BM101-BM403)'
    },
    {
        'category': 'Environment',
        'standard_items': 7,
        'codes': ['CE101', 'CE201', 'CE301', 'CE401', 'CE402', 'CE501', 'CE601'],
        'note': 'F40:F46 (CE101-CE601)'
    },
    {
        'category': 'Environment System',
        'standard_items': 10,
        'codes': ['CM101', 'CM102', 'CM201', 'CM202', 'CM203', 'CM301', 'CM302', 'CM401', 'CM402', 'CM403'],
        'note': 'F47:F56 (CM101-CM403)'
    }
]

CODE_TO_CATEGORY = {code: grp['category'] for grp in SUMMARY_CATEGORY_GROUPS for code in grp['codes']}

# Complete 41-Item RBA 8.0.1 EHS Rule Matrix (Priority / Major / Minor keywords & count thresholds)
RBA_801_RULE_MATRIX = {
    # --- BH1: Occupational Health & Safety ---
    'BH101': {
        'priority_kw': ['không bổ nhiệm người quản lý an toàn', 'no safety manager appointed', 'no health manager appointed'],
        'major_kw': ['không bổ nhiệm', 'chưa bổ nhiệm', 'không có chứng chỉ chuyên môn', 'no qualification'],
        'major_min_count': 2,
        'desc': 'Giấy phép, bổ nhiệm nhân sự an toàn & y tế'
    },
    'BH102': {
        'priority_kw': ['nguy cơ ngừng hoạt động', 'không cung cấp dụng cụ bảo hộ chống hóa chất', 'không có tiêu chuẩn cung cấp dụng cụ bảo hộ'],
        'major_kw': ['tủ điện', 'electric cabinet', 'aptomat', 'bảo hộ', 'protective gear', 'ppe', 'tiếp địa', 'khe hở', 'unsealed opening'],
        'major_min_count': 2,
        'desc': 'Thiết kế & kiểm soát nơi làm việc an toàn (An toàn điện & PPE)'
    },
    'BH103': {
        'priority_kw': ['nguy hiểm rõ ràng đến sức khỏe của phụ nữ mang thai', 'clear dangers to the health of the pregnant'],
        'major_kw': ['không có kế hoạch định hướng nào liên quan đến phụ nữ mang thai', 'không cung cấp không gian nghỉ ngơi', 'no policies related to pregnant'],
        'major_min_count': 2,
        'desc': 'Bảo vệ lao động nữ mang thai & nuôi con nhỏ'
    },
    # --- BH2: Emergency Preparedness ---
    'BH201': {
        'priority_kw': ['không lắp đặt thiết bị chữa cháy tự động', 'công trình bất hợp pháp', 'illegal building', 'không lắp đặt thiết bị phát hiện và báo cháy tự động'],
        'major_kw': ['bơm bù', 'bơm diesel', 'diesel pump', 'nút ấn báo cháy', 'fire alarm button', 'bình chữa cháy', 'fire extinguisher', 'họng nước', 'che chắn'],
        'major_min_count': 3,
        'desc': 'Hệ thống phát hiện, báo cháy và chữa cháy'
    },
    'BH202': {
        'priority_kw': ['không có kế hoạch ứng phó khẩn cấp', 'no emergency response plans'],
        'major_kw': ['không thiết lập điểm tập kết', 'không thiết lập trình tự, kế hoạch vận hành liên tục', 'bcp'],
        'major_min_count': 2,
        'desc': 'Chương trình chuẩn bị và ứng phó khẩn cấp (ERP/BCP)'
    },
    'BH203': {
        'priority_kw': ['không gắn sơ đồ thoát hiểm toàn bộ', '3 lối thoát hiểm trong từng tòa nhà bị chặn', 'three or more of all evacuation routes per building blocked'],
        'major_kw': ['toàn bộ nơi làm việc không xác định đường lối thoát hiểm'],
        'major_min_count': 6,
        'desc': 'Lối thoát nạn, cửa thoát hiểm, đèn chiếu sáng khẩn cấp & sơ đồ thoát nạn'
    },
    'BH204': {
        'priority_kw': ['không tổ chức diễn tập phòng cháy chữa cháy', 'did not perform fire extinguishing training'],
        'major_kw': ['ca đêm', 'night rehearsals', 'nighttime', '82/900', 'chỉ tổ chức diễn tập cho một số ca', 'thiếu sự tham gia'],
        'major_min_count': 2,
        'desc': 'Diễn tập sơ tán khẩn cấp PCCC cho toàn bộ ca/nhân viên'
    },
    # --- BH3: Occupational Injury and Illness ---
    'BH301': {
        'priority_kw': ['không báo cáo tai nạn lao động', 'không có thủ tục ứng phó', 'trở lại làm việc trước khi'],
        'major_kw': ['không quản lý các ghi chép về tai nạn', 'không tiến hành điều tra tai nạn', 'không phân tích nguyên nhân'],
        'major_min_count': 2,
        'desc': 'Báo cáo, điều tra nguyên nhân tai nạn lao động & bệnh nghề nghiệp'
    },
    'BH302': {
        'priority_kw': ['không có nhân lực cứu hộ khẩn cấp', 'không có quy trình sơ cấp cứu', 'no emergency rescue procedure'],
        'major_kw': ['không chuẩn bị hòm sơ cấp cứu', 'chưa được đào tạo sơ cấp cứu', 'first-aid kit not furnished'],
        'major_min_count': 4,
        'desc': 'Trang thiết bị sơ cấp cứu, túi y tế & phòng y tế'
    },
    # --- BH4: Industrial Hygiene ---
    'BH401': {
        'priority_kw': ['sử dụng chất bị cấm', 'benzene', 'n-hexane', 'không tiến hành đo lường chất lượng môi trường', 'không tiến hành kiểm tra sức khỏe'],
        'major_kw': ['msds', 'ghs', 'kho hóa chất', 'kho hoá chất', 'chemical storage', 'khay chống tràn', 'ứng phó sự cố'],
        'major_min_count': 2,
        'desc': 'Kiểm soát phơi nhiễm hóa chất, tác nhân vật lý & sinh học'
    },
    # --- BH5: Physically Demanding Work ---
    'BH501': {
        'priority_kw': ['không điều tra tác nhân gây hại tới cơ xương khớp', 'muscular-skeletal harm factor investigations not performed'],
        'major_kw': ['không lập kế hoạch cải thiện cơ xương khớp', 'no plan for improving'],
        'major_min_count': 2,
        'desc': 'Kiểm soát công việc nặng nhọc / Ergonomics cơ xương khớp'
    },
    # --- BH6: Machine Safeguarding (Negative Penalty Scores: Major=-2, Priority=-6) ---
    'BH601': {
        'priority_kw': ['tháo rời tùy tiện hai hoặc nhiều thiết bị an toàn', 'bỏ qua việc kiểm tra toàn bộ máy móc nguy hiểm'],
        'major_kw': ['chưa được kiểm định', 'not tested', 'untested', 'nút dừng khẩn cấp', 'emergency stop', 'cover an toàn', 'secure cover', 'không được lắp cover', 'cảm biến va chạm'],
        'major_min_count': 2,
        'desc': 'Chương trình an toàn máy móc thiết bị (Thiết bị áp lực, băng tải, che chắn)'
    },
    # --- BH7: Food, Sanitation, and Housing ---
    'BH701': {
        'priority_kw': ['không có giấy phép pháp lý để vận hành ký túc xá', 'không có kế hoạch dự phòng khẩn cấp trong ký túc xá'],
        'major_kw': ['cơ sở hạ tầng ký túc xá không đáp ứng', 'dorms and auxiliary facilities not meets'],
        'major_min_count': 2,
        'desc': 'Hạ tầng ký túc xá & khu vệ sinh sinh hoạt'
    },
    'BH702': {
        'priority_kw': ['chưa được phép điều hành nhà ăn', 'thực phẩm hết hạn sử dụng', 'expired food'],
        'major_kw': ['tủ sấy dao thớt', 'bể tách mỡ', 'bảo quản lạnh', 'tủ đông', 'nhiệt độ', 'hư hỏng', 'khay khử khuẩn', 'bếp điện'],
        'major_min_count': 2,
        'desc': 'Vệ sinh an toàn thực phẩm nhà ăn, bếp nấu & bảo quản thực phẩm'
    },
    # --- BM1..BM4: OHS Management System ---
    'BM101': {'priority_kw': ['không lập quy trình tuân thủ'], 'major_kw': ['không thực hiện xin giấy phép', 'sổ đăng ký y tế thiếu'], 'major_min_count': 2, 'desc': 'Quy trình tuân thủ pháp luật & khách hàng về OHS'},
    'BM102': {'priority_kw': ['không có quy trình quản lý rủi ro', 'a risk assessment is not conducted'], 'major_kw': ['bỏ qua một số đối tượng liên quan', 'bỏ qua một số tình huống khẩn cấp'], 'major_min_count': 3, 'desc': 'Quy trình đánh giá rủi ro an toàn sức khỏe (Due Diligence)'},
    'BM201': {'priority_kw': ['không thành lập đội phản ứng khẩn cấp', 'no ert and first responders'], 'major_kw': ['không được ghi lại bằng văn bản', 'thiếu một số tòa nhà'], 'major_min_count': 3, 'desc': 'Phân công trách nhiệm OHS & Đội ứng phó khẩn cấp (ERT)'},
    'BM202': {'priority_kw': ['không có quy trình xây dựng và lập văn bản quản lý chính sách an toàn'], 'major_kw': ['thiếu ít nhất 2 trong số các quy trình quản lý chính sách'], 'major_min_count': 2, 'desc': 'Chính sách & Quy trình kiểm soát OHS'},
    'BM203': {'priority_kw': ['quy trình đào tạo an toàn y tế không được thiết lập'], 'major_kw': ['thiếu ít nhất 2 nội dung đào tạo an toàn'], 'major_min_count': 2, 'desc': 'Quy trình đào tạo an toàn vệ sinh lao động'},
    'BM301': {'priority_kw': ['không thiết lập quy trình giao tiếp'], 'major_kw': ['thiếu các bên liên quan cần truyền đạt'], 'major_min_count': 2, 'desc': 'Giao tiếp thông tin OHS với người lao động & các bên liên quan'},
    'BM302': {'priority_kw': ['không thiết lập quy trình xử lý khiếu nại', 'quá 3 tháng'], 'major_kw': ['không được xử lý dưới dạng ẩn danh', 'trì hoãn trong hơn hai tuần'], 'major_min_count': 2, 'desc': 'Quy trình giải quyết khiếu nại/góp ý về OHS'},
    'BM401': {'priority_kw': ['không thiết lập quy trình kiểm tra kết quả an toàn y tế'], 'major_kw': ['không có mục tiêu chi tiết', 'vượt quá hai năm'], 'major_min_count': 2, 'desc': 'Đánh giá kết quả thực hiện của lãnh đạo & Cải tiến liên tục OHS'},
    'BM402': {'priority_kw': ['không thiết lập quy trình tự quản lý', 'self-audit process is not established'], 'major_kw': ['không tiến hành kiểm tra, đánh giá kết quả tự quản lý'], 'major_min_count': 2, 'desc': 'Quy trình tự đánh giá nội bộ (Self-audit OHS)'},
    'BM403': {'priority_kw': ['không thiết lập quy trình xử lý khắc phục'], 'major_kw': ['quy trình xử lý khắc phục không đầy đủ'], 'major_min_count': 2, 'desc': 'Quy trình hành động khắc phục phòng ngừa (CAPA OHS)'},
    # --- CE1..CE6: Environment ---
    'CE101': {
        'priority_kw': ['không có giấy phép môi trường', 'không thực hiện nghĩa vụ đo lường, báo cáo môi trường', 'environmental authorizations not acquired'],
        'major_kw': ['không báo cáo thay đổi', 'không tuân thủ chu kỳ kiểm tra, báo cáo'],
        'major_min_count': 2,
        'desc': 'Giấy phép môi trường & Báo cáo quan trắc định kỳ'
    },
    'CE201': {
        'priority_kw': ['chưa có kho chứa rác thải nguy hại', 'hazardous waste storage facility not installed', 'xả thải bất hợp pháp', 'tập kết chung với kho hoá chất', 'tập kết chung với kho hóa chất'],
        'major_kw': ['không tiến hành kiểm tra thực tế doanh nghiệp xử lý chất thải', 'không phân loại và lưu trữ chất thải theo đặc tính', 'urenco'],
        'major_min_count': 2,
        'desc': 'Quản lý chất thải nguy hại & đánh giá nhà thầu xử lý chất thải'
    },
    'CE301': {
        'priority_kw': ['xả thải bất hợp pháp', 'không ký hợp đồng với doanh nghiệp có giấy phép vận chuyển, xử lý chất thải thông thường'],
        'major_kw': ['không có kho bảo quản chất thải thông thường tại nơi làm việc', 'không tiến hành thẩm định, kiểm tra thực tế đối với doanh nghiệp xử lý chất thải thông thường'],
        'major_min_count': 5,
        'desc': 'Quản lý và xử lý chất thải rắn công nghiệp / sinh hoạt'
    },
    'CE401': {
        'priority_kw': ['vượt quá tiêu chuẩn cho phép phát thải', 'phát thải trái phép mà không được xử lý', 'exceeding the emission approval level'],
        'major_kw': ['quản lý không hợp lý về thiết bị ngăn chặn phát thải', 'than hoạt tính', 'bộ lọc', 'chưa hoàn thành chương trình giáo dục bắt buộc'],
        'major_min_count': 2,
        'desc': 'Hệ thống kiểm soát khí thải (Penalty Item = X khi Priority)'
    },
    'CE402': {
        'priority_kw': ['không tiến hành đo lường mức độ tiếng ồn', 'khiếu nại của người dân về tiếng ồn'],
        'major_kw': ['tiếng ồn vượt quá tiêu chuẩn quy định'],
        'major_min_count': 2,
        'desc': 'Kiểm soát tiếng ồn môi trường xung quanh (Penalty Item = X khi Priority)'
    },
    'CE501': {
        'priority_kw': ['xả nước thải vượt quá tiêu chuẩn', 'xả trái phép mà không qua xử lý', 'exceeding of the wastewater discharge standards'],
        'major_kw': ['quản lý không hợp lý về thiết bị xử lý nước thải', 'chưa hoàn thành chương trình giáo dục bắt buộc về nước thải'],
        'major_min_count': 5,
        'desc': 'Quản lý nước & Hệ thống xử lý nước thải (Penalty Item = X khi Priority)'
    },
    'CE601': {
        'priority_kw': ['không quản lý lượng sử dụng năng lượng và lượng phát thải khí nhà kính', 'không lập kế hoạch và mục tiêu tiết kiệm năng lượng'],
        'major_kw': ['không được chuyển đổi thành lượng phát thải khí nhà kính', 'không ghi chép quản lý hiệu suất tiết kiệm năng lượng'],
        'major_min_count': 2,
        'desc': 'Tiêu thụ năng lượng & Kiểm soát phát thải khí nhà kính (GHG)'
    },
    # --- CM1..CM4: Environmental Management System ---
    'CM101': {'priority_kw': ['không thành lập quy trình để tuân thủ quy định luật môi trường'], 'major_kw': ['thiếu thủ tục gia hạn giấy phép môi trường'], 'major_min_count': 2, 'desc': 'Quy trình tuân thủ pháp luật & khách hàng về Môi trường'},
    'CM102': {'priority_kw': ['không có quy trình đánh giá ảnh hưởng tới môi trường'], 'major_kw': ['bỏ qua một số bên liên quan', 'bỏ qua 1 số yếu tố ảnh hưởng tới môi trường'], 'major_min_count': 3, 'desc': 'Quy trình đánh giá tác động/rủi ro Môi trường'},
    'CM201': {'priority_kw': ['không tiến hành văn bản hóa quyền hạn và trách nhiệm môi trường'], 'major_kw': ['thiếu ít nhất hai người phụ trách liên quan đến các yếu tố ảnh hưởng đến môi trường'], 'major_min_count': 2, 'desc': 'Phân công trách nhiệm quản lý Môi trường'},
    'CM202': {'priority_kw': ['không có quy trình xây dựng, quản lý và văn bản hóa chính sách môi trường'], 'major_kw': ['thiếu ít nhất một trong các nội dung bao gồm chính sách môi trường'], 'major_min_count': 2, 'desc': 'Chính sách & Quy trình kiểm soát Môi trường'},
    'CM203': {'priority_kw': ['không thiết lập quy trình đào tạo về môi trường'], 'major_kw': ['thiếu ít nhất 2 nội dung đào tạo về môi trường'], 'major_min_count': 2, 'desc': 'Quy trình đào tạo về Môi trường'},
    'CM301': {'priority_kw': ['không thiết lập quy trình giao tiếp, truyền đạt nội dung về các thông tin môi trường'], 'major_kw': ['công khai lượng khí thải nhà kính', 'thiếu các bên liên quan'], 'major_min_count': 2, 'desc': 'Giao tiếp thông tin Môi trường với người lao động & bên liên quan'},
    'CM302': {'priority_kw': ['không thiết lập quy trình xử lý khiếu nại các vấn đề môi trường'], 'major_kw': ['không được xử lý dưới dạng ẩn danh', 'trì hoãn trong hơn hai tuần'], 'major_min_count': 2, 'desc': 'Quy trình giải quyết khiếu nại về Môi trường'},
    'CM401': {'priority_kw': ['không thiết lập quy trình kiểm tra kết quả môi trường doanh nghiệp'], 'major_kw': ['mục tiêu giảm thiểu sử dụng nguồn ô nhiễm', 'vượt quá hai năm'], 'major_min_count': 2, 'desc': 'Đánh giá kết quả thực hiện của lãnh đạo & Cải tiến liên tục Môi trường'},
    'CM402': {'priority_kw': ['không thiết lập quy trình tự quản lý các yêu cầu của khách hàng và tuân thủ các hạng mục môi trường'], 'major_kw': ['không tiến hành kiểm tra, đánh giá kết quả tự quản lý'], 'major_min_count': 2, 'desc': 'Quy trình tự đánh giá nội bộ (Self-audit Môi trường)'},
    'CM403': {'priority_kw': ['không thiết lập quy trình xử lý khắc phục các vấn đề không phù hợp về môi trường'], 'major_kw': ['quy trình xử lý khắc phục không đầy đủ'], 'major_min_count': 2, 'desc': 'Quy trình hành động khắc phục phòng ngừa (CAPA Môi trường)'},
}


def normalize_audit_id(raw_id, sub_category="", provision="", valid_items_list=None):
    """
    Normalizes an Audit ID string from Findings sheet (e.g. 'bh 102', 'BH-102', 'BH102')
    to one of the 41 canonical RBA EHS Audit IDs ('BH101'..'CM403').
    If Audit ID is missing or mistyped, attempts fallback matching by Sub Category.
    Returns (canonical_id, was_recovered, warning_msg).
    """
    cleaned = str(raw_id or '').strip().upper()
    m = re.search(r'(BH|BM|CE|CM|AL|AM|BE|DM|EE|EM)\s*[-_]?\s*(\d{3})', cleaned)
    if m:
        candidate = f"{m.group(1)}{m.group(2)}"
        if not valid_items_list or any(it['audit_id'] == candidate for it in valid_items_list):
            return candidate, False, None

    # Fallback: match by Sub Category or Provision if valid_items_list is provided
    if valid_items_list and sub_category:
        sub_low = sub_category.strip().lower()
        for it in valid_items_list:
            if it['sub_category'].strip().lower() == sub_low:
                return it['audit_id'], True, f"Tự động khôi phục mã {it['audit_id']} từ Sub Category '{sub_category}' (mã gốc: '{raw_id}')"

    # The id reaches HTML unescaped in several views, so keep only code characters
    return re.sub(r'[^A-Z0-9_-]', '', cleaned)[:20] or 'UNKNOWN', False, f"Mã Audit ID '{raw_id}' không nằm trong danh mục 41 mã RBA EHS chuẩn"


# Instruction text printed in the blank Findings form (row 7), not an auditor's statement
FORM_PLACEHOLDERS = {'vấn đề hiện trường cải tiến', 'ảnh up', 'nội dung cần cải tiến là gì'}
_LIST_MARKER_RE = re.compile(r'^(?:[-–•*]+\s+|[-–•*]+(?=\D)|\d+\s*[:)]\s*|\d+\.\s+)')


def split_bilingual(text, auto_translate=True):
    """
    Splits a cell string into (en_text, vn_text, full_text) where:
    - The auditor's wording is kept word for word (only list markers like '- ' or '1: ' go).
    - A missing language comes from vetted translations only. Without one, both values hold
      the original sentence: QA flags it and the report shows it unchanged.
    - full_text is ALWAYS formatted with Vietnamese FIRST and English SECOND:
      f"{vn_text}\\n{en_text}"
    """
    if not text:
        return "", "", ""
    raw_lines = str(text).replace('\r\n', '\n').replace('\r', '\n').split('\n')
    lines = [_LIST_MARKER_RE.sub('', ln.strip()).strip() for ln in raw_lines]
    lines = [ln for ln in lines if ln]
    if not lines:
        return "", "", ""
    vn_text = "\n".join(ln for ln in lines if is_vietnamese_text(ln))
    en_text = "\n".join(ln for ln in lines if not is_vietnamese_text(ln))
    if auto_translate:
        vn_text = vn_text or auto_translate_en_to_vn(en_text)
        en_text = en_text or auto_translate_vn_to_en(vn_text)
    return en_text or vn_text, vn_text or en_text, format_bilingual_vn_first(vn_text, en_text)


def _compact_violation_text(txt, max_len=165):
    """Compacts a violation line so executive summary bullets fit cleanly on 2 pages."""
    s = re.sub(r'\s+', ' ', str(txt or '').replace('\n', ' ')).strip().rstrip(',;:')
    if len(s) <= max_len:
        return s
    cut = s[:max_len].rsplit(' ', 1)[0].rstrip(',;:.')
    return cut + "..."


def cap_violations_pair(doc_list, fac_list, max_per_type=3, max_total=5):
    """
    Ensures doc_violations and facility_violations each have at most 2-3 representative
    items (max_per_type=3) and their combined total never exceeds max_total (5).
    """
    docs = [_compact_violation_text(x) for x in (doc_list or []) if str(x or '').strip()][:max_per_type]
    facs = [_compact_violation_text(x) for x in (fac_list or []) if str(x or '').strip()][:max_per_type]
    if len(docs) + len(facs) > max_total:
        # Keep 2-3 of each so total <= 5 (e.g. 2 doc + 3 fac, or 3 doc + 2 fac)
        if len(facs) >= 3 and len(docs) >= 3:
            docs = docs[:2]
            facs = facs[:3]
        elif len(docs) > max_total - len(facs):
            docs = docs[:max(2, max_total - len(facs))]
            facs = facs[:max_total - len(docs)]
    return docs, facs


def select_top_violations(findings, checklist_evaluated, max_per_type=3, max_total=5):
    """
    Selects 2-3 representative document violations and 2-3 representative facility
    violations (prioritizing Priority -> Major -> Minor), with combined total <= 5.
    """
    sig_rank = {'Priority': 3, 'Major': 2, 'Minor': 1, 'Conformance': 0, 'N/A': 0}
    code_sig = {it['audit_id']: it.get('significance', 'Conformance') for it in (checklist_evaluated or [])}

    def rank_key(f):
        s_r = sig_rank.get(code_sig.get(f.get('audit_id'), 'Minor'), 1)
        m_r = 1 if str(f.get('mandatory', '')).strip().lower() in ('mandatory', 'bắt buộc', 'hmbb', 'x') or f.get('audit_id') == 'CE201' else 0
        return (-s_r, -m_r, f.get('no', 999))

    doc_f = sorted(
        [f for f in findings if f.get('cause', '').strip().lower() == 'administrative' or 'hồ sơ' in f.get('location_vn', '').lower()],
        key=rank_key
    )
    fac_f = sorted(
        [f for f in findings if f.get('cause', '').strip().lower() == 'facility' and f not in doc_f],
        key=rank_key
    )
    doc_raw, fac_raw = [], []
    for f in doc_f:
        v = f.get('issue_vn', '').strip()
        if v and v not in doc_raw:
            doc_raw.append(v)
    for f in fac_f:
        v = f.get('issue_vn', '').strip()
        if v and v not in fac_raw:
            fac_raw.append(v)
    return cap_violations_pair(doc_raw, fac_raw, max_per_type=max_per_type, max_total=max_total)


def compute_penalty_violation(penalty_item_flag, penalty_criteria, final_significance):
    """
    Replicates exact Excel formula in Checklist Column H:
    =IF(AND(F5="X",G5=D5),"X",IF(AND(F5="X",G5="Major", D5="Priority"),"X",""))
    """
    f_val = str(penalty_item_flag or '').strip().upper()
    g_val = str(penalty_criteria or '').strip()
    d_val = str(final_significance or '').strip()
    if f_val == "X" and g_val == d_val:
        return "X"
    if f_val == "X" and g_val == "Major" and d_val == "Priority":
        return "X"
    return ""


_REF_CACHE = {'key': None, 'ref': None}


def _mtime(path):
    try:
        return os.path.getmtime(path)
    except OSError:
        return None


def load_checklist_reference(checklist_path=DEFAULT_CHECKLIST_TEMPLATE):
    """Parses the checklist template only when it or the master rules changed on disk."""
    if _REF_CACHE['key'] != (checklist_path, _mtime(checklist_path), _mtime(MASTER_RULES_FILE)):
        ref = _parse_checklist_reference(checklist_path)
        # parsing may create or rewrite the master rules file, so stat again afterwards
        _REF_CACHE.update(key=(checklist_path, _mtime(checklist_path), _mtime(MASTER_RULES_FILE)), ref=ref)
    return copy.deepcopy(_REF_CACHE['ref'])


def _parse_checklist_reference(checklist_path):
    """
    Loads the 41 EHS Audit IDs, their metadata, criteria (VN/EN), penalty flags,
    and the Score lookup table from the RBA Audit Checklist template.
    """
    with zipfile.ZipFile(checklist_path, 'r') as z:
        shared_strings = []
        if 'xl/sharedStrings.xml' in z.namelist():
            ss_xml = ET.fromstring(z.read('xl/sharedStrings.xml'))
            for si in ss_xml.findall(f'{XL_NS}si'):
                texts = [t.text or '' for t in si.iter(f'{XL_NS}t')]
                shared_strings.append(''.join(texts))

        def get_cell_val(c_el):
            if c_el is None:
                return ""
            c_type = c_el.attrib.get('t')
            v_el = c_el.find(f'{XL_NS}v')
            is_el = c_el.find(f'{XL_NS}is')
            if c_type == 's' and v_el is not None and v_el.text is not None:
                idx = int(v_el.text)
                return shared_strings[idx] if idx < len(shared_strings) else v_el.text
            elif c_type == 'inlineStr' and is_el is not None:
                return ''.join([t.text or '' for t in is_el.iter(f'{XL_NS}t')])
            elif v_el is not None and v_el.text is not None:
                return v_el.text
            return ""

        # 1. Load Score Table from sheet4.xml (Table)
        score_map = {}
        tbl_xml = ET.fromstring(z.read('xl/worksheets/sheet4.xml'))
        for row in tbl_xml.findall(f'.//{XL_NS}row'):
            r_num = int(row.attrib.get('r', 0))
            if r_num < 2:
                continue
            c_map = {}
            for c in row.findall(f'{XL_NS}c'):
                col = ''.join([ch for ch in c.attrib.get('r', '') if ch.isalpha()])
                c_map[col] = get_cell_val(c)
            audit_id = c_map.get('A', '').strip()
            grade = c_map.get('B', '').strip()
            section = c_map.get('C', '').strip()
            score_str = c_map.get('E', '0').strip()
            if audit_id and grade:
                try:
                    score_val = float(score_str)
                    if score_val.is_integer():
                        score_val = int(score_val)
                except ValueError:
                    score_val = 0
                score_map[f"{audit_id}|{grade}|{section}"] = score_val

        # 2. Load 41 Checklist Items from sheet2.xml (Checklist)
        items = []
        chk_xml = ET.fromstring(z.read('xl/worksheets/sheet2.xml'))
        for row in chk_xml.findall(f'.//{XL_NS}row'):
            r_num = int(row.attrib.get('r', 0))
            if r_num < 5 or r_num > 45:
                continue
            c_map = {}
            for c in row.findall(f'{XL_NS}c'):
                col = ''.join([ch for ch in c.attrib.get('r', '') if ch.isalpha()])
                c_map[col] = get_cell_val(c)
            audit_id = c_map.get('B', '').strip()
            section = c_map.get('S', 'EHS').strip() or 'EHS'
            items.append({
                'row_num': r_num,
                'provision': c_map.get('A', '').strip(),
                'audit_id': audit_id,
                'audit_item': c_map.get('C', 'O').strip(),
                'template_significance': c_map.get('D', 'Conformance').strip(),
                'penalty_item': c_map.get('F', '').strip(),
                'penalty_criteria': c_map.get('G', '').strip(),
                'sub_category': c_map.get('J', '').strip(),
                'conformance_statement': c_map.get('K', '').strip(),
                'criteria_vn': c_map.get('M', '').strip(),
                'criteria_en': c_map.get('N', '').strip(),
                'section': section,
                'scores': {
                    g: score_map.get(f"{audit_id}|{g}|{section}", 0)
                    for g in ['Conformance', 'Minor', 'Major', 'Priority', 'N/A']
                }
            })

        # 3. Load General Information defaults from sheet1.xml
        gen_info = {}
        gen_xml = ET.fromstring(z.read('xl/worksheets/sheet1.xml'))
        for row in gen_xml.findall(f'.//{XL_NS}row'):
            r_num = int(row.attrib.get('r', 0))
            c_map = {}
            for c in row.findall(f'{XL_NS}c'):
                col = ''.join([ch for ch in c.attrib.get('r', '') if ch.isalpha()])
                c_map[col] = get_cell_val(c)
            if 'D' in c_map and r_num <= 35:
                gen_info[f"D{r_num}"] = c_map['D']

    raw_ref = {
        'items': items,
        'score_map': score_map,
        'general_info_defaults': gen_info
    }
    master_db = init_or_load_master_rules(RBA_801_RULE_MATRIX, SUMMARY_CATEGORY_GROUPS, raw_ref)
    init_file_repository(DEFAULT_FINDINGS_PATH, DEFAULT_CHECKLIST_TEMPLATE, DEFAULT_DOCX_TEMPLATE)
    return {
        'items': master_db['items'],
        'score_map': score_map,
        'general_info_defaults': master_db.get('general_info_defaults', gen_info),
        'category_groups': master_db.get('category_groups', SUMMARY_CATEGORY_GROUPS),
        'mandatory_triggers': master_db.get('mandatory_triggers', ['mandatory', 'bắt buộc', 'hmbb', 'x', 'yes', '1']),
        'grade_thresholds': master_db.get('grade_thresholds', {'A': 90, 'B': 80, 'C': 70, 'D': 0}),
    }


def auto_classify_significance(audit_id, findings_list, criteria_vn="", criteria_en="", custom_rule=None, mandatory_triggers=None):
    """
    Comprehensive 4-Layer RBA 8.0.1 Significance Classifier for all 41 EHS Audit IDs:
    - Layer 1: Zero findings -> Conformance
    - Layer 2: Explicit Mandatory flag (Column I) or Explicit Grade (Column R/S) in Findings
    - Layer 3: Master Rule Matrix keyword & count threshold evaluation for all 41 codes
    - Layer 4: Fallback count threshold
    """
    # Layer 1: Zero findings
    if not findings_list:
        return "Conformance", "Không có điểm không phù hợp (0 lỗi ➔ Conformance)"

    # Layer 2a: Explicit Mandatory violation flag in Column I
    triggers = tuple(t.lower() for t in (mandatory_triggers or ('mandatory', 'bắt buộc', 'hmbb', 'x', 'yes', '1')))
    for f in findings_list:
        mand_val = str(f.get('mandatory', '')).strip().lower()
        if mand_val in triggers:
            return "Priority", f"Vi phạm hạng mục bắt buộc (Cờ Mandatory tại lỗi #{f['no']} ➔ Priority)"

    # Layer 2b: Check if Auditor explicitly tagged grade in Column R/S (eval_grade)
    explicit_ranks = {'priority': 3, 'major': 2, 'minor': 1}
    best_explicit = None
    best_rank = 0
    for f in findings_list:
        eg = str(f.get('eval_grade', '')).strip().lower()
        if eg in explicit_ranks and explicit_ranks[eg] > best_rank:
            best_rank = explicit_ranks[eg]
            best_explicit = eg.capitalize()
    if best_explicit:
        return best_explicit, f"Phân loại trực tiếp từ cột đánh giá ({best_explicit})"

    # Layer 3: Evaluate against Master Database rule (or fallback RBA_801_RULE_MATRIX) for this Audit ID
    count = len(findings_list)
    combined_text = " ".join([
        f"{f.get('issue_vn', '')} {f.get('issue_en', '')}".lower()
        for f in findings_list
    ])

    rule = custom_rule or RBA_801_RULE_MATRIX.get(audit_id)
    if rule:
        # 3.1 Check Priority keywords
        for kw in rule.get('priority_kw', []):
            if kw and kw.lower() in combined_text:
                return "Priority", f"Phát hiện từ khóa vi phạm nghiêm trọng '{kw}' theo tiêu chí {audit_id} (➔ Priority)"

        # 3.2 Check Major keywords or Major count threshold
        for kw in rule.get('major_kw', []):
            if kw and kw.lower() in combined_text:
                return "Major", f"Có {count} lỗi thuộc {audit_id} ({rule.get('desc', '')}: khớp tiêu chí '{kw}' ➔ Major)"

        major_min = int(rule.get('major_min_count', 3))
        if count >= major_min:
            return "Major", f"Có {count} lỗi thuộc {audit_id} (≥{major_min} lỗi theo ngưỡng {rule.get('desc', '')} ➔ Major)"

        return "Minor", f"Có {count} lỗi cục bộ thuộc {audit_id} ({rule.get('desc', '')} ➔ Minor)"

    # Layer 4: General fallback
    if count >= 3:
        return "Major", f"Có {count} vấn đề phát hiện tại mã {audit_id} (➔ Major)"
    return "Minor", f"Có {count} vấn đề phát hiện tại mã {audit_id} (➔ Minor)"


def build_summary_6_categories(checklist_evaluated, category_groups=None):
    """
    Computes the 6-category RBA Compliance Rate table matching Sheet 'Summary' (rows 5-11)
    of Audit Findings.xlsm using the Master Category Grouping.
    """
    code_map = {it['audit_id']: it for it in checklist_evaluated}
    cat_rows = []
    tot_std = 0
    tot_prob_items = 0
    tot_obs_items = 0
    tot_findings = 0

    groups_to_use = category_groups or SUMMARY_CATEGORY_GROUPS
    for grp in groups_to_use:
        std_cnt = grp['standard_items']
        prob_items = sum(
            1 for c in grp['codes']
            if code_map.get(c, {}).get('finding_count', 0) > 0
            or code_map.get(c, {}).get('significance') in ('Minor', 'Major', 'Priority')
        )
        obs_items = std_cnt - prob_items
        rate = round((obs_items / std_cnt) * 100, 1) if std_cnt else 0
        f_sum = sum(
            max(
                code_map.get(c, {}).get('finding_count', 0),
                1 if code_map.get(c, {}).get('significance') in ('Minor', 'Major', 'Priority') else 0
            )
            for c in grp['codes']
        )

        tot_std += std_cnt
        tot_prob_items += prob_items
        tot_obs_items += obs_items
        tot_findings += f_sum

        cat_rows.append({
            'category': grp['category'],
            'codes': grp['codes'],
            'standard_items': std_cnt,
            'problem_items': prob_items,
            'observe_items': obs_items,
            'compliance_rate': rate,
            'total_findings': f_sum,
            'note': grp['note']
        })

    return {
        'categories': cat_rows,
        'total': {
            'standard_items': tot_std,
            'problem_items': tot_prob_items,
            'observe_items': tot_obs_items,
            'compliance_rate': round((tot_obs_items / tot_std) * 100, 2) if tot_std else 0,
            'total_findings': tot_findings
        }
    }


def _extract_checklist_evidence_lines(ev_raw):
    """
    Splits Checklist Column L evidence text (e.g. '1: Issue A\\n2: Issue B\\n3:')
    into clean non-empty finding strings, stripping empty numbered placeholders.
    """
    txt = str(ev_raw or '').replace('\r\n', '\n').replace('\r', '\n').strip()
    if not txt:
        return []
    # Remove any standalone empty numbered lines like '1:', '2:', '3:' first
    lines_raw = []
    for raw_ln in txt.split('\n'):
        s_ln = raw_ln.strip()
        if not s_ln or re.match(r'^\d+\s*[:.]?\s*$', s_ln):
            continue
        lines_raw.append(s_ln)
    if not lines_raw:
        return []
    joined = '\n'.join(lines_raw)
    if re.search(r'(?:^|\n)[ \t]*\d+[ \t]*[:.]', joined):
        parts = re.split(r'(?:^|\n)[ \t]*\d+[ \t]*[:.][ \t]*', joined)
    else:
        parts = lines_raw
    cleaned = []
    for p in parts:
        line = ' '.join(ln.strip() for ln in p.split('\n') if ln.strip()).strip()
        line = re.sub(r'^[-•*]+\s*', '', line).strip()
        if line and not re.match(r'^\d+\s*[:.]?\s*$', line):
            cleaned.append(line)
    return cleaned


def _infer_checklist_finding_cause(audit_id, issue_text):
    """
    Infers whether a finding extracted from a Checklist sheet is 'administrative'
    (Lỗi quy trình, hồ sơ) or 'facility' (Lỗi hiện trường).
    """
    low = str(issue_text or '').lower()
    facility_kw = (
        'trang bị', 'lắp đặt', 'kết nối', 'cửa cuốn', 'đê bao', 'biển cảnh báo',
        'bảng biển', 'rò rỉ', 'che chắn', 'nút dừng', 'khay chống tràn', 'nhãn',
        'lưu trữ', 'bố trí', 'kho hóa chất', 'kho nguyên vật liệu', 'kho thành phẩm',
        'tủ điện', 'bình chữa cháy', 'vật liệu chống cháy nổ', 'scba'
    )
    doc_kw = (
        'quy trình', 'hồ sơ', 'giấy phép', 'kiểm định', 'huấn luyện', 'đào tạo',
        'quan trắc', 'đánh giá rủi ro', 'báo cáo', 'kế hoạch', 'chương trình',
        'kiểm kê', 'đánh giá nội bộ', 'khắc phục phòng ngừa'
    )
    if any(k in low for k in facility_kw) and not audit_id.startswith(('BM', 'CM')):
        return 'facility'
    if audit_id.startswith(('BM', 'CM')) or audit_id in ('BH101', 'CE101'):
        return 'administrative'
    if any(k in low for k in doc_kw):
        return 'administrative'
    return 'facility'


def parse_checklist_xlsx(xlsx_path, checklist_ref=None, default_cause=None):
    """
    Directly parses an RBA Audit Checklist (.xlsx) workbook (containing 'General Information'
    and 'Checklist' sheets), preserving all 41 item ratings (Col D), VLOOKUP scores,
    evidence texts (Col L), observation columns (O..R), and General Information metadata.
    """
    if checklist_ref is None:
        checklist_ref = load_checklist_reference()

    with zipfile.ZipFile(xlsx_path, 'r') as z:
        shared_strings = []
        if 'xl/sharedStrings.xml' in z.namelist():
            ss_xml = ET.fromstring(z.read('xl/sharedStrings.xml'))
            for si in ss_xml.findall(f'{XL_NS}si'):
                texts = [t.text or '' for t in si.iter(f'{XL_NS}t')]
                shared_strings.append(''.join(texts))

        def get_cell_val(c_el):
            if c_el is None:
                return ""
            c_type = c_el.attrib.get('t')
            v_el = c_el.find(f'{XL_NS}v')
            is_el = c_el.find(f'{XL_NS}is')
            if c_type == 's' and v_el is not None and v_el.text is not None:
                idx = int(v_el.text)
                return shared_strings[idx] if idx < len(shared_strings) else v_el.text
            elif c_type == 'inlineStr' and is_el is not None:
                return ''.join([t.text or '' for t in is_el.iter(f'{XL_NS}t')])
            elif v_el is not None and v_el.text is not None:
                return v_el.text
            return ""

        def read_sheet_rows(sheet_path):
            if not sheet_path or sheet_path not in z.namelist():
                return {}
            sh_xml = ET.fromstring(z.read(sheet_path))
            rows = {}
            for row in sh_xml.findall(f'.//{XL_NS}row'):
                r_num = int(row.attrib.get('r', 0))
                c_map = {}
                for c in row.findall(f'{XL_NS}c'):
                    col = ''.join([ch for ch in c.attrib.get('r', '') if ch.isalpha()])
                    c_map[col] = get_cell_val(c)
                rows[r_num] = c_map
            return rows

        gen_sheet_path = 'xl/worksheets/sheet1.xml'
        chk_sheet_path = 'xl/worksheets/sheet2.xml'
        if 'xl/workbook.xml' in z.namelist() and 'xl/_rels/workbook.xml.rels' in z.namelist():
            wb_xml = ET.fromstring(z.read('xl/workbook.xml'))
            wb_rels = ET.fromstring(z.read('xl/_rels/workbook.xml.rels'))
            rid_to_target = {r.attrib['Id']: r.attrib['Target'] for r in wb_rels}
            for sh in wb_xml.iter(f'{XL_NS}sheet'):
                sh_name = sh.attrib.get('name', '').strip().lower()
                rid = sh.attrib.get(f'{REL_NS}id', '')
                t_path = rid_to_target.get(rid, '')
                if not t_path.startswith('xl/'):
                    t_path = 'xl/' + t_path.lstrip('/')
                if 'general' in sh_name and t_path in z.namelist():
                    gen_sheet_path = t_path
                elif sh_name == 'checklist' and t_path in z.namelist():
                    chk_sheet_path = t_path

        gen_rows = read_sheet_rows(gen_sheet_path)
        chk_rows = read_sheet_rows(chk_sheet_path)

    def g_val(r_idx, default=''):
        return str(gen_rows.get(r_idx, {}).get('D', default) or '').strip()

    def g_int(r_idx, default=0):
        try:
            return int(float(g_val(r_idx, default) or 0))
        except (ValueError, TypeError):
            return default

    vendor_short_chk = str(chk_rows.get(1, {}).get('B', '') or '').strip()
    vendor_code_chk = str(chk_rows.get(2, {}).get('B', '') or '').strip()
    vendor_full_raw = g_val(3, '')
    vendor_full = re.sub(r'\bTNHH\s+TNHH\b', 'TNHH', vendor_full_raw, flags=re.IGNORECASE).strip()
    if not vendor_short_chk and vendor_full:
        vendor_short_chk = re.sub(r'^(công\s+ty\s+(tnhh|cổ\s+phần|cp)\s+)', '', vendor_full, flags=re.IGNORECASE).strip()
    vendor_short = vendor_short_chk or 'VENDOR'
    if not vendor_full:
        vendor_full = f"Công ty TNHH {vendor_short}"

    d9_raw = g_val(9, '')
    d10_raw = g_val(10, '')
    d11_raw = g_val(11, '')
    d9 = _excel_serial_to_date(d9_raw)
    d10 = _excel_serial_to_date(d10_raw)
    d1_chk = _excel_serial_to_date(str(chk_rows.get(1, {}).get('D', '') or '').strip())
    if d9 and d10 and d9 != d10:
        audit_date_raw = f"{d9.replace('/', '-')} , {d10.replace('/', '-')}"
    elif d9:
        audit_date_raw = d9.replace('/', '-')
    elif d1_chk:
        audit_date_raw = d1_chk.replace('/', '-')
    else:
        audit_date_raw = datetime.datetime.now().strftime('%d-%m-%Y')

    auditor_1 = g_val(6, '')
    auditor_2 = g_val(7, '')
    auditor_raw = auditor_1 if (auditor_1 == auditor_2 or not auditor_2) else f"{auditor_1}, {auditor_2}".strip(', ')

    chk_by_code = {}
    for r_num in range(5, 46):
        c_map = chk_rows.get(r_num, {})
        code = str(c_map.get('B', '') or '').strip().upper()
        if code:
            chk_by_code[code] = (r_num, c_map)

    valid_sigs = {'conformance': 'Conformance', 'minor': 'Minor', 'major': 'Major', 'priority': 'Priority', 'n/a': 'N/A', 'na': 'N/A'}
    findings = []
    checklist_evaluated = []
    audit_warnings = []
    for item in checklist_ref['items']:
        code = item['audit_id']
        r_num, c_map = chk_by_code.get(code, (item['row_num'], chk_rows.get(item['row_num'], {})))
        raw_sig = str(c_map.get('D', 'Conformance') or 'Conformance').strip().lower()
        sig = valid_sigs.get(raw_sig, 'Conformance')
        ev_raw = str(c_map.get('L', '') or '').strip()
        ev_lines = _extract_checklist_evidence_lines(ev_raw)

        if sig in ('Conformance', 'N/A') and ev_lines:
            audit_warnings.append(f"Mã {code}: cột D đang để '{sig}' nhưng cột L có ghi nhận nội dung phát hiện.")

        f_list = []
        if sig in ('Minor', 'Major', 'Priority'):
            for l_idx, ln in enumerate(ev_lines):
                no_val = len(findings) + 1
                cause = default_cause or _infer_checklist_finding_cause(code, ln)
                iss_en, iss_vn, iss_full = split_bilingual(ln, auto_translate=True)
                is_fac = str(cause).lower() == 'facility'
                loc_vn = 'Nhà máy' if is_fac else 'Hồ sơ'
                loc_en = 'Factory' if is_fac else 'Document'
                f_obj = {
                    'excel_row': r_num,
                    'no': no_val,
                    'provision': item['provision'],
                    'category': CODE_TO_CATEGORY.get(code, 'Safety'),
                    'audit_id': code,
                    'raw_audit_id': code,
                    'was_recovered': False,
                    'sub_category': item['sub_category'],
                    'location_full': f"{loc_vn}\n{loc_en}",
                    'location_en': loc_en,
                    'location_vn': loc_vn,
                    'issue_full': iss_full,
                    'issue_en': iss_en,
                    'issue_vn': iss_vn,
                    'cause': cause,
                    'mandatory': 'Mandatory' if (sig == 'Priority' and l_idx == 0) else '',
                    'eval_grade': sig if sig in ('Minor', 'Major', 'Priority') else '',
                    'improvement_full': '',
                    'improvement_en': '',
                    'improvement_vn': '',
                    'improvement_date': '',
                    'complete_date': '',
                    'photos': [],
                    'after_photos': []
                }
                findings.append(f_obj)
                f_list.append(f_obj)

        score = item['scores'].get(sig, 0)
        pen_viol = compute_penalty_violation(item['penalty_item'], item['penalty_criteria'], sig)
        if not f_list:
            evidence_text = "1:\n2:\n3:"
        elif len(f_list) == 1:
            evidence_text = f_list[0]['issue_full']
        else:
            evidence_text = "\n".join(f"{idx}. {f_obj['issue_full']}" for idx, f_obj in enumerate(f_list, 1))

        checklist_evaluated.append({
            'row_num': item['row_num'],
            'provision': item['provision'],
            'audit_id': code,
            'sub_category': item['sub_category'],
            'finding_count': len(f_list),
            'significance': sig,
            'doc_significance': sig,
            'auto_significance': sig,
            'auto_reason': f"Đọc trực tiếp từ file RBA Audit Checklist ({sig})",
            'violation_mark': "X" if sig not in ("Conformance", "N/A") else "",
            'penalty_item': item['penalty_item'],
            'penalty_criteria': item['penalty_criteria'],
            'penalty_violation': pen_viol,
            'score': score,
            'scores_table': item['scores'],
            'rule': item.get('rule', RBA_801_RULE_MATRIX.get(code, {})),
            'evidence_text': evidence_text,
            'criteria_vn': item['criteria_vn'],
            'criteria_en': item['criteria_en'],
            'site_observation': str(c_map.get('O', '') or '').strip(),
            'record_review': str(c_map.get('P', 'O') or 'O').strip(),
            'mgmt_interview': str(c_map.get('Q', '') or '').strip(),
            'worker_interview': str(c_map.get('R', '') or '').strip(),
            'findings': f_list
        })

    total_score = round(sum(it['score'] for it in checklist_evaluated), 2)
    if isinstance(total_score, float) and total_score.is_integer():
        total_score = int(total_score)

    counts = {
        'Conformance': sum(1 for it in checklist_evaluated if it['significance'] == 'Conformance'),
        'Minor': sum(1 for it in checklist_evaluated if it['significance'] == 'Minor'),
        'Major': sum(1 for it in checklist_evaluated if it['significance'] == 'Major'),
        'Priority': sum(1 for it in checklist_evaluated if it['significance'] == 'Priority'),
        'N/A': sum(1 for it in checklist_evaluated if it['significance'] == 'N/A'),
    }
    violated_items_count = counts['Minor'] + counts['Major'] + counts['Priority']
    mandatory_count = counts['Priority']
    penalty_violation_count = sum(1 for it in checklist_evaluated if it['penalty_violation'] == 'X')

    g_thresh = checklist_ref.get('grade_thresholds', {'A': 90, 'B': 80, 'C': 70, 'D': 0})
    if total_score >= g_thresh.get('A', 90):
        grade_level = "A"
    elif total_score >= g_thresh.get('B', 80):
        grade_level = "B"
    elif total_score >= g_thresh.get('C', 70):
        grade_level = "C"
    else:
        grade_level = "D"

    summary_6_cats = build_summary_6_categories(checklist_evaluated, checklist_ref.get('category_groups'))

    doc_violations, facility_violations_top = select_top_violations(
        findings, checklist_evaluated, max_per_type=3, max_total=5
    )

    code_to_sig = {it['audit_id']: it['significance'] for it in checklist_evaluated}
    key_issues_candidates = []
    for sig_order in ('Priority', 'Major', 'Minor'):
        for f_obj in findings:
            if code_to_sig.get(f_obj['audit_id']) == sig_order:
                key_issues_candidates.append({
                    'no': f_obj['no'],
                    'excel_row': f_obj['excel_row'],
                    'audit_id': f_obj['audit_id'],
                    'significance': sig_order,
                    'issue_vn': f_obj['issue_vn'],
                    'photos': f_obj['photos']
                })
                if len(key_issues_candidates) >= 5:
                    break
        if len(key_issues_candidates) >= 5:
            break

    main_proc = g_val(12, 'Assembly')
    sub_info = g_val(29, '')
    sub_cnt = 0 if sub_info in ('', '0', 'Không', 'None', 'No') else 1

    result_data = {
        'source_type': 'checklist',
        'metadata': {
            'subsidiary': 'SEV/T',
            'gbm': 'Mobile',
            'vendor_raw': f"{vendor_short} ({vendor_code_chk})" if vendor_code_chk else vendor_short,
            'vendor_short': vendor_short,
            'vendor_full': vendor_full,
            'vendor_code': vendor_code_chk,
            'address': g_val(4, ''),
            'audit_criteria': g_val(5, 'RBA 8.0.1') or 'RBA 8.0.1',
            'audit_type': g_val(8, ''),
            'audit_date_raw': audit_date_raw,
            'cav_date_serial': _int_or_blank(d11_raw) if d11_raw else '',
            'report_date': audit_date_raw.replace('-', '/'),
            'auditor_raw': auditor_raw,
            'auditor_1': auditor_1,
            'auditor_2': auditor_2,
            'auditor_short': auditor_1 or auditor_raw,
            'main_process': main_proc,
            'main_process_vn': main_proc,
            'product': g_val(13, main_proc),
            'ceo_name': g_val(14, ''),
            'ceo_position': g_val(15, 'CEO'),
            'ceo_phone': g_val(16, ''),
            'ceo_email': g_val(17, ''),
            'contact_name': g_val(18, ''),
            'contact_position': g_val(19, ''),
            'contact_phone': g_val(20, ''),
            'contact_email': g_val(21, ''),
            'total_workers': g_int(22, 0),
            'permanent_workers': g_int(23, 0),
            'temp_workers': g_int(24, 0),
            'foreign_workers': g_int(25, 0),
            'juvenile_workers': _int_or_blank(g_val(26, '')) if g_val(26, '') != '' else '',
            'child_workers': _int_or_blank(g_val(27, '')) if g_val(27, '') != '' else '',
            'intern_workers': _int_or_blank(g_val(28, '')) if g_val(28, '') != '' else '',
            'subcontract_info': sub_info,
            'subcontract_count': sub_cnt,
            'dormitory': g_val(30, ''),
            'cafeteria': g_val(31, ''),
            'samsung_Revenue_ratio': '100%',
            'certifications': g_val(32, ''),
            'legal_violation': g_val(33, ''),
            'legal_violation_desc': g_val(34, ''),
            'interview_count': g_int(35, 0),
        },
        'summary': {
            'total_findings': len(findings),
            'total_items': len(checklist_evaluated),
            'violated_items_count': violated_items_count,
            'mandatory_count': mandatory_count,
            'penalty_violation_count': penalty_violation_count,
            'total_score': total_score,
            'grade_level': grade_level,
            'counts': counts,
            'compliance_rate': round((counts['Conformance'] / len(checklist_evaluated)) * 100, 2) if checklist_evaluated else 0,
            'category_breakdown': summary_6_cats,
            'audit_warnings': audit_warnings
        },
        'findings': findings,
        'checklist': checklist_evaluated,
        'doc_violations': doc_violations,
        'facility_violations': facility_violations_top,
        'key_issues': key_issues_candidates
    }
    result_data['qa_report'] = run_qa_checks(result_data)
    return result_data


def parse_findings_xlsm(xlsm_path=DEFAULT_FINDINGS_PATH, checklist_ref=None):
    """
    Parses the source EHS Audit Findings (.xlsm / .xlsx) file OR automatically routes
    to parse_checklist_xlsx() if the uploaded file is an RBA Audit Checklist (.xlsx).
    Raises ValueError with a clear Vietnamese message if the file matches neither format.
    """
    if checklist_ref is None:
        checklist_ref = load_checklist_reference()

    try:
        z_test = zipfile.ZipFile(xlsm_path, 'r')
    except Exception:
        raise ValueError("Tệp tải lên không phải là tệp Excel (.xlsx / .xlsm) hợp lệ!")

    with z_test as z:
        shared_strings = []
        if 'xl/sharedStrings.xml' in z.namelist():
            ss_xml = ET.fromstring(z.read('xl/sharedStrings.xml'))
            for si in ss_xml.findall(f'{XL_NS}si'):
                texts = [t.text or '' for t in si.iter(f'{XL_NS}t')]
                shared_strings.append(''.join(texts))

        def get_cell_val(c_el):
            if c_el is None:
                return ""
            c_type = c_el.attrib.get('t')
            v_el = c_el.find(f'{XL_NS}v')
            is_el = c_el.find(f'{XL_NS}is')
            if c_type == 's' and v_el is not None and v_el.text is not None:
                idx = int(v_el.text)
                return shared_strings[idx] if idx < len(shared_strings) else v_el.text
            elif c_type == 'inlineStr' and is_el is not None:
                return ''.join([t.text or '' for t in is_el.iter(f'{XL_NS}t')])
            elif v_el is not None and v_el.text is not None:
                return v_el.text
            return ""

        # Inspect workbook sheets to distinguish Findings vs Checklist vs Invalid file
        sheet_map = []  # [(sheet_name_lower, sheet_path)]
        if 'xl/workbook.xml' in z.namelist() and 'xl/_rels/workbook.xml.rels' in z.namelist():
            wb_xml = ET.fromstring(z.read('xl/workbook.xml'))
            wb_rels = ET.fromstring(z.read('xl/_rels/workbook.xml.rels'))
            rid_to_target = {r.attrib['Id']: r.attrib['Target'] for r in wb_rels}
            for sh in wb_xml.iter(f'{XL_NS}sheet'):
                sh_name = sh.attrib.get('name', '').strip().lower()
                rid = sh.attrib.get(f'{REL_NS}id', '')
                t_path = rid_to_target.get(rid, '')
                if not t_path.startswith('xl/'):
                    t_path = 'xl/' + t_path.lstrip('/')
                if t_path in z.namelist():
                    sheet_map.append((sh_name, t_path))

        finding_sheet_path = None
        checklist_sheet_path = None
        for sh_name, t_path in sheet_map:
            if 'finding' in sh_name:
                finding_sheet_path = t_path
                break
            if sh_name == 'checklist':
                checklist_sheet_path = t_path

        # If workbook is an RBA Audit Checklist (has 'Checklist' sheet and no 'Findings' sheet), delegate!
        if not finding_sheet_path and checklist_sheet_path:
            return parse_checklist_xlsx(xlsm_path, checklist_ref)

        # Map embedded images in Findings sheet (xl/drawings/drawing1.xml)
        row_images = {}
        if 'xl/drawings/drawing1.xml' in z.namelist() and 'xl/drawings/_rels/drawing1.xml.rels' in z.namelist():
            d_xml = ET.fromstring(z.read('xl/drawings/drawing1.xml'))
            d_rels = ET.fromstring(z.read('xl/drawings/_rels/drawing1.xml.rels'))
            rid_map = {r.attrib['Id']: r.attrib['Target'] for r in d_rels}
            anchors = d_xml.findall(f'{XDR_NS}twoCellAnchor') + d_xml.findall(f'{XDR_NS}oneCellAnchor')
            for anc in anchors:
                fr = anc.find(f'{XDR_NS}from')
                if fr is not None:
                    col_idx = int(fr.find(f'{XDR_NS}col').text)
                    row_idx = int(fr.find(f'{XDR_NS}row').text) + 1  # 1-based Excel row
                    blip = anc.find(f'.//{A_NS}blip')
                    rid = blip.attrib.get(f'{REL_NS}embed') if blip is not None else None
                    target = rid_map.get(rid, '')
                    if target.startswith('../'):
                        media_path = 'xl/' + target[3:]
                    elif not target.startswith('xl/'):
                        media_path = 'xl/drawings/' + target
                    else:
                        media_path = target
                    if media_path in z.namelist():
                        row_images.setdefault(row_idx, []).append((col_idx, media_path))

        for r_k in row_images:
            row_images[r_k].sort(key=lambda x: x[0])

        target_sheet_path = finding_sheet_path
        if not target_sheet_path:
            ws_files = [n for n in z.namelist() if n.startswith('xl/worksheets/sheet') and n.endswith('.xml')]
            if ws_files:
                target_sheet_path = sorted(ws_files)[-1]
        if not target_sheet_path or target_sheet_path not in z.namelist():
            raise ValueError("Tệp Excel không có trang tính hợp lệ!")

        sh_xml = ET.fromstring(z.read(target_sheet_path))
        rows_by_num = {}
        for row in sh_xml.findall(f'.//{XL_NS}row'):
            r_num = int(row.attrib.get('r', 0))
            c_map = {}
            for c in row.findall(f'{XL_NS}c'):
                col = ''.join([ch for ch in c.attrib.get('r', '') if ch.isalpha()])
                c_map[col] = get_cell_val(c)
            rows_by_num[r_num] = c_map

        # Auto-detect if this sheet is actually an RBA Checklist sheet (Col B = BH101..CM403 on rows 5..45)
        valid_codes = {it['audit_id'] for it in checklist_ref['items']}
        col_b_codes = sum(1 for r in range(5, 46) if rows_by_num.get(r, {}).get('B', '').strip().upper() in valid_codes)
        if col_b_codes >= 20:
            return parse_checklist_xlsx(xlsm_path, checklist_ref)

        # Validate that this is a genuine EHS Audit Findings sheet
        hdr_row = rows_by_num.get(6, {})
        has_findings_header = ('audit id' in hdr_row.get('D', '').lower() or 'point of issue' in hdr_row.get('G', '').lower())
        valid_col_d_count = sum(
            1 for r, cm in rows_by_num.items()
            if r >= 7 and not normalize_audit_id(cm.get('D', ''), cm.get('E', ''), cm.get('B', ''), checklist_ref['items'])[2]
        )
        if not finding_sheet_path and not has_findings_header and valid_col_d_count == 0:
            raise ValueError(
                "Tệp Excel tải lên không đúng định dạng 'EHS Audit Findings (.xlsm/.xlsx)' hoặc 'RBA Audit Checklist (.xlsx)'. "
                "Vui lòng kiểm tra lại cấu trúc tệp (cần có sheet 'Findings' hoặc 'Checklist' chuẩn RBA 8.0.1)!"
            )

        # Extract metadata (Rows 1-4)
        subsidiary = rows_by_num.get(1, {}).get('C', '').strip()
        vendor_raw = rows_by_num.get(2, {}).get('C', '').strip()
        audit_date_raw = normalize_audit_date(rows_by_num.get(3, {}).get('C', ''))
        auditor_raw = rows_by_num.get(4, {}).get('C', '').strip()

        m_v = re.match(r'^(.+?)\s*\(([^)]+)\)\s*$', vendor_raw)
        if m_v:
            vendor_short = m_v.group(1).strip()
            vendor_code = m_v.group(2).strip()
        else:
            vendor_short = vendor_raw
            vendor_code = ""

        auditors = [a.strip() for a in auditor_raw.split(',') if a.strip()]
        auditor_1 = auditors[0] if auditors else ""
        auditor_2 = ", ".join(auditors[1:]) if len(auditors) > 1 else ""

        findings = []
        audit_warnings = []
        for r_num in sorted(rows_by_num.keys()):
            if r_num < 7:
                continue
            c_map = rows_by_num[r_num]
            raw_audit_id = c_map.get('D', '').strip()
            issue_raw = c_map.get('G', '').strip()
            # Forms may pre-list all 41 codes: only a written statement is a finding
            if not issue_raw:
                if row_images.get(r_num) or c_map.get('I', '').strip():
                    audit_warnings.append(f"Dòng Excel {r_num}: có ảnh hoặc cờ mandatory nhưng chưa có nội dung nhận định (cột G) nên chưa được tính.")
                continue
            if _tm_key(issue_raw) in FORM_PLACEHOLDERS:
                audit_warnings.append(f"Dòng Excel {r_num}: còn nội dung mẫu '{issue_raw}' của biểu mẫu nên không tính là nhận định.")
                continue

            sub_cat_raw = c_map.get('E', '').strip()
            prov_raw = c_map.get('B', '').strip()
            norm_id, recovered, warn_msg = normalize_audit_id(
                raw_audit_id, sub_cat_raw, prov_raw, checklist_ref['items']
            )
            if warn_msg:
                audit_warnings.append(f"Dòng Excel {r_num}: {warn_msg}")

            loc_en, loc_vn, loc_full = split_bilingual(c_map.get('F', ''))
            iss_en, iss_vn, iss_full = split_bilingual(issue_raw)
            imp_en, imp_vn, imp_full = split_bilingual(c_map.get('M', ''))

            imgs_info = []
            for col_idx, media_path in row_images.get(r_num, []):
                ext = os.path.splitext(media_path)[1].lower().lstrip('.')
                mime = 'image/jpeg' if ext in ('jpg', 'jpeg') else 'image/png'
                raw_bytes = z.read(media_path)
                b64 = base64.b64encode(raw_bytes).decode('ascii')
                imgs_info.append({
                    'col': col_idx,
                    'media_path': media_path,
                    'data_url': f"data:{mime};base64,{b64}"
                })

            try:
                no_val = int(float(c_map.get('A', len(findings) + 1)))
            except (ValueError, TypeError):
                no_val = len(findings) + 1

            # Check if Column R (A score) or Column S (Evaluation Point) has an explicit grade
            eval_grade = c_map.get('R', '').strip() or c_map.get('S', '').strip()

            findings.append({
                'excel_row': r_num,
                'no': no_val,
                'provision': prov_raw,
                'category': c_map.get('C', '').strip(),
                'audit_id': norm_id,
                'raw_audit_id': raw_audit_id,
                'was_recovered': recovered,
                'sub_category': sub_cat_raw,
                'location_full': loc_full,
                'location_en': loc_en,
                'location_vn': loc_vn,
                'issue_full': iss_full,
                'issue_en': iss_en,
                'issue_vn': iss_vn,
                'cause': c_map.get('H', 'facility').strip(),
                'mandatory': c_map.get('I', '').strip(),
                'eval_grade': eval_grade,
                'improvement_full': imp_full,
                'improvement_en': imp_en,
                'improvement_vn': imp_vn,
                'improvement_date': _excel_serial_to_date(c_map.get('N', '')),
                'complete_date': _excel_serial_to_date(c_map.get('Q', '')),
                # Columns I..M = problem photos; N..P = post-improvement photos
                'photos': [im for im in imgs_info if im['col'] <= 12],
                'after_photos': [im for im in imgs_info if im['col'] >= 13]
            })

    no_vn = [str(f['no']) for f in findings if f['issue_vn'] == f['issue_en'] and not is_vietnamese_text(f['issue_vn'])]
    if no_vn:
        audit_warnings.append(
            f"{len(no_vn)} nhận định chưa có bản tiếng Việt (#{', #'.join(no_vn)}): báo cáo giữ nguyên câu gốc. "
            "Vui lòng nhập bản dịch ở tab Chấm điểm và kiểm tra lại mức độ lỗi vì từ khóa phân loại là tiếng Việt."
        )

    # Group findings by canonical Audit ID
    findings_by_code = {}
    for f in findings:
        findings_by_code.setdefault(f['audit_id'], []).append(f)

    # Evaluate all 41 Checklist items using the Master Rules & VLOOKUP DB
    checklist_evaluated = []
    mand_triggers = checklist_ref.get('mandatory_triggers', ['mandatory', 'bắt buộc', 'hmbb', 'x', 'yes', '1'])
    for item in checklist_ref['items']:
        code = item['audit_id']
        f_list = findings_by_code.get(code, [])
        sig, reason = auto_classify_significance(
            code, f_list, item['criteria_vn'], item['criteria_en'],
            custom_rule=item.get('rule'), mandatory_triggers=mand_triggers
        )
        score = item['scores'].get(sig, 0)
        pen_viol = compute_penalty_violation(item['penalty_item'], item['penalty_criteria'], sig)

        if not f_list:
            evidence_text = "1:\n2:\n3:"
        elif len(f_list) == 1:
            evidence_text = f_list[0]['issue_full']
        else:
            lines = []
            for idx, f_obj in enumerate(f_list, 1):
                lines.append(f"{idx}. {f_obj['issue_full']}")
            evidence_text = "\n".join(lines)

        has_facility = any(f['cause'].lower() == 'facility' for f in f_list)
        site_obs = "O" if (not f_list or has_facility) else ""
        rec_rev = "O"

        checklist_evaluated.append({
            'row_num': item['row_num'],
            'provision': item['provision'],
            'audit_id': code,
            'sub_category': item['sub_category'],
            'finding_count': len(f_list),
            'significance': sig,
            'auto_significance': sig,
            'auto_reason': reason,
            'violation_mark': "X" if sig not in ("Conformance", "N/A") else "",
            'penalty_item': item['penalty_item'],
            'penalty_criteria': item['penalty_criteria'],
            'penalty_violation': pen_viol,
            'score': score,
            'scores_table': item['scores'],
            'rule': item.get('rule', RBA_801_RULE_MATRIX.get(code, {})),
            'evidence_text': evidence_text,
            'criteria_vn': item['criteria_vn'],
            'criteria_en': item['criteria_en'],
            'site_observation': site_obs,
            'record_review': rec_rev,
            'findings': f_list
        })

    # Compute summary metrics with exact rounding
    total_score = round(sum(it['score'] for it in checklist_evaluated), 2)
    if isinstance(total_score, float) and total_score.is_integer():
        total_score = int(total_score)

    counts = {
        'Conformance': sum(1 for it in checklist_evaluated if it['significance'] == 'Conformance'),
        'Minor': sum(1 for it in checklist_evaluated if it['significance'] == 'Minor'),
        'Major': sum(1 for it in checklist_evaluated if it['significance'] == 'Major'),
        'Priority': sum(1 for it in checklist_evaluated if it['significance'] == 'Priority'),
        'N/A': sum(1 for it in checklist_evaluated if it['significance'] == 'N/A'),
    }
    violated_items_count = counts['Minor'] + counts['Major'] + counts['Priority']
    mandatory_count = sum(1 for f in findings if f['mandatory'].strip().lower() in tuple(t.lower() for t in mand_triggers))
    penalty_violation_count = sum(1 for it in checklist_evaluated if it['penalty_violation'] == 'X')

    g_thresh = checklist_ref.get('grade_thresholds', {'A': 90, 'B': 80, 'C': 70, 'D': 0})
    if total_score >= g_thresh.get('A', 90):
        grade_level = "A"
    elif total_score >= g_thresh.get('B', 80):
        grade_level = "B"
    elif total_score >= g_thresh.get('C', 70):
        grade_level = "C"
    else:
        grade_level = "D"

    summary_6_cats = build_summary_6_categories(checklist_evaluated, checklist_ref.get('category_groups'))

    doc_violations, facility_violations_top = select_top_violations(
        findings, checklist_evaluated, max_per_type=3, max_total=5
    )

    code_to_sig = {it['audit_id']: it['significance'] for it in checklist_evaluated}
    key_issues_candidates = []
    used_nos = set()
    for sig_order in ('Priority', 'Major', 'Minor'):
        for f_obj in findings:
            if len(key_issues_candidates) < 5 and f_obj['no'] not in used_nos and f_obj['photos'] and code_to_sig.get(f_obj['audit_id']) == sig_order:
                key_issues_candidates.append({
                    'no': f_obj['no'],
                    'excel_row': f_obj['excel_row'],
                    'audit_id': f_obj['audit_id'],
                    'significance': sig_order,
                    'issue_vn': f_obj['issue_vn'],
                    'photos': f_obj['photos']
                })
                used_nos.add(f_obj['no'])

    # The checklist template stores its own vendor's profile: it must not reach another vendor's report
    is_template_vendor = 'YOUSUNG' in vendor_short.upper()
    profile = checklist_ref['general_info_defaults'] if is_template_vendor else {}

    result_data = {
        'metadata': {
            'subsidiary': subsidiary,
            'gbm': 'Mobile',
            'vendor_raw': vendor_raw,
            'vendor_short': vendor_short,
            'vendor_full': profile.get('D3', vendor_short),
            'vendor_code': vendor_code,
            'address': profile.get('D4', ''),
            'audit_criteria': 'RBA 8.0.1',
            'audit_date_raw': audit_date_raw,
            'report_date': today_report_date(),
            'auditor_raw': auditor_raw,
            'auditor_1': auditor_1,
            'auditor_2': auditor_2,
            'auditor_short': "Mr Nam, Mr Lanh, Mr Biên" if is_template_vendor and "Nam" in auditor_raw else auditor_raw,
            'main_process': profile.get('D12', ''),
            'main_process_vn': 'Lắp ráp' if is_template_vendor else '',
            'product': profile.get('D13', ''),
            'ceo_name': profile.get('D14', ''),
            'ceo_position': profile.get('D15', ''),
            'ceo_phone': profile.get('D16', ''),
            'ceo_email': profile.get('D17', ''),
            'contact_name': profile.get('D18', ''),
            'contact_position': profile.get('D19', ''),
            'contact_phone': profile.get('D20', ''),
            'contact_email': profile.get('D21', ''),
            'total_workers': _int_or_blank(profile.get('D22')),
            'permanent_workers': _int_or_blank(profile.get('D23')),
            'temp_workers': _int_or_blank(profile.get('D24')),
            'foreign_workers': _int_or_blank(profile.get('D25')),
            'subcontract_info': profile.get('D29', ''),
            'subcontract_count': 1 if is_template_vendor else '',
            'samsung_Revenue_ratio': '100%' if is_template_vendor else '',
            'certifications': profile.get('D32', ''),
            'interview_count': _int_or_blank(profile.get('D35')),
        },
        'summary': {
            'total_findings': len(findings),
            'total_items': len(checklist_evaluated),
            'violated_items_count': violated_items_count,
            'mandatory_count': mandatory_count,
            'penalty_violation_count': penalty_violation_count,
            'total_score': total_score,
            'grade_level': grade_level,
            'counts': counts,
            'compliance_rate': round((counts['Conformance'] / len(checklist_evaluated)) * 100, 2) if checklist_evaluated else 0,
            'category_breakdown': summary_6_cats,
            'audit_warnings': audit_warnings
        },
        'findings': findings,
        'checklist': checklist_evaluated,
        'doc_violations': doc_violations,
        'facility_violations': facility_violations_top,
        'key_issues': key_issues_candidates
    }
    result_data['qa_report'] = run_qa_checks(result_data)
    return result_data


def _col_to_num(col_str):
    num = 0
    for ch in col_str:
        if ch.isalpha():
            num = num * 26 + (ord(ch.upper()) - ord('A') + 1)
    return num


def set_xlsx_cell_value(row_el, col_letter, row_num, val, is_formula=False, formula_str=None, is_number=False):
    """
    Updates or creates a cell <c r="col+row"> in an openpyxl/OpenXML worksheet row element
    in strict ascending column order, preserving 100% of existing styles (s attribute).
    """
    c_ref = f"{col_letter}{row_num}"
    target_c = None
    target_col_idx = _col_to_num(col_letter)
    existing_cells = row_el.findall(f'{XL_NS}c')
    insert_idx = len(existing_cells)
    for i, c in enumerate(existing_cells):
        r_attr = c.attrib.get('r', '')
        if r_attr == c_ref:
            target_c = c
            break
        c_col = ''.join([ch for ch in r_attr if ch.isalpha()])
        if _col_to_num(c_col) > target_col_idx and insert_idx == len(existing_cells):
            insert_idx = i

    if target_c is None:
        target_c = ET.Element(f'{XL_NS}c', {'r': c_ref})
        row_el.insert(insert_idx, target_c)

    for child in list(target_c):
        target_c.remove(child)

    if is_formula and formula_str is not None:
        if isinstance(val, (int, float)):
            if 't' in target_c.attrib:
                del target_c.attrib['t']
        else:
            target_c.attrib['t'] = 'str'
        f_el = ET.SubElement(target_c, f'{XL_NS}f')
        f_el.text = formula_str
        v_el = ET.SubElement(target_c, f'{XL_NS}v')
        v_el.text = str(val) if val is not None else ""
    elif is_number or isinstance(val, (int, float)):
        if 't' in target_c.attrib:
            del target_c.attrib['t']
        v_el = ET.SubElement(target_c, f'{XL_NS}v')
        v_el.text = str(val)
    else:
        target_c.attrib['t'] = 'inlineStr'
        is_el = ET.SubElement(target_c, f'{XL_NS}is')
        t_el = ET.SubElement(is_el, f'{XL_NS}t')
        if val and ('\n' in str(val) or str(val).startswith(' ') or str(val).endswith(' ')):
            t_el.attrib['{http://www.w3.org/XML/1998/namespace}space'] = 'preserve'
        t_el.text = str(val) if val is not None else ""


def generate_checklist_xlsx(parsed_data, output_path, template_path=DEFAULT_CHECKLIST_TEMPLATE, lang_mode=None):
    """
    Generates the filled RBA Audit Checklist (.xlsx) file from parsed_data
    while preserving 100% of the template's formatting, styles, formulas, and sheets.
    Supports optional `lang_mode` ('vi_ko', 'vi_en', 'vi_zh', 'vi').
    """
    if lang_mode:
        from translator import apply_export_lang_to_data
        parsed_data = apply_export_lang_to_data(parsed_data, lang_mode)

    meta = parsed_data['metadata']
    summary = parsed_data['summary']
    checklist_items = {it['row_num']: it for it in parsed_data['checklist']}
    is_yousung = 'YOUSUNG' in str(meta.get('vendor_short', '')).upper()

    with zipfile.ZipFile(template_path, 'r') as zin:
        sheet1_xml = ET.fromstring(zin.read('xl/worksheets/sheet1.xml'))
        sheet2_xml = ET.fromstring(zin.read('xl/worksheets/sheet2.xml'))

        # 1. Update Sheet 1: General Information
        s1_rows = {int(r.attrib.get('r', 0)): r for r in sheet1_xml.findall(f'.//{XL_NS}row')}
        gen_updates = {
            3: (meta.get('vendor_full', 'Công ty TNHH You Sung Vina' if is_yousung else ''), False),
            4: (meta.get('address', ''), False),
            5: (meta.get('audit_criteria', 'RBA 8.0.1'), False),
            6: (meta.get('auditor_1', ''), False),
            7: (meta.get('auditor_2', ''), False),
            12: (meta.get('main_process', 'Assembly'), False),
            13: (meta.get('product', 'Linh kiện điện thoại' if is_yousung else meta.get('main_process', '')), False),
            14: (meta.get('ceo_name', ''), False),
            15: (meta.get('ceo_position', 'CEO'), False),
            16: (meta.get('ceo_phone', ''), False),
            17: (meta.get('ceo_email', ''), False),
            18: (meta.get('contact_name', ''), False),
            19: (meta.get('contact_position', ''), False),
            20: (meta.get('contact_phone', ''), False),
            21: (meta.get('contact_email', ''), False),
            22: (_int_or_blank(meta.get('total_workers')), True),
            23: (_int_or_blank(meta.get('permanent_workers')), True),
            24: (_int_or_blank(meta.get('temp_workers')), True),
            25: (_int_or_blank(meta.get('foreign_workers')), True),
            29: (meta.get('subcontract_info', ''), False),
            32: (meta.get('certifications', ''), False),
            35: (_int_or_blank(meta.get('interview_count')), True),
        }
        if meta.get('audit_type'):
            gen_updates[8] = (meta['audit_type'], False)
        audit_days = _audit_day_serials(meta)
        gen_updates[9] = (audit_days[0] if audit_days else '', True)
        gen_updates[10] = (audit_days[-1] if audit_days else '', True)
        if meta.get('cav_date_serial') not in (None, ''):
            gen_updates[11] = (_int_or_blank(meta.get('cav_date_serial')), True)
        elif not is_yousung:
            gen_updates[11] = ('', False)

        extra_fields = (
            (26, 'juvenile_workers', True),
            (27, 'child_workers', True),
            (28, 'intern_workers', True),
            (30, 'dormitory', False),
            (31, 'cafeteria', False),
            (33, 'legal_violation', False),
            (34, 'legal_violation_desc', False),
        )
        for r_idx, m_key, is_num in extra_fields:
            val = meta.get(m_key)
            if val not in (None, ''):
                gen_updates[r_idx] = (_int_or_blank(val) if is_num else str(val), is_num)
            elif not is_yousung:
                gen_updates[r_idx] = ('', False)

        for r_idx, (val, is_num) in gen_updates.items():
            if r_idx in s1_rows:
                set_xlsx_cell_value(s1_rows[r_idx], 'D', r_idx, val, is_number=is_num and val != '')

        counts = summary['counts']
        if 36 in s1_rows:
            set_xlsx_cell_value(s1_rows[36], 'D', 36, summary['total_score'], is_formula=True, formula_str="Checklist!D2")
        if 37 in s1_rows:
            set_xlsx_cell_value(s1_rows[37], 'D', 37, counts['Conformance'], is_formula=True, formula_str="COUNTIF(Checklist!$D$5:$D$45,'General Information'!C37)")
        if 38 in s1_rows:
            set_xlsx_cell_value(s1_rows[38], 'D', 38, counts['Minor'], is_formula=True, formula_str="COUNTIF(Checklist!$D$5:$D$45,'General Information'!C38)")
        if 39 in s1_rows:
            set_xlsx_cell_value(s1_rows[39], 'D', 39, counts['Major'], is_formula=True, formula_str="COUNTIF(Checklist!$D$5:$D$45,'General Information'!C39)")
        if 40 in s1_rows:
            set_xlsx_cell_value(s1_rows[40], 'D', 40, counts['Priority'], is_formula=True, formula_str="COUNTIF(Checklist!$D$5:$D$45,'General Information'!C40)")
        if 41 in s1_rows:
            set_xlsx_cell_value(s1_rows[41], 'D', 41, counts['N/A'], is_formula=True, formula_str="COUNTIF(Checklist!$D$5:$D$45,'General Information'!C41)")
        if 42 in s1_rows:
            set_xlsx_cell_value(s1_rows[42], 'D', 42, summary['total_items'], is_formula=True, formula_str="SUM(D37:D41)")

        # 2. Update Sheet 2: Checklist
        s2_rows = {int(r.attrib.get('r', 0)): r for r in sheet2_xml.findall(f'.//{XL_NS}row')}
        if 1 in s2_rows:
            set_xlsx_cell_value(s2_rows[1], 'B', 1, "YOUSUNG VINA" if meta.get('vendor_short', '').upper() == 'YOUSUNG' else meta.get('vendor_short', ''))
            set_xlsx_cell_value(s2_rows[1], 'D', 1, meta.get('audit_date_raw', '').replace(',', '&'))
            set_xlsx_cell_value(s2_rows[1], 'J', 1, counts['Priority'], is_formula=True, formula_str='COUNTIF($D$5:$D$45,"Priority")')
        if 2 in s2_rows:
            raw_vcode = str(meta.get('vendor_code') or '').strip()
            vcode = '' if raw_vcode in ('', 'N/A') else raw_vcode
            if not vcode and is_yousung:
                vcode = 'L10PO5'
            set_xlsx_cell_value(s2_rows[2], 'B', 2, vcode)
            set_xlsx_cell_value(s2_rows[2], 'D', 2, summary['total_score'], is_formula=True, formula_str='SUMIFS($T$5:$T$45,$S$5:$S$45,"EHS")')
            set_xlsx_cell_value(s2_rows[2], 'J', 2, summary.get('penalty_violation_count', 0), is_formula=True, formula_str='COUNTIF($H$5:$H$45,"X")')
        if 3 in s2_rows:
            set_xlsx_cell_value(s2_rows[3], 'C', 3, summary['violated_items_count'], is_formula=True, formula_str='SUBTOTAL(3,$C$5:$C$45)')

        for r_num, item in checklist_items.items():
            if r_num not in s2_rows:
                continue
            r_el = s2_rows[r_num]
            sig = item['significance']
            viol_mark = "X" if sig not in ("Conformance", "N/A") else ""
            pen_mark = compute_penalty_violation(item.get('penalty_item', ''), item.get('penalty_criteria', ''), sig)

            set_xlsx_cell_value(r_el, 'D', r_num, sig)
            set_xlsx_cell_value(
                r_el, 'E', r_num, viol_mark,
                is_formula=True,
                formula_str=f'IF(AND(D{r_num}<>"Conformance", D{r_num}<>"N/A"),"X","")'
            )
            set_xlsx_cell_value(
                r_el, 'H', r_num, pen_mark,
                is_formula=True,
                formula_str=f'IF(AND(F{r_num}="X",G{r_num}=D{r_num}),"X",IF(AND(F{r_num}="X",G{r_num}="Major", D{r_num}="Priority"),"X",""))'
            )
            set_xlsx_cell_value(r_el, 'L', r_num, item['evidence_text'])
            for obs_col, obs_key in (('O', 'site_observation'), ('P', 'record_review'), ('Q', 'mgmt_interview'), ('R', 'worker_interview')):
                if obs_key in item:
                    set_xlsx_cell_value(r_el, obs_col, r_num, item.get(obs_key, '') or '')
            set_xlsx_cell_value(
                r_el, 'T', r_num, item['score'],
                is_formula=True,
                formula_str=f'VLOOKUP(B{r_num}&D{r_num}&S{r_num},Table!$D:$E,2,0)'
            )

        ct_xml = ET.fromstring(zin.read('[Content_Types].xml'))
        for ov in list(ct_xml):
            if ov.attrib.get('PartName') == '/xl/calcChain.xml':
                ct_xml.remove(ov)
        wb_rels_xml = ET.fromstring(zin.read('xl/_rels/workbook.xml.rels'))
        for rel in list(wb_rels_xml):
            if 'calcChain.xml' in rel.attrib.get('Target', ''):
                wb_rels_xml.remove(rel)

        # All reads of zin come first: writestr() below alters zin's entries in place
        edited_parts = {
            'xl/worksheets/sheet1.xml': sheet1_xml,
            'xl/worksheets/sheet2.xml': sheet2_xml,
            '[Content_Types].xml': ct_xml,
            'xl/_rels/workbook.xml.rels': wb_rels_xml,
            'xl/sharedStrings.xml': _scrubbed_shared_strings(zin, sheet1_xml, sheet2_xml),
        }
        part_bytes = {name: _office_xml(root_el, zin.read(name)) for name, root_el in edited_parts.items()}
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zout:
            for member in zin.infolist():
                if member.filename == 'xl/calcChain.xml':
                    continue
                zout.writestr(member, part_bytes.get(member.filename) or zin.read(member.filename))

    return output_path


def _findings_sheet_parts(z):
    """Paths of the Findings worksheet and of its drawing (None without photos) inside a workbook."""
    wb_xml = ET.fromstring(z.read('xl/workbook.xml'))
    wb_rels = {r.attrib['Id']: r.attrib['Target'] for r in ET.fromstring(z.read('xl/_rels/workbook.xml.rels'))}
    sheet_path = None
    for sh in wb_xml.iter(f'{XL_NS}sheet'):
        if 'finding' in sh.attrib.get('name', '').lower():
            target = wb_rels.get(sh.attrib.get(f'{REL_NS}id'), '')
            sheet_path = target.lstrip('/') if target.startswith('/') else 'xl/' + target
    if sheet_path not in z.namelist():
        raise ValueError('Tệp không có sheet Findings.')
    rels_path = f"{os.path.dirname(sheet_path)}/_rels/{os.path.basename(sheet_path)}.rels"
    if rels_path in z.namelist():
        for rel in ET.fromstring(z.read(rels_path)):
            if rel.attrib.get('Type', '').endswith('/drawing'):
                return sheet_path, os.path.normpath(os.path.join(os.path.dirname(sheet_path), rel.attrib['Target']))
    return sheet_path, None


def generate_findings_file(parsed_data, source_path, output_path, lang_mode=None):
    """
    Writes the clean Findings workbook from the uploaded/combined file, in the layout auditors use:
    one row per real finding (photos move with their rows), formatted according to `lang_mode`
    ('vi_ko', 'vi_en', 'vi_zh', 'vi') when provided, or legacy English+Vietnamese when None.
    """
    if lang_mode:
        from translator import apply_export_lang_to_data
        parsed_data = apply_export_lang_to_data(parsed_data, lang_mode)

    findings = {f['excel_row']: f for f in parsed_data.get('findings', [])}
    meta = parsed_data.get('metadata') or {}
    with zipfile.ZipFile(source_path, 'r') as zin:
        sheet_path, drawing_path = _findings_sheet_parts(zin)
        sheet_xml = ET.fromstring(zin.read(sheet_path))
        sheet_data = sheet_xml.find(f'{XL_NS}sheetData')
        rows = {int(r.attrib['r']): r for r in sheet_data.findall(f'{XL_NS}row')}
        drawing_xml = ET.fromstring(zin.read(drawing_path)) if drawing_path else None
        anchors = [] if drawing_xml is None else drawing_xml.findall(f'{XDR_NS}twoCellAnchor') + drawing_xml.findall(f'{XDR_NS}oneCellAnchor')
        photo_rows = {int(a.find(f'{XDR_NS}from/{XDR_NS}row').text) + 1 for a in anchors}

        keep = sorted(r for r in rows if r >= 7 and (r in findings or r in photo_rows))
        new_row = {old: 7 + i for i, old in enumerate(keep)}
        for r_num, row_el in rows.items():
            if r_num >= 7:
                sheet_data.remove(row_el)
        for old in keep:
            row_el, num = rows[old], new_row[old]
            row_el.attrib['r'] = str(num)
            for c in row_el.findall(f'{XL_NS}c'):
                c.attrib['r'] = ''.join(ch for ch in c.attrib['r'] if ch.isalpha()) + str(num)
            sheet_data.append(row_el)
            set_xlsx_cell_value(row_el, 'A', num, num - 6, is_number=True)
            f = findings.get(old)
            if f:
                no, code = f.get('no'), f.get('audit_id')
                if 'export_issue_cell' in f:
                    set_xlsx_cell_value(row_el, 'F', num, f.get('export_location_cell', ''))
                    set_xlsx_cell_value(row_el, 'G', num, f.get('export_issue_cell', ''))
                    set_xlsx_cell_value(row_el, 'M', num, f.get('export_improvement_cell', ''))
                else:
                    plan_en, plan_vn = f.get('improvement_en', ''), f.get('improvement_vn', '')
                    if not (plan_en or plan_vn):
                        plan_en, plan_vn = draft_improvement_plan(f.get('issue_en', ''))
                    set_xlsx_cell_value(row_el, 'F', num, findings_cell_text(f.get('location_en', ''), f.get('location_vn', ''), 'location', no, code))
                    set_xlsx_cell_value(row_el, 'G', num, findings_cell_text(f.get('issue_en', ''), f.get('issue_vn', ''), 'issue', no, code))
                    set_xlsx_cell_value(row_el, 'M', num, findings_cell_text(plan_en, plan_vn, 'improvement', no, code))

        # Keep header metadata rows 1-4 synchronized with workspace metadata
        if 1 in rows and meta.get('subsidiary'):
            set_xlsx_cell_value(rows[1], 'C', 1, meta['subsidiary'])
        if 2 in rows and meta.get('vendor_short'):
            vc = str(meta.get('vendor_code') or '').strip()
            v_disp = f"{meta['vendor_short']} ({vc})" if vc and vc != 'N/A' else meta['vendor_short']
            set_xlsx_cell_value(rows[2], 'C', 2, v_disp)
        if 3 in rows and meta.get('audit_date_raw'):
            set_xlsx_cell_value(rows[3], 'C', 3, meta['audit_date_raw'])
        if 4 in rows and (meta.get('auditor_raw') or meta.get('auditor_short')):
            set_xlsx_cell_value(rows[4], 'C', 4, meta.get('auditor_raw') or meta.get('auditor_short'))

        last = max(7, 6 + len(keep))
        dimension, auto_filter = sheet_xml.find(f'{XL_NS}dimension'), sheet_xml.find(f'{XL_NS}autoFilter')
        for el in (dimension, auto_filter):
            if el is not None:
                el.attrib['ref'] = re.sub(r'\d+$', str(last), el.attrib['ref'])
        for a in anchors:
            start = a.find(f'{XDR_NS}from/{XDR_NS}row')
            end = a.find(f'{XDR_NS}to/{XDR_NS}row')
            delta = new_row.get(int(start.text) + 1, int(start.text) + 1) - (int(start.text) + 1)
            start.text = str(int(start.text) + delta)
            if end is not None:
                end.text = str(int(end.text) + delta)

        # Summary counts come from Findings: drop its stored results and ensure COUNTIF covers all rows
        edited = {sheet_path: sheet_xml}
        if drawing_path:
            edited[drawing_path] = drawing_xml
        cap_row = max(150, last + 10)
        missing_summary_formulas = {
            **{f'E{r}': f'+C{r}-D{r}' for r in range(5, 11)},
            **{f'F{r}': f'+E{r}/C{r}' for r in range(5, 11)},
            'F11': '+E11/C11',
        }
        for name in zin.namelist():
            if name.startswith('xl/worksheets/sheet') and name.endswith('.xml') and name != sheet_path:
                raw_other = zin.read(name)
                other = ET.fromstring(raw_other)
                is_summary_sh = b'Findings!' in raw_other
                for c in other.iter(f'{XL_NS}c'):
                    ref = c.attrib.get('r', '')
                    f_el = c.find(f'{XL_NS}f')
                    v_el = c.find(f'{XL_NS}v')
                    if is_summary_sh and f_el is None and ref in missing_summary_formulas:
                        f_el = ET.Element(f'{XL_NS}f')
                        f_el.text = missing_summary_formulas[ref]
                        c.insert(0, f_el)
                    if f_el is not None:
                        if f_el.text and 'Findings!' in f_el.text:
                            f_el.text = re.sub(
                                r'(Findings!\$[A-Z]+\$7:\$?[A-Z]+\$?)(\d+)',
                                lambda m: f"{m.group(1)}{max(int(m.group(2)), cap_row)}",
                                f_el.text,
                            )
                        if v_el is not None:
                            c.remove(v_el)
                            c.attrib.pop('t', None)
                edited[name] = other
        ct_xml = ET.fromstring(zin.read('[Content_Types].xml'))
        for el in list(ct_xml):
            if el.attrib.get('PartName') == '/xl/calcChain.xml':
                ct_xml.remove(el)
        wb_rels_xml = ET.fromstring(zin.read('xl/_rels/workbook.xml.rels'))
        for el in list(wb_rels_xml):
            if el.attrib.get('Target', '').endswith('calcChain.xml'):
                wb_rels_xml.remove(el)
        edited['[Content_Types].xml'] = ct_xml
        edited['xl/_rels/workbook.xml.rels'] = wb_rels_xml
        part_bytes = {name: _office_xml(root_el, zin.read(name)) for name, root_el in edited.items()}
        wb_text = zin.read('xl/workbook.xml').decode('utf-8').replace('<calcPr ', '<calcPr fullCalcOnLoad="1" ')
        part_bytes['xl/workbook.xml'] = re.sub(
            r'(_xlnm\._FilterDatabase"[^>]*>[^<]*\$)\d+(</definedName>)', rf'\g<1>{last}\g<2>', wb_text).encode('utf-8')

        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zout:
            for member in zin.infolist():
                if member.filename == 'xl/calcChain.xml':
                    continue
                zout.writestr(member, part_bytes.get(member.filename) or zin.read(member.filename))
    return output_path


def _office_xml(root_el, template_bytes):
    """
    Serializes an edited Office part with the template's own namespace prefixes. ElementTree
    otherwise writes ns0, ns1... and declares only the prefixes it sees used, while mc:Ignorable
    and mc:Choice name prefixes as plain text: Word and Excel then treat the file as damaged.
    """
    template_text = template_bytes.decode('utf-8')
    src_head = re.search(r'<[\w:]+\s[^>]*xmlns[^>]*>', template_text).group(0)
    declared = dict(re.findall(r'xmlns:(\w+)="([^"]+)"', template_text)).items()
    default_ns = re.search(r'\sxmlns="([^"]+)"', src_head)
    for prefix, uri in declared:
        ET.register_namespace(prefix, uri)
    if default_ns:
        ET.register_namespace('', default_ns.group(1))
    head, rest = ET.tostring(root_el, encoding='unicode').split('>', 1)
    for prefix, uri in declared:
        if f'xmlns:{prefix}=' not in head:
            head += f' xmlns:{prefix}="{uri}"'
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n' + head + '>' + rest).encode('utf-8')


def _scrubbed_shared_strings(zin, *edited_sheets):
    """
    Empties shared strings no cell uses any more. Filled cells are written inline, so the
    template vendor's details would otherwise stay readable inside every generated file.
    """
    sheets = list(edited_sheets)
    edited = {'xl/worksheets/sheet1.xml', 'xl/worksheets/sheet2.xml'}
    for name in zin.namelist():
        if name.startswith('xl/worksheets/sheet') and name.endswith('.xml') and name not in edited:
            sheets.append(ET.fromstring(zin.read(name)))
    used = set()
    for sheet in sheets:
        for c in sheet.iter(f'{XL_NS}c'):
            v_el = c.find(f'{XL_NS}v')
            if c.attrib.get('t') == 's' and v_el is not None and v_el.text is not None:
                used.add(int(v_el.text))
    sst = ET.fromstring(zin.read('xl/sharedStrings.xml'))
    for idx, si in enumerate(sst.findall(f'{XL_NS}si')):
        if idx not in used:
            for child in list(si):
                si.remove(child)
            ET.SubElement(si, f'{XL_NS}t')
    return sst


def audit_period(meta):
    """Returns (year, yyyymmdd) from the audit date text, e.g. '21-04-2026 , 22-04-2026' -> ('2026', '20260422')."""
    raw = str((meta or {}).get('audit_date_raw', '') or '')
    dates = re.findall(r'(\d{1,2})[-/.](\d{1,2})[-/.](\d{4})', raw)
    if dates:
        d, m, y = dates[-1]
        return y, f"{y}{int(m):02d}{int(d):02d}"
    ys = re.findall(r'(20\d{2})', raw)
    now = datetime.datetime.now()
    y = ys[-1] if ys else str(now.year)
    return y, now.strftime('%Y%m%d') if not ys else f"{y}0101"


def report_title(meta, round_no=1):
    year, _ = audit_period(meta)
    return f"Kết quả đánh giá định kỳ RBA 8.0.1 Lần {round_no}.{year}"


def normalize_audit_date(raw):
    """"'26.02.26" (year first, as typed in the Findings form) -> "26/02/2026"; other text stays as written."""
    s = str(raw or '').strip()
    m = re.fullmatch(r"'(\d{2})[-./](\d{2})[-./](\d{2})", s)
    return f"{m.group(3)}/{m.group(2)}/20{m.group(1)}" if m else s.lstrip("'")


def today_report_date():
    now = datetime.datetime.now()
    day = 'Chủ nhật' if now.weekday() == 6 else f'Thứ {now.weekday() + 2}'
    return f"{now.strftime('%d/%m/%Y')} ({day})"


def _int_or_blank(val):
    try:
        return int(float(val))
    except (TypeError, ValueError):
        return ''


def _audit_day_serials(meta):
    """Excel date serials of the days in the audit date text."""
    serials = []
    for d, m, y in re.findall(r'(\d{1,2})[-/.](\d{1,2})[-/.](\d{4})', str((meta or {}).get('audit_date_raw', ''))):
        try:
            serials.append((datetime.date(int(y), int(m), int(d)) - datetime.date(1899, 12, 30)).days)
        except ValueError:
            pass
    return serials


def partner_profile(meta):
    """'(Lắp ráp/ 900 người/ tỷ trọng giao dịch vs Samsung: 100%)' from the values actually known."""
    workers = _int_or_blank(meta.get('total_workers'))
    ratio = meta.get('samsung_Revenue_ratio')
    parts = [meta.get('main_process_vn'), f"{workers} người" if workers else '',
             f"tỷ trọng giao dịch vs Samsung: {ratio}" if ratio else '']
    parts = [p for p in parts if p]
    return f"({'/ '.join(parts)})" if parts else ''


def workforce_note(meta):
    """'* NLĐ nước ngoài 4 người,  Vendor Sub contract: 1' from the values actually known."""
    foreign, subcontract = _int_or_blank(meta.get('foreign_workers')), _int_or_blank(meta.get('subcontract_count'))
    parts = [f"NLĐ nước ngoài {foreign} người" if foreign else '', f"Vendor Sub contract: {subcontract}" if subcontract else '']
    parts = [p for p in parts if p]
    return '* ' + ',  '.join(parts) if parts else ''


ASSESSMENT_AREAS = {'Safety': 'an toàn', 'Firefighting': 'PCCC', 'Chemical': 'hóa chất',
                    'Safety System': 'hệ thống quản lý an toàn', 'Environment': 'môi trường',
                    'Environment System': 'hệ thống quản lý môi trường'}


def overall_assessment(parsed_data):
    """The one-line conclusion of section 2, built from this report's violated items."""
    violated = [f for it in parsed_data.get('checklist', []) if it.get('significance') in ('Priority', 'Major', 'Minor')
                for f in it.get('findings', [])]
    if not violated:
        return "Không phát hiện điểm không phù hợp trong đợt đánh giá này."
    causes = {str(f.get('cause', '')).strip().lower() for f in violated}
    aspects = [label for key, label in (('facility', 'hiện trường'), ('administrative', 'tài liệu')) if key in causes]
    areas = []
    for f in violated:
        area = ASSESSMENT_AREAS.get(re.sub(r'\s+', ' ', str(f.get('category', ''))).strip())
        if area and area not in areas:
            areas.append(area)
    text = "Công ty cần cải thiện các điểm"
    if aspects:
        text += f" về mặt {' và '.join(aspects)}"
    if areas:
        text += " liên quan đến " + (f"{', '.join(areas[:-1])} và {areas[-1]}" if len(areas) > 1 else areas[0])
    return text + "."


def _set_paragraph_text_legacy(p_el, new_text):
    """Fallback for paragraphs that contain no text runs at all."""
    runs = p_el.findall(f'{W_NS}r')
    first_rpr = None
    for r in runs:
        if r.find(f'.//{W_NS}drawing') is None:
            rpr = r.find(f'{W_NS}rPr')
            if rpr is not None:
                first_rpr = copy.deepcopy(rpr)
                break
    new_r = ET.SubElement(p_el, f'{W_NS}r')
    if first_rpr is not None:
        new_r.append(first_rpr)
    t_el = ET.SubElement(new_r, f'{W_NS}t')
    t_el.attrib['{http://www.w3.org/XML/1998/namespace}space'] = 'preserve'
    t_el.text = new_text


def _apply_run_multiline_and_cjk_font(p_el):
    """Splits any '\\n' inside <w:t> into <w:br/> within its run and sets w:eastAsia font for Hangul/CJK."""
    for r in p_el.iter(f'{W_NS}r'):
        if r.find(f'.//{W_NS}drawing') is not None:
            continue
        full_r = ''.join(t.text or '' for t in r.findall(f'{W_NS}t'))
        if re.search(r'[\uac00-\ud7af\u4e00-\u9fff]', full_r):
            ea_font = 'Malgun Gothic' if re.search(r'[\uac00-\ud7af]', full_r) else 'Microsoft YaHei'
            rpr = r.find(f'{W_NS}rPr')
            if rpr is None:
                rpr = ET.Element(f'{W_NS}rPr')
                r.insert(0, rpr)
            rf = rpr.find(f'{W_NS}rFonts')
            if rf is None:
                rf = ET.SubElement(rpr, f'{W_NS}rFonts')
            rf.attrib[f'{W_NS}eastAsia'] = ea_font
        for t in list(r.findall(f'{W_NS}t')):
            txt = t.text or ''
            if '\n' in txt:
                idx = list(r).index(t)
                r.remove(t)
                segs = txt.split('\n')
                for s_i, seg in enumerate(segs):
                    if s_i > 0:
                        r.insert(idx, ET.Element(f'{W_NS}br'))
                        idx += 1
                    nt = ET.Element(f'{W_NS}t')
                    if seg != seg.strip() or '  ' in seg:
                        nt.attrib['{http://www.w3.org/XML/1998/namespace}space'] = 'preserve'
                    nt.text = seg
                    r.insert(idx, nt)
                    idx += 1


def _set_paragraph_text_preserve_rpr(p_el, new_text):
    """
    Replaces the visible text of a Word paragraph while preserving 100% of the template
    formatting (font, size, bold, colour, highlight, underline) and run order (logos/drawings).

    Only the part of the text that actually differs is rewritten: the common prefix and suffix
    stay in their original runs, and the changed middle segment is written into the run where
    the difference starts — so e.g. '[Priority]' keeps its red colour and '64 điểm' stays bold.
    """
    new_text = new_text or ''
    t_nodes = []
    for r in p_el.iter(f'{W_NS}r'):
        if r.find(f'.//{W_NS}drawing') is not None:
            continue
        t_nodes.extend(r.findall(f'{W_NS}t'))
    if not t_nodes:
        _set_paragraph_text_legacy(p_el, new_text)
        _apply_run_multiline_and_cjk_font(p_el)
        return

    old_text = ''.join(t.text or '' for t in t_nodes)
    if old_text == new_text and '\n' not in new_text:
        return

    i = 0
    max_pre = min(len(old_text), len(new_text))
    while i < max_pre and old_text[i] == new_text[i]:
        i += 1
    j = 0
    while j < min(len(old_text) - i, len(new_text) - i) and old_text[-1 - j] == new_text[-1 - j]:
        j += 1
    del_start, del_end = i, len(old_text) - j
    insert_txt = new_text[i:len(new_text) - j]

    # Pick the run that receives the inserted text: the run containing del_start
    # (or the last non-empty run when appending at the very end).
    pos = 0
    target_idx = None
    for idx, t in enumerate(t_nodes):
        L = len(t.text or '')
        if pos <= del_start < pos + L:
            target_idx = idx
            break
        pos += L
    if target_idx is None:
        non_empty = [k for k, t in enumerate(t_nodes) if t.text]
        target_idx = non_empty[-1] if non_empty else len(t_nodes) - 1

    pos = 0
    for idx, t in enumerate(t_nodes):
        txt = t.text or ''
        L = len(txt)
        a = max(0, min(L, del_start - pos))
        b = max(a, min(L, del_end - pos))
        new_seg = txt[:a] + (insert_txt if idx == target_idx else '') + txt[b:]
        if idx == target_idx and not (pos <= del_start <= pos + L):
            # appending after the end of this run
            new_seg = txt[:a] + txt[b:] + insert_txt
        t.text = new_seg
        if new_seg != new_seg.strip() or '  ' in new_seg:
            t.attrib['{http://www.w3.org/XML/1998/namespace}space'] = 'preserve'
        pos += L

    _apply_run_multiline_and_cjk_font(p_el)


def _excel_serial_to_date(val):
    s_val = str(val or '').strip()
    if not s_val:
        return ''
    try:
        num = float(s_val)
        if 20000 < num < 80000:
            d = datetime.datetime(1899, 12, 30) + datetime.timedelta(days=int(num))
            return d.strftime('%d/%m/%Y')
    except ValueError:
        pass
    return s_val


def _insert_round2_into_docx(body, tbl1, result_para, r1_summary, r2_summary, gbm):
    """
    Section '1. Khái quát' of the round-2 report: keeps the round-1 result table and inserts a
    round-2 result table (identical template formatting) right below it for comparison.
    """
    _set_paragraph_text_preserve_rpr(result_para, f" □ Kết quả lần 1: Tổng {r1_summary['total_score']} điểm")
    r2_para = copy.deepcopy(result_para)
    delta = round(float(r2_summary['total_score']) - float(r1_summary['total_score']), 2)
    delta_txt = (f"+{delta:g}" if delta >= 0 else f"{delta:g}")
    _set_paragraph_text_preserve_rpr(
        r2_para, f" □ Kết quả lần 2 (đánh giá lại): Tổng {r2_summary['total_score']} điểm ({delta_txt} điểm so với lần 1)"
    )
    r2_tbl = copy.deepcopy(tbl1)
    rows = r2_tbl.findall(f'{W_NS}tr')
    if len(rows) >= 3:
        c2 = r2_summary['counts']
        vals = [
            f"{gbm} (Lần 2)",
            str(c2['Priority']), str(c2['Major']), str(c2['Minor']),
            f"{r2_summary['violated_items_count']} items/HMBB: {r2_summary['mandatory_count']}",
            f"{r2_summary['total_score']} điểm",
            r2_summary['grade_level'],
        ]
        for c_idx, tc in enumerate(rows[2].findall(f'{W_NS}tc')):
            if c_idx < len(vals):
                p_el = tc.find(f'{W_NS}p')
                if p_el is not None:
                    _set_paragraph_text_preserve_rpr(p_el, vals[c_idx])
    # Label the round-1 table's GBM cell
    r1_rows = tbl1.findall(f'{W_NS}tr')
    if len(r1_rows) >= 3:
        first_tc = r1_rows[2].find(f'{W_NS}tc')
        p_el = first_tc.find(f'{W_NS}p') if first_tc is not None else None
        if p_el is not None:
            _set_paragraph_text_preserve_rpr(p_el, f"{gbm} (Lần 1)")
    pos = list(body).index(tbl1) + 1
    spacer = ET.Element(f'{W_NS}p')
    body.insert(pos, spacer)
    body.insert(pos + 1, r2_para)
    body.insert(pos + 2, r2_tbl)


def generate_summary_docx(parsed_data, output_path, template_path=DEFAULT_DOCX_TEMPLATE, source_xlsm_path=DEFAULT_FINDINGS_PATH, round2_summary=None, round_no=None, lang_mode=None):
    """
    Generates the filled Word Executive Summary Report (.docx) from parsed_data.
    Supports optional `lang_mode` ('vi_ko', 'vi_en', 'vi_zh', 'vi').
    """
    if lang_mode:
        from translator import apply_export_lang_to_data
        parsed_data = apply_export_lang_to_data(parsed_data, lang_mode)

    meta = parsed_data['metadata']
    summary = parsed_data['summary']
    counts = summary['counts']

    with zipfile.ZipFile(template_path, 'r') as zin:
        doc_xml = ET.fromstring(zin.read('word/document.xml'))
        body = doc_xml.find(f'{W_NS}body')
        body_children = list(body)

        _set_paragraph_text_preserve_rpr(body_children[0], report_title(meta, round_no or (2 if round2_summary else 1)))
        _set_paragraph_text_preserve_rpr(body_children[1], f"đối tác ({meta.get('vendor_short', '')})")
        _set_paragraph_text_preserve_rpr(body_children[2], f"                                                                   {meta.get('report_date', '')}")
        note = workforce_note(meta)
        if not note:  # an empty text box would print as a bare dashed frame
            for child in list(body_children[3]):
                if next(child.iter(f'{W_NS}txbxContent'), None) is not None:
                    body_children[3].remove(child)
        _set_paragraph_text_preserve_rpr(
            body_children[3],
            f"{note or ' ' * 50}                                                  Samsung Vietnam EHS"
        )
        for box in body_children[3].iter(f'{W_NS}txbxContent'):
            for p_el in box.iter(f'{W_NS}p'):
                _set_paragraph_text_preserve_rpr(p_el, note)
        _set_paragraph_text_preserve_rpr(
            body_children[5],
            f" □ Tên đối tác: {meta.get('vendor_short', '')}{' ' * max(4, 60 - len(meta.get('vendor_short', '')) - len(partner_profile(meta)))}{partner_profile(meta)}"
        )
        audit_date, auditors = meta.get('audit_date_raw', ''), meta.get('auditor_short', '')
        _set_paragraph_text_preserve_rpr(
            body_children[6],
            f" □ Ngày kiểm tra: {audit_date}{' ' * max(4, 60 - len(audit_date) - len(auditors))}* Người kiểm tra: {auditors}"
        )
        _set_paragraph_text_preserve_rpr(body_children[7], f" □ Kết quả: Tổng {summary['total_score']} điểm")

        tbl1 = body_children[9]
        result_para = body_children[7]
        tbl1_rows = tbl1.findall(f'{W_NS}tr')
        if len(tbl1_rows) >= 3:
            r2_cells = tbl1_rows[2].findall(f'{W_NS}tc')
            t1_vals = [
                meta.get('gbm', 'Mobile'),
                str(counts['Priority']),
                str(counts['Major']),
                str(counts['Minor']),
                f"{summary['violated_items_count']} items/HMBB: {summary['mandatory_count']}",
                f"{summary['total_score']} điểm",
                summary['grade_level']
            ]
            for c_idx, val_str in enumerate(t1_vals):
                if c_idx < len(r2_cells):
                    p_el = r2_cells[c_idx].find(f'{W_NS}p')
                    if p_el is not None:
                        _set_paragraph_text_preserve_rpr(p_el, val_str)

        # The template's conclusion sits in a text box, so look inside nested paragraphs too
        overall_txt = parsed_data.get('export_overall') or overall_assessment(parsed_data)
        for p_el in body.iter(f'{W_NS}p'):
            if 'Công ty cần cải thiện' in ''.join(t.text or '' for t in p_el.iter(f'{W_NS}t')) and not list(p_el.iter(f'{W_NS}txbxContent')):
                _set_paragraph_text_preserve_rpr(p_el, overall_txt)

        idx_doc_hdr = None
        idx_fac_hdr = None
        idx_sec3_hdr = None
        for idx, el in enumerate(list(body)):
            if el.tag == f'{W_NS}p':
                txt = ''.join([t.text or '' for t in el.iter(f'{W_NS}t')])
                if 'Lỗi vi phạm Tài liệu' in txt:
                    idx_doc_hdr = idx
                elif 'Lỗi vi phạm Hiện trường' in txt:
                    idx_fac_hdr = idx
                elif '3. Kế hoạch sau này' in txt:
                    idx_sec3_hdr = idx

        if idx_doc_hdr is not None and idx_fac_hdr is not None and idx_sec3_hdr is not None:
            doc_bullet_proto = copy.deepcopy(list(body)[idx_doc_hdr + 1])
            fac_bullet_proto = copy.deepcopy(list(body)[idx_fac_hdr + 1])
            fac_hdr_el = copy.deepcopy(list(body)[idx_fac_hdr])
            sec3_hdr_el = list(body)[idx_sec3_hdr]

            current_children = list(body)
            for el in current_children[idx_doc_hdr + 1:idx_sec3_hdr]:
                body.remove(el)

            if 'doc_violations_export' in parsed_data or 'facility_violations_export' in parsed_data:
                doc_capped = parsed_data.get('doc_violations_export', [])
                fac_capped = parsed_data.get('facility_violations_export', [])
            else:
                doc_capped, fac_capped = cap_violations_pair(
                    parsed_data.get('doc_violations', []),
                    parsed_data.get('facility_violations', []),
                    max_per_type=3, max_total=5
                )
            insert_pos = list(body).index(current_children[idx_doc_hdr]) + 1
            for d_txt in doc_capped:
                new_p = copy.deepcopy(doc_bullet_proto)
                _set_paragraph_text_preserve_rpr(new_p, d_txt)
                body.insert(insert_pos, new_p)
                insert_pos += 1

            body.insert(insert_pos, fac_hdr_el)
            insert_pos += 1

            for f_txt in fac_capped:
                new_p = copy.deepcopy(fac_bullet_proto)
                _set_paragraph_text_preserve_rpr(new_p, f_txt)
                body.insert(insert_pos, new_p)
                insert_pos += 1

            # Ensure Section 3 ("3. Kế hoạch sau này") has exact required lines & year
            year_str, _ = audit_period(meta)
            sec3_idx = list(body).index(sec3_hdr_el)
            _set_paragraph_text_preserve_rpr(sec3_hdr_el, "  3. Kế hoạch sau này")
            body_after_sec3 = list(body)[sec3_idx + 1:]
            if len(body_after_sec3) >= 3:
                _set_paragraph_text_preserve_rpr(
                    body_after_sec3[0],
                    "□ Theo dõi tình hình cải tiến của đối tác                                         ~ hàng tuần"
                )
                _set_paragraph_text_preserve_rpr(
                    body_after_sec3[1],
                    "     -  Triển khai đốc thúc, theo dõi tiến độ và hướng dẫn cải tiến"
                )
                # The attachment list is one floating text box (plus its fallback copy): only the year changes
                for box in body_after_sec3[2].iter(f'{W_NS}txbxContent'):
                    for p_el in box.iter(f'{W_NS}p'):
                        line = ''.join(t.text or '' for t in p_el.iter(f'{W_NS}t'))
                        _set_paragraph_text_preserve_rpr(p_el, re.sub(r'RBA\.\d{4}', f'RBA.{year_str}', line))
            # Remove empty spacer paragraphs so the entire report stays strictly <= 2 pages
            for p_cand in list(body):
                if p_cand.tag == f'{W_NS}p':
                    p_txt = ''.join(t.text or '' for t in p_cand.iter(f'{W_NS}t')).strip()
                    has_draw = p_cand.find(f'.//{W_NS}drawing') is not None
                    has_sect = p_cand.find(f'.//{W_NS}sectPr') is not None
                    if not p_txt and not has_draw and not has_sect:
                        body.remove(p_cand)

        all_tbls = body.findall(f'{W_NS}tbl')
        tbl3 = all_tbls[2]
        t3_rows = tbl3.findall(f'{W_NS}tr')
        header_tr = copy.deepcopy(t3_rows[0])
        proto_single_tr = copy.deepcopy(t3_rows[1])
        proto_restart_tr = copy.deepcopy(t3_rows[2])
        proto_continue_tr = copy.deepcopy(t3_rows[3])
        footer_tr = copy.deepcopy(t3_rows[-1])

        for tr in list(t3_rows):
            tbl3.remove(tr)
        tbl3.append(header_tr)

        def build_t3_row(proto_tr, col0_lines, findings_vn_list, code_str):
            tr = copy.deepcopy(proto_tr)
            tcs = tr.findall(f'{W_NS}tc')
            if col0_lines is not None and len(tcs) >= 1:
                tc0 = tcs[0]
                p0s = tc0.findall(f'{W_NS}p')
                p0_proto = copy.deepcopy(p0s[0])
                for p in p0s:
                    tc0.remove(p)
                for ln in col0_lines:
                    np = copy.deepcopy(p0_proto)
                    _set_paragraph_text_preserve_rpr(np, ln)
                    tc0.append(np)
            if len(tcs) >= 2:
                tc1 = tcs[1]
                p1s = tc1.findall(f'{W_NS}p')
                p1_proto = copy.deepcopy(p1s[0])
                for p in p1s:
                    tc1.remove(p)
                for f_vn in findings_vn_list:
                    np = copy.deepcopy(p1_proto)
                    _set_paragraph_text_preserve_rpr(np, f"- {f_vn}")
                    tc1.append(np)
            if len(tcs) >= 3:
                tc2 = tcs[2]
                p2 = tc2.find(f'{W_NS}p')
                if p2 is not None:
                    _set_paragraph_text_preserve_rpr(p2, code_str)
            return tr

        for sev in ('Priority', 'Major', 'Minor'):
            sev_items = [it for it in parsed_data['checklist'] if it['significance'] == sev]
            sev_count = len(sev_items)
            for idx, it in enumerate(sev_items):
                if 'export_t3_lines' in it:
                    vn_list = it['export_t3_lines']
                else:
                    vn_list = [_compact_violation_text(f['issue_vn'], 140) for f in it['findings'][:2]]
                    if len(it['findings']) > 2:
                        vn_list[-1] = vn_list[-1].rstrip('.') + "..."
                    if not vn_list:
                        ev_fallback = _extract_checklist_evidence_lines(it.get('evidence_text', ''))
                        vn_list = [_compact_violation_text(ev_fallback[0], 140)] if ev_fallback else [it.get('sub_category') or it['audit_id']]

                if sev_count == 1 and sev == 'Priority':
                    tr_new = build_t3_row(proto_single_tr, [sev, f"({sev_count})"], vn_list, it['audit_id'])
                elif idx == 0:
                    tr_new = build_t3_row(proto_restart_tr, [sev, f"({sev_count:02d})" if sev_count < 10 and sev != 'Priority' else f"({sev_count})"], vn_list, it['audit_id'])
                else:
                    tr_new = build_t3_row(proto_continue_tr, None, vn_list, it['audit_id'])
                tbl3.append(tr_new)

        if len(tbl3.findall(f'{W_NS}tr')) == 1:
            tbl3.append(build_t3_row(proto_single_tr, ['—'], [parsed_data.get('empty_t3_text', 'Không có lỗi vi phạm')], '—'))
        tbl3.append(footer_tr)

        tbl4 = all_tbls[3]
        t4_rows = tbl4.findall(f'{W_NS}tr')
        key_issues = parsed_data.get('key_issues', [])[:5]
        new_media = []  # (rel_id, target, bytes)
        xlsm_zip = zipfile.ZipFile(source_xlsm_path, 'r') if source_xlsm_path and os.path.exists(source_xlsm_path) else None

        def _photo_bytes(ph):
            du = str(ph.get('data_url', ''))
            if du.startswith('data:'):
                head, b64 = du.split(',', 1)
                return base64.b64decode(b64), ('jpeg' if ('jpeg' in head or 'jpg' in head) else 'png')
            mp = ph.get('media_path')
            if xlsm_zip is not None and mp and mp in xlsm_zip.namelist():
                ext = os.path.splitext(mp)[1].lower().lstrip('.')
                return xlsm_zip.read(mp), ('jpeg' if ext in ('jpg', 'jpeg') else (ext or 'png'))
            return None, None

        def _remove_drawings(tr_el):
            for p_el in tr_el.iter(f'{W_NS}p'):
                for r_el in list(p_el.findall(f'{W_NS}r')):
                    if r_el.find(f'.//{W_NS}drawing') is not None:
                        p_el.remove(r_el)

        keep_rows = max(len(key_issues), 1)
        for r_i, tr in enumerate(t4_rows):
            if r_i >= keep_rows:
                tbl4.remove(tr)
                continue
            # Dashed frames the template's author drew on that vendor's photos mark nothing on new ones
            for p_el in tr.iter(f'{W_NS}p'):
                for r_el in list(p_el.findall(f'{W_NS}r')):
                    if r_el.find(f'{MC_NS}AlternateContent') is not None:
                        p_el.remove(r_el)
            ki = key_issues[r_i] if r_i < len(key_issues) else None
            tcs = tr.findall(f'{W_NS}tc')
            if len(tcs) >= 2:
                ps = tcs[1].findall(f'{W_NS}p')
                if ki:
                    ki_txt = ki.get('export_issue_text') or ki['issue_vn'].replace('\n', ' ')
                    if len(ps) >= 2:
                        _set_paragraph_text_preserve_rpr(ps[0], f"[{ki['significance']}] ")
                        _set_paragraph_text_preserve_rpr(ps[1], ki_txt)
                    elif len(ps) == 1:
                        _set_paragraph_text_preserve_rpr(ps[0], f"[{ki['significance']}] {ki_txt}")
                else:
                    empty_txt = parsed_data.get('empty_key_issue_text', 'Không có vấn đề tồn đọng')
                    if len(ps) >= 2:
                        _set_paragraph_text_preserve_rpr(ps[0], '')
                        _set_paragraph_text_preserve_rpr(ps[1], empty_txt)
                    elif len(ps) == 1:
                        _set_paragraph_text_preserve_rpr(ps[0], empty_txt)
            photos = (ki or {}).get('photos') or []
            img_bytes, ext = _photo_bytes(photos[0]) if photos else (None, None)
            blips = list(tr.iter(f'{A_NS}blip'))
            if img_bytes and blips:
                rid = f"rIdRBA{len(new_media) + 1}"
                target = f"media/rba_photo_{len(new_media) + 1}.{ext}"
                new_media.append((rid, target, img_bytes))
                for b in blips:
                    b.attrib[f'{REL_NS}embed'] = rid
            else:
                _remove_drawings(tr)

        if xlsm_zip is not None:
            xlsm_zip.close()

        if round2_summary:
            _insert_round2_into_docx(body, tbl1, result_para, summary, round2_summary, meta.get('gbm', 'Mobile'))

        doc_bytes = _office_xml(doc_xml, zin.read('word/document.xml'))
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zout:
            for member in zin.infolist():
                if member.filename == 'word/document.xml':
                    zout.writestr(member, doc_bytes)
                elif member.filename == 'word/_rels/document.xml.rels' and new_media:
                    rels_txt = zin.read(member.filename).decode('utf-8')
                    add = ''.join(
                        f'<Relationship Id="{rid}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="{tg}"/>'
                        for rid, tg, _ in new_media)
                    zout.writestr(member, rels_txt.replace('</Relationships>', add + '</Relationships>'))
                elif member.filename == '[Content_Types].xml' and new_media:
                    ct_txt = zin.read(member.filename).decode('utf-8')
                    for ext_name, mime in (('jpeg', 'image/jpeg'), ('png', 'image/png')):
                        if f'Extension="{ext_name}"' not in ct_txt and any(tg.endswith('.' + ext_name) for _, tg, _ in new_media):
                            ct_txt = ct_txt.replace('<Default ', f'<Default Extension="{ext_name}" ContentType="{mime}"/><Default ', 1)
                    zout.writestr(member, ct_txt)
                else:
                    zout.writestr(member, zin.read(member.filename))
            for rid, tg, data_bytes in new_media:
                zout.writestr('word/' + tg, data_bytes)

    return output_path


if __name__ == '__main__':
    print("Testing Upgraded 41-Item RBA Audit Automation Engine...")
    data = parse_findings_xlsm()
    print("Summary:", json.dumps(data['summary'], ensure_ascii=False, indent=2))
    out_xlsx = os.path.join(OUTPUT_DIR, "20260422_YOUSUNG VINA_RBA Audit checklist_AUTO.xlsx")
    out_docx = os.path.join(OUTPUT_DIR, "20260422_YOUSUNG_Tóm tắt kết quả đánh giá định kỳ RBA 8.0_AUTO.docx")
    generate_checklist_xlsx(data, out_xlsx)
    generate_summary_docx(data, out_docx)
    print("Generated:", out_xlsx)
    print("Generated:", out_docx)
