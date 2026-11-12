"""
Ghép & chuẩn hóa 2 nguồn dữ liệu đánh giá RBA 8.0.1:
  - File hiện trường (field -> cause mặc định: 'facility')
  - File tài liệu (doc   -> cause mặc định: 'Administrative')

Mỗi ô có thể nhận:
  1) Biểu mẫu 'EHS Audit Findings (.xlsm/.xlsx)' (có/không có ảnh hiện trường)
  2) Biểu mẫu 'RBA Audit Checklist (.xlsx)' (form báo cáo tài liệu 41 hạng mục)

Kết quả luôn tạo ra MỘT workbook chuẩn 'EHS Audit Findings (.xlsm/.xlsx)' hoàn chỉnh:
  - Giữ toàn bộ ảnh nhúng (neo đúng dòng nhận định hiện trường).
  - Nối toàn bộ nhận định từ File tài liệu & File hiện trường, đánh lại số thứ tự cột A liên tục.
  - Điền mặc định cột H (cause: facility / Administrative), cột I (Mandatory cho lỗi Priority),
    và tự động dự thảo kế hoạch cải tiến cột M khi nguồn là RBA Audit Checklist.
  - Trả kèm `info['checklist_data']` và `info['row_slots']` để `server.py` hợp nhất chính xác
    thông tin chung (General Information) và kết quả chấm điểm 41 hạng mục.
© NGUYỄN NGỌC NGÔN — RBA 8.0.1 EHS Automation Suite
"""
import os
import posixpath
import re
import tempfile
import xml.etree.ElementTree as ET
import zipfile

from engine import (
    A_NS,
    DEFAULT_FINDINGS_PATH,
    REL_NS,
    XDR_NS,
    XL_NS,
    _office_xml,
    load_checklist_reference,
    parse_checklist_xlsx,
    set_xlsx_cell_value,
)
from translator import auto_draft_improvement_vn

PKG_REL_NS = '{http://schemas.openxmlformats.org/package/2006/relationships}'
CT_NS = '{http://schemas.openxmlformats.org/package/2006/content-types}'
DRAWING_REL = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships/drawing'
IMAGE_REL = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships/image'
DEFAULT_CAUSE = {'field': 'facility', 'doc': 'Administrative'}
SLOT_LABEL = {'field': 'File hiện trường', 'doc': 'File tài liệu'}
IMG_CTYPES = {
    'png': 'image/png', 'jpeg': 'image/jpeg', 'jpg': 'image/jpeg', 'gif': 'image/gif',
    'emf': 'image/x-emf', 'wmf': 'image/x-wmf', 'bmp': 'image/bmp', 'tiff': 'image/tiff', 'webp': 'image/webp',
}

# Standard cell style indices on Row 7 of DEFAULT_FINDINGS_PATH
ROW7_STYLES = {
    'A': '3', 'B': '65', 'C': '6', 'D': '4', 'E': '66', 'F': '64', 'G': '28',
    'H': '37', 'I': '38', 'J': '3', 'K': '3', 'L': '1', 'M': '64', 'N': '2',
    'O': '1', 'P': '1', 'Q': '1', 'R': '1', 'S': '1',
}
ALL_COLS = ('A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S')

# Order of worksheet children after which <drawing> must be inserted (OOXML schema order)
_BEFORE_DRAWING = (
    'sheetPr', 'dimension', 'sheetViews', 'sheetFormatPr', 'cols', 'sheetData', 'sheetCalcPr',
    'sheetProtection', 'protectedRanges', 'scenarios', 'autoFilter', 'sortState', 'dataConsolidate',
    'customSheetViews', 'mergeCells', 'phoneticPr', 'conditionalFormatting', 'dataValidations',
    'hyperlinks', 'printOptions', 'pageMargins', 'pageSetup', 'headerFooter', 'rowBreaks',
    'colBreaks', 'customProperties', 'cellWatches', 'ignoredErrors', 'smartTags',
)


class _Book:
    """Read-only view of an uploaded Excel workbook: sheet rows, shared strings, photos per row."""

    def __init__(self, path):
        try:
            self.z = zipfile.ZipFile(path, 'r')
        except Exception:
            raise ValueError('Tệp tải lên không phải là tệp Excel (.xlsx / .xlsm) hợp lệ!')
        self.names = set(self.z.namelist())
        if 'xl/workbook.xml' not in self.names:
            self.z.close()
            raise ValueError('Tệp tải lên không phải là tệp Excel (.xlsx / .xlsm) hợp lệ!')
        self.ss = []
        if 'xl/sharedStrings.xml' in self.names:
            for si in ET.fromstring(self.z.read('xl/sharedStrings.xml')).findall(f'{XL_NS}si'):
                self.ss.append(''.join(t.text or '' for t in si.iter(f'{XL_NS}t')))
        self.sheet_path, self.kind = self._find_sheet()
        self.sheet_xml = ET.fromstring(self.z.read(self.sheet_path)) if self.sheet_path else None
        self.drawing_path = self._drawing_path() if self.sheet_path else None

    def _find_sheet(self):
        wb = ET.fromstring(self.z.read('xl/workbook.xml'))
        rels = {r.attrib['Id']: r.attrib['Target'] for r in ET.fromstring(self.z.read('xl/_rels/workbook.xml.rels'))}
        checklist = None
        sheets = []
        for sh in wb.iter(f'{XL_NS}sheet'):
            name = sh.attrib.get('name', '').strip().lower()
            target = rels.get(sh.attrib.get(f'{REL_NS}id'), '')
            path = target.lstrip('/') if target.startswith('/') else 'xl/' + target
            if path not in self.names:
                continue
            sheets.append((name, path))
            if 'finding' in name:
                return path, 'findings'
            if name == 'checklist':
                checklist = path
        if checklist:
            return checklist, 'checklist'
        # Fallback content inspection when worksheet tabs were renamed
        ref_codes = {it['audit_id'] for it in load_checklist_reference()['items']}
        for _, path in sheets:
            try:
                root = ET.fromstring(self.z.read(path))
                rmap = {}
                for r_el in root.findall(f'.//{XL_NS}row'):
                    rn = int(r_el.attrib.get('r', 0))
                    if rn <= 46:
                        rmap[rn] = {
                            ''.join(ch for ch in c.attrib.get('r', '') if ch.isalpha()): self.cell_text(c)
                            for c in r_el.findall(f'{XL_NS}c')
                        }
                h6 = rmap.get(6, {})
                if 'audit id' in h6.get('D', '').lower() or 'point of issue' in h6.get('G', '').lower():
                    return path, 'findings'
                if sum(1 for rn in range(5, 46) if rmap.get(rn, {}).get('B', '').strip().upper() in ref_codes) >= 20:
                    return path, 'checklist'
            except Exception:
                pass
        return (None, 'unknown')

    def _drawing_path(self):
        rels_path = f"{posixpath.dirname(self.sheet_path)}/_rels/{posixpath.basename(self.sheet_path)}.rels"
        if rels_path not in self.names:
            return None
        for rel in ET.fromstring(self.z.read(rels_path)):
            if rel.attrib.get('Type') == DRAWING_REL:
                p = posixpath.normpath(posixpath.join(posixpath.dirname(self.sheet_path), rel.attrib['Target']))
                return p if p in self.names else None
        return None

    def cell_text(self, c):
        t = c.attrib.get('t')
        v = c.find(f'{XL_NS}v')
        if t == 's' and v is not None and v.text is not None:
            i = int(v.text)
            return self.ss[i] if i < len(self.ss) else ''
        if t == 'inlineStr':
            is_el = c.find(f'{XL_NS}is')
            return ''.join(x.text or '' for x in is_el.iter(f'{XL_NS}t')) if is_el is not None else ''
        return v.text if v is not None and v.text is not None else ''

    def rows(self):
        sd = self.sheet_xml.find(f'{XL_NS}sheetData')
        return {int(r.attrib['r']): r for r in sd.findall(f'{XL_NS}row')}

    def row_values(self, row_el):
        out = {}
        for c in row_el.findall(f'{XL_NS}c'):
            out[''.join(ch for ch in c.attrib.get('r', '') if ch.isalpha())] = self.cell_text(c)
        return out

    def anchors(self):
        """[(anchor_element, start_row_1based, media_path_or_None)]"""
        if not self.drawing_path:
            return []
        d_xml = ET.fromstring(self.z.read(self.drawing_path))
        rels_path = f"{posixpath.dirname(self.drawing_path)}/_rels/{posixpath.basename(self.drawing_path)}.rels"
        rels = {}
        if rels_path in self.names:
            rels = {r.attrib['Id']: r.attrib['Target'] for r in ET.fromstring(self.z.read(rels_path))}
        out = []
        for anc in list(d_xml):
            fr = anc.find(f'{XDR_NS}from')
            if fr is None:
                continue
            row1 = int(fr.find(f'{XDR_NS}row').text) + 1
            blip = anc.find(f'.//{A_NS}blip')
            rid = blip.attrib.get(f'{REL_NS}embed') if blip is not None else None
            media = None
            if rid and rid in rels:
                media = posixpath.normpath(posixpath.join(posixpath.dirname(self.drawing_path), rels[rid]))
                if media not in self.names:
                    media = None
            out.append((anc, row1, media))
        return out


def workbook_kind(path):
    """'findings' | 'checklist' | 'unknown' for an uploaded Excel file."""
    b = _Book(path)
    try:
        return b.kind
    finally:
        b.z.close()


def _is_finding_row(vals):
    return bool(str(vals.get('G', '')).strip())


def _make_clean_findings_base(dest_path):
    """
    Creates a clean empty Findings (.xlsm) workbook from DEFAULT_FINDINGS_PATH:
    - Removes all sample finding rows >= 7
    - Clears header metadata C1..C4 (no YOUSUNG/L10PO5 leakage)
    - Empties drawing1.xml & drawing1.xml.rels and omits all sample xl/media/* photos
    """
    with zipfile.ZipFile(DEFAULT_FINDINGS_PATH, 'r') as zin:
        wb = ET.fromstring(zin.read('xl/workbook.xml'))
        wrels = {r.attrib['Id']: r.attrib['Target'] for r in ET.fromstring(zin.read('xl/_rels/workbook.xml.rels'))}
        sh_path = 'xl/worksheets/sheet2.xml'
        for sh in wb.iter(f'{XL_NS}sheet'):
            if 'finding' in sh.attrib.get('name', '').lower():
                t = wrels.get(sh.attrib.get(f'{REL_NS}id'), '')
                sh_path = t.lstrip('/') if t.startswith('/') else 'xl/' + t
                break

        sh_xml = ET.fromstring(zin.read(sh_path))
        sd = sh_xml.find(f'{XL_NS}sheetData')
        for r_el in list(sd.findall(f'{XL_NS}row')):
            rn = int(r_el.attrib.get('r', 0))
            if rn >= 7:
                sd.remove(r_el)
            elif rn in (1, 2, 3, 4):
                set_xlsx_cell_value(r_el, 'C', rn, '')

        edited = {sh_path: _office_xml(sh_xml, zin.read(sh_path))}
        if 'xl/drawings/drawing1.xml' in zin.namelist():
            edited['xl/drawings/drawing1.xml'] = _blank_template('xl/drawings/drawing1.xml')
        if 'xl/drawings/_rels/drawing1.xml.rels' in zin.namelist():
            edited['xl/drawings/_rels/drawing1.xml.rels'] = _blank_template('xl/drawings/_rels/drawing1.xml.rels')

        with zipfile.ZipFile(dest_path, 'w', zipfile.ZIP_DEFLATED) as zout:
            for m in zin.infolist():
                if m.filename == 'xl/calcChain.xml' or m.filename.startswith('xl/media/'):
                    continue
                zout.writestr(m, edited.get(m.filename) or zin.read(m.filename))
    _drop_calc_chain(dest_path)
    return dest_path


def _harvest_row_styles(base, base_cell_xfs):
    """Returns dict col -> style_idx for synthesized finding rows."""
    styles = {}
    b_rows = base.rows()
    ref_row = b_rows.get(7)
    if ref_row is not None:
        for c in ref_row.findall(f'{XL_NS}c'):
            col = ''.join(ch for ch in c.attrib.get('r', '') if ch.isalpha())
            s = c.attrib.get('s')
            if col and s is not None and int(s) < base_cell_xfs:
                styles[col] = s
    for col, s in ROW7_STYLES.items():
        if col not in styles and int(s) < base_cell_xfs:
            styles[col] = s
    return styles


def _fill_meta_if_blank(rows, base, meta):
    """Fills C1..C4 on the Findings sheet when blank using parsed Checklist metadata."""
    if not meta:
        return
    vc = str(meta.get('vendor_code') or '').strip()
    vs = str(meta.get('vendor_short') or '').strip()
    v_disp = f"{vs} ({vc})" if (vs and vc and vc != 'N/A') else vs
    vals_map = {
        1: str(meta.get('subsidiary') or '').strip(),
        2: v_disp,
        3: str(meta.get('audit_date_raw') or '').strip(),
        4: str(meta.get('auditor_raw') or meta.get('auditor_short') or '').strip(),
    }
    for r_idx, val in vals_map.items():
        if val and r_idx in rows:
            cur = str(base.row_values(rows[r_idx]).get('C', '')).strip()
            if not cur:
                set_xlsx_cell_value(rows[r_idx], 'C', r_idx, val)


def merge_findings_files(field_path, doc_path, output_path):
    """
    Builds a unified Findings (.xlsm/.xlsx) workbook from `field_path` and/or `doc_path`.
    Supports both 'EHS Audit Findings' and 'RBA Audit Checklist' in either slot!
    Returns (output_path, info) where info contains:
      - 'field': int | None
      - 'doc': int | None
      - 'kinds': {'field': kind, 'doc': kind}
      - 'row_slots': {excel_row_int: 'field' | 'doc'}
      - 'checklist_data': {slot: parsed_checklist_dict}
    """
    parts = [(slot, p) for slot, p in (('field', field_path), ('doc', doc_path)) if p and os.path.exists(p)]
    if not parts:
        raise ValueError('Vui lòng nạp ít nhất 1 file: File hiện trường hoặc File tài liệu.')

    books = {}
    tmp_clean_base = None
    try:
        for slot, p in parts:
            b = _Book(p)
            if b.kind == 'unknown':
                b.z.close()
                raise ValueError(
                    f"{SLOT_LABEL[slot]} không đúng định dạng mẫu RBA 8.0.1 "
                    "(cần 'EHS Audit Findings' hoặc 'RBA Audit Checklist')."
                )
            books[slot] = b

        checklist_ref = load_checklist_reference()
        findings_slots = [slot for slot, _ in parts if books[slot].kind == 'findings']

        if findings_slots:
            base_slot = findings_slots[0]
            base = books[base_slot]
            append_queue = [(slot, p) for slot, p in parts if slot != base_slot]
        else:
            # All uploaded files are RBA Audit Checklists -> synthesize clean Findings .xlsm base
            base_slot = None
            fd, tmp_clean_base = tempfile.mkstemp(suffix='.xlsm', prefix='rba_clean_base_')
            os.close(fd)
            _make_clean_findings_base(tmp_clean_base)
            base = _Book(tmp_clean_base)
            append_queue = list(parts)

        sheet_xml = base.sheet_xml
        sheet_data = sheet_xml.find(f'{XL_NS}sheetData')
        rows = base.rows()
        info = {
            'field': None,
            'doc': None,
            'kinds': {slot: books[slot].kind for slot, _ in parts},
            'row_slots': {},
            'checklist_data': {},
        }

        # 1) Process base Findings sheet (if one of the slots was 'findings')
        photo_rows = {r for _, r, _ in base.anchors()}
        if base_slot is not None:
            n_base = 0
            for r_num, row_el in rows.items():
                if r_num < 7:
                    continue
                vals = base.row_values(row_el)
                if _is_finding_row(vals):
                    n_base += 1
                    info['row_slots'][r_num] = base_slot
                    if not str(vals.get('H', '')).strip():
                        set_xlsx_cell_value(row_el, 'H', r_num, DEFAULT_CAUSE[base_slot])
            info[base_slot] = n_base

        # Trim empty trailing template rows on base so appended rows sit right after last real row
        meaningful = [
            r for r, el in rows.items()
            if r >= 7 and (_is_finding_row(base.row_values(el)) or r in photo_rows)
        ]
        nxt = (max(meaningful) if meaningful else 6) + 1
        for r in sorted(list(rows.keys())):
            if r >= nxt:
                if _is_finding_row(base.row_values(rows[r])) or r in photo_rows:
                    nxt = r + 1
                else:
                    sheet_data.remove(rows[r])
                    rows.pop(r)

        base_cell_xfs = _count_cell_xfs(base)
        synth_styles = _harvest_row_styles(base, base_cell_xfs)

        edited = {}
        new_parts = {}
        drawing_path = base.drawing_path
        drawing_xml = ET.fromstring(base.z.read(drawing_path)) if drawing_path else None
        drawing_rels_path = (
            f"{posixpath.dirname(drawing_path)}/_rels/{posixpath.basename(drawing_path)}.rels"
            if drawing_path else None
        )
        drawing_rels = (
            ET.fromstring(base.z.read(drawing_rels_path))
            if drawing_rels_path and drawing_rels_path in base.names else None
        )
        ct_xml = ET.fromstring(base.z.read('[Content_Types].xml'))
        sheet_rels_path = f"{posixpath.dirname(base.sheet_path)}/_rels/{posixpath.basename(base.sheet_path)}.rels"
        sheet_rels = None
        other_drawing_donor = None

        # 2) Append remaining slot(s) ('findings' or 'checklist')
        for other_slot, other_path in append_queue:
            other = books[other_slot]
            if other.kind == 'findings':
                orows = other.rows()
                mapping = {}
                o_photo_rows = {r for _, r, _ in other.anchors()}
                n_other = 0
                for r_num in sorted(orows):
                    if r_num < 7:
                        continue
                    vals = other.row_values(orows[r_num])
                    if not _is_finding_row(vals) and r_num not in o_photo_rows:
                        continue
                    new_r = nxt
                    nxt += 1
                    mapping[r_num] = new_r
                    src = orows[r_num]
                    row_el = ET.Element(
                        f'{XL_NS}row',
                        {k: v for k, v in src.attrib.items() if k in ('ht', 'customHeight', 's', 'customFormat')},
                    )
                    row_el.attrib['r'] = str(new_r)
                    for c in src.findall(f'{XL_NS}c'):
                        col = ''.join(ch for ch in c.attrib.get('r', '') if ch.isalpha())
                        text = other.cell_text(c)
                        nc = ET.SubElement(row_el, f'{XL_NS}c', {'r': f'{col}{new_r}'})
                        s_attr = c.attrib.get('s')
                        if s_attr is not None and int(s_attr) < base_cell_xfs:
                            nc.attrib['s'] = s_attr
                        elif col in synth_styles:
                            nc.attrib['s'] = synth_styles[col]
                        if text == '':
                            continue
                        if c.attrib.get('t') in (None, 'n') and re.fullmatch(r'-?\d+(\.\d+)?([eE][-+]?\d+)?', text):
                            ET.SubElement(nc, f'{XL_NS}v').text = text
                        else:
                            nc.attrib['t'] = 'inlineStr'
                            t_el = ET.SubElement(ET.SubElement(nc, f'{XL_NS}is'), f'{XL_NS}t')
                            t_el.attrib['{http://www.w3.org/XML/1998/namespace}space'] = 'preserve'
                            t_el.text = text
                    if _is_finding_row(vals):
                        n_other += 1
                        info['row_slots'][new_r] = other_slot
                        if not str(vals.get('H', '')).strip():
                            set_xlsx_cell_value(row_el, 'H', new_r, DEFAULT_CAUSE[other_slot])
                    sheet_data.append(row_el)
                    rows[new_r] = row_el
                info[other_slot] = n_other

                # Copy embedded photos from `other`
                o_anchors = [(a, r, m) for a, r, m in other.anchors() if r in mapping and m]
                if o_anchors:
                    other_drawing_donor = other
                    if drawing_xml is None:
                        drawing_path, drawing_xml, drawing_rels, drawing_rels_path, sheet_rels = _new_drawing(
                            base, sheet_xml, sheet_rels_path, ct_xml
                        )
                    if drawing_rels is None:
                        drawing_rels = ET.Element(f'{PKG_REL_NS}Relationships')
                    used_ids = {r.attrib['Id'] for r in drawing_rels}
                    max_cnv = max([int(e.attrib.get('id', 0)) for e in drawing_xml.iter(f'{XDR_NS}cNvPr')] + [1])
                    k = 0
                    for anc, r1, media in o_anchors:
                        k += 1
                        ext = media.rsplit('.', 1)[-1].lower()
                        new_media = f'xl/media/merged_{other_slot}_{k}.{ext}'
                        while new_media in base.names or new_media in new_parts:
                            k += 1
                            new_media = f'xl/media/merged_{other_slot}_{k}.{ext}'
                        new_parts[new_media] = other.z.read(media)
                        _ensure_default_ct(ct_xml, ext)
                        rid_n = 1
                        while f'rIdM{rid_n}' in used_ids:
                            rid_n += 1
                        rid = f'rIdM{rid_n}'
                        used_ids.add(rid)
                        ET.SubElement(
                            drawing_rels,
                            f'{PKG_REL_NS}Relationship',
                            {'Id': rid, 'Type': IMAGE_REL, 'Target': posixpath.relpath(new_media, posixpath.dirname(drawing_path))},
                        )
                        delta = mapping[r1] - r1
                        new_anc = ET.fromstring(ET.tostring(anc))
                        for tag in ('from', 'to'):
                            el = new_anc.find(f'{XDR_NS}{tag}/{XDR_NS}row')
                            if el is not None:
                                el.text = str(int(el.text) + delta)
                        blip = new_anc.find(f'.//{A_NS}blip')
                        blip.attrib[f'{REL_NS}embed'] = rid
                        for cnv in new_anc.iter(f'{XDR_NS}cNvPr'):
                            max_cnv += 1
                            cnv.attrib['id'] = str(max_cnv)
                        drawing_xml.append(new_anc)
                    edited[drawing_path] = drawing_xml
                    edited[drawing_rels_path] = drawing_rels

                # Metadata rows 1-4: fill blanks of the base from the other Findings file
                for r in (1, 2, 3, 4):
                    if r in rows and r in orows:
                        bv, ov = base.row_values(rows[r]), other.row_values(orows[r])
                        if not str(bv.get('C', '')).strip() and str(ov.get('C', '')).strip():
                            set_xlsx_cell_value(rows[r], 'C', r, ov['C'])

            elif other.kind == 'checklist':
                chk_data = parse_checklist_xlsx(
                    other_path, checklist_ref, default_cause=DEFAULT_CAUSE[other_slot]
                )
                info['checklist_data'][other_slot] = chk_data
                n_chk = 0
                for f in chk_data.get('findings', []):
                    new_r = nxt
                    nxt += 1
                    n_chk += 1
                    info['row_slots'][new_r] = other_slot
                    row_el = ET.Element(f'{XL_NS}row', {'r': str(new_r), 'ht': '87', 'customHeight': '1'})
                    for col in ALL_COLS:
                        nc = ET.SubElement(row_el, f'{XL_NS}c', {'r': f'{col}{new_r}'})
                        if col in synth_styles:
                            nc.attrib['s'] = synth_styles[col]
                    imp_vn = f.get('improvement_vn') or auto_draft_improvement_vn(f.get('issue_vn', ''), f.get('audit_id', ''))
                    cell_payload = {
                        'B': f.get('provision', ''),
                        'C': f.get('category', ''),
                        'D': f.get('audit_id', ''),
                        'E': f.get('sub_category', ''),
                        'F': f.get('location_vn', '') or ('Hồ sơ' if other_slot == 'doc' else 'Nhà máy'),
                        'G': f.get('issue_vn', ''),
                        'H': f.get('cause') or DEFAULT_CAUSE[other_slot],
                        'I': f.get('mandatory', ''),
                        'M': imp_vn,
                    }
                    for col, val in cell_payload.items():
                        if val:
                            set_xlsx_cell_value(row_el, col, new_r, val)
                    sheet_data.append(row_el)
                    rows[new_r] = row_el
                info[other_slot] = n_chk
                _fill_meta_if_blank(rows, base, chk_data.get('metadata'))

        # 3) Renumber column A of all finding rows continuously (1..N)
        n = 0
        for r in sorted(rows):
            if r >= 7 and _is_finding_row(base.row_values(rows[r])):
                n += 1
                set_xlsx_cell_value(rows[r], 'A', r, n, is_number=True)

        # Keep rows ordered and expand sheet dimension / autoFilter / dataValidation ranges
        for el in sorted(sheet_data.findall(f'{XL_NS}row'), key=lambda e: int(e.attrib['r'])):
            sheet_data.remove(el)
            sheet_data.append(el)
        last_row = max(rows) if rows else 7
        for tag in ('dimension', 'autoFilter'):
            el = sheet_xml.find(f'{XL_NS}{tag}')
            if el is not None and re.search(r'\d+$', el.attrib.get('ref', '')):
                m = re.match(r'^(.*?)(\d+)$', el.attrib['ref'])
                if int(m.group(2)) < last_row:
                    el.attrib['ref'] = f'{m.group(1)}{last_row}'
        for dv in sheet_xml.iter(f'{XL_NS}dataValidation'):
            sq = dv.attrib.get('sqref', '')
            mm = re.fullmatch(r'([A-Z]+)(\d+):([A-Z]+)(\d+)', sq)
            if mm and int(mm.group(4)) < last_row:
                dv.attrib['sqref'] = f'{mm.group(1)}{mm.group(2)}:{mm.group(3)}{last_row}'

        edited[base.sheet_path] = sheet_xml
        edited['[Content_Types].xml'] = ct_xml
        if sheet_rels is not None:
            edited[sheet_rels_path] = sheet_rels

        # Expand Summary sheet COUNTIF ranges and restore missing E5..F11 formulas if present
        cap_row = max(150, last_row + 10)
        missing_summary_formulas = {
            **{f'E{r}': f'+C{r}-D{r}' for r in range(5, 11)},
            **{f'F{r}': f'+E{r}/C{r}' for r in range(5, 11)},
            'F11': '+E11/C11',
        }
        for name in base.names:
            if name.startswith('xl/worksheets/sheet') and name.endswith('.xml') and name != base.sheet_path:
                raw_sh = base.z.read(name)
                if b'Findings!' not in raw_sh:
                    continue
                other_sh = ET.fromstring(raw_sh)
                for c in other_sh.iter(f'{XL_NS}c'):
                    ref = c.attrib.get('r', '')
                    f_el = c.find(f'{XL_NS}f')
                    v_el = c.find(f'{XL_NS}v')
                    if f_el is None and ref in missing_summary_formulas:
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
                edited[name] = other_sh

        part_bytes = {}
        if other_drawing_donor is not None and other_drawing_donor.drawing_path:
            for prefix, uri in re.findall(
                r'xmlns:(\w+)="([^"]+)"',
                other_drawing_donor.z.read(other_drawing_donor.drawing_path).decode('utf-8', 'ignore'),
            ):
                try:
                    ET.register_namespace(prefix, uri)
                except ValueError:
                    pass
        for name, root_el in edited.items():
            if name in base.names:
                tpl = base.z.read(name)
            elif name == drawing_path and other_drawing_donor is not None and other_drawing_donor.drawing_path:
                tpl = other_drawing_donor.z.read(other_drawing_donor.drawing_path)
            else:
                tpl = _blank_template(name)
            part_bytes[name] = _office_xml(root_el, tpl)

        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zout:
            for member in base.z.infolist():
                if member.filename == 'xl/calcChain.xml':
                    continue
                zout.writestr(member, part_bytes.pop(member.filename, None) or base.z.read(member.filename))
            for name, data in list(part_bytes.items()) + list(new_parts.items()):
                zout.writestr(name, data)

        _drop_calc_chain(output_path)
        if base_slot is None:
            base.z.close()
        return output_path, info
    finally:
        for b in books.values():
            try:
                b.z.close()
            except Exception:
                pass
        if tmp_clean_base and os.path.exists(tmp_clean_base):
            try:
                os.remove(tmp_clean_base)
            except OSError:
                pass


def _count_cell_xfs(book):
    if 'xl/styles.xml' not in book.names:
        return 0
    st = ET.fromstring(book.z.read('xl/styles.xml'))
    xfs = st.find(f'{XL_NS}cellXfs')
    return len(xfs.findall(f'{XL_NS}xf')) if xfs is not None else 0


def _ensure_default_ct(ct_xml, ext):
    if any(el.attrib.get('Extension', '').lower() == ext for el in ct_xml.findall(f'{CT_NS}Default')):
        return
    el = ET.Element(f'{CT_NS}Default', {'Extension': ext, 'ContentType': IMG_CTYPES.get(ext, 'application/octet-stream')})
    ct_xml.insert(0, el)


def _blank_template(name):
    if name.endswith('.rels'):
        return b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"></Relationships>'
    return (
        b'<xdr:wsDr xmlns:xdr="http://schemas.openxmlformats.org/drawingml/2006/spreadsheetDrawing" '
        b'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
        b'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"></xdr:wsDr>'
    )


def _new_drawing(base, sheet_xml, sheet_rels_path, ct_xml):
    """Creates a drawing part for a Findings sheet that had no photo yet (engine reads drawing1.xml)."""
    i = 1
    while f'xl/drawings/drawing{i}.xml' in base.names:
        i += 1
    drawing_path = f'xl/drawings/drawing{i}.xml'
    drawing_xml = ET.Element(f'{XDR_NS}wsDr')
    drawing_rels_path = f'xl/drawings/_rels/drawing{i}.xml.rels'
    drawing_rels = ET.Element(f'{PKG_REL_NS}Relationships')
    sheet_rels = (
        ET.fromstring(base.z.read(sheet_rels_path))
        if sheet_rels_path in base.names else ET.Element(f'{PKG_REL_NS}Relationships')
    )
    used = {r.attrib['Id'] for r in sheet_rels}
    n = 1
    while f'rIdD{n}' in used:
        n += 1
    rid = f'rIdD{n}'
    ET.SubElement(
        sheet_rels,
        f'{PKG_REL_NS}Relationship',
        {'Id': rid, 'Type': DRAWING_REL, 'Target': posixpath.relpath(drawing_path, posixpath.dirname(base.sheet_path))},
    )
    children = list(sheet_xml)
    pos = 0
    for idx, ch in enumerate(children):
        if ch.tag.replace(XL_NS, '') in _BEFORE_DRAWING:
            pos = idx + 1
    d_el = ET.Element(f'{XL_NS}drawing', {f'{REL_NS}id': rid})
    sheet_xml.insert(pos, d_el)
    ET.SubElement(
        ct_xml,
        f'{CT_NS}Override',
        {'PartName': '/' + drawing_path, 'ContentType': 'application/vnd.openxmlformats-officedocument.drawing+xml'},
    )
    return drawing_path, drawing_xml, drawing_rels, drawing_rels_path, sheet_rels


def _drop_calc_chain(path):
    """Removes calcChain references (the part itself was not copied) so Excel opens the file cleanly."""
    with zipfile.ZipFile(path, 'r') as z:
        items = [(m, z.read(m.filename)) for m in z.infolist()]
    changed = False
    out = []
    for m, data in items:
        if m.filename == '[Content_Types].xml' and b'calcChain' in data:
            data = re.sub(rb'<Override[^>]*calcChain\.xml"[^>]*/>', b'', data)
            changed = True
        elif m.filename == 'xl/_rels/workbook.xml.rels' and b'calcChain' in data:
            data = re.sub(rb'<Relationship[^>]*calcChain\.xml"[^>]*/>', b'', data)
            changed = True
        out.append((m, data))
    if changed:
        with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as z:
            for m, data in out:
                z.writestr(m, data)
