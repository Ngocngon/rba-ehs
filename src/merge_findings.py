"""
Ghép 2 file Finding: File hiện trường (facility) + File tài liệu (Administrative).
Cả hai cùng mẫu 'EHS Audit Findings (.xlsm/.xlsx)'. Kết quả là MỘT workbook Findings:
- Lấy file hiện trường làm nền (nếu thiếu thì lấy file tài liệu).
- Các dòng nhận định của file còn lại được nối vào cuối sheet Findings, kèm ảnh.
- Cột H (cause) để trống được điền mặc định: hiện trường = 'facility', tài liệu = 'Administrative'.
- Cột A (No.) được đánh số lại liên tục để mỗi nhận định có số riêng.
Mọi bước sau (chấm điểm, Checklist, Word, PDF, Findings song ngữ) dùng file ghép như một file bình thường.
© NGUYỄN NGỌC NGÔN — RBA 8.0.1 EHS Automation Suite
"""
import os
import re
import zipfile
import posixpath
import xml.etree.ElementTree as ET

from engine import XL_NS, REL_NS, XDR_NS, A_NS, _office_xml, set_xlsx_cell_value, _col_to_num

PKG_REL_NS = '{http://schemas.openxmlformats.org/package/2006/relationships}'
CT_NS = '{http://schemas.openxmlformats.org/package/2006/content-types}'
DRAWING_REL = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships/drawing'
IMAGE_REL = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships/image'
DEFAULT_CAUSE = {'field': 'facility', 'doc': 'Administrative'}
SLOT_LABEL = {'field': 'File hiện trường', 'doc': 'File tài liệu'}
IMG_CTYPES = {'png': 'image/png', 'jpeg': 'image/jpeg', 'jpg': 'image/jpeg', 'gif': 'image/gif',
              'emf': 'image/x-emf', 'wmf': 'image/x-wmf', 'bmp': 'image/bmp', 'tiff': 'image/tiff', 'webp': 'image/webp'}

# Order of worksheet children after which <drawing> must be inserted (OOXML schema order)
_BEFORE_DRAWING = ('sheetPr', 'dimension', 'sheetViews', 'sheetFormatPr', 'cols', 'sheetData', 'sheetCalcPr',
                   'sheetProtection', 'protectedRanges', 'scenarios', 'autoFilter', 'sortState', 'dataConsolidate',
                   'customSheetViews', 'mergeCells', 'phoneticPr', 'conditionalFormatting', 'dataValidations',
                   'hyperlinks', 'printOptions', 'pageMargins', 'pageSetup', 'headerFooter', 'rowBreaks',
                   'colBreaks', 'customProperties', 'cellWatches', 'ignoredErrors', 'smartTags')


class _Book:
    """Read-only view of a Findings workbook: sheet rows, shared strings, photos per row."""

    def __init__(self, path):
        try:
            self.z = zipfile.ZipFile(path, 'r')
        except Exception:
            raise ValueError('Tệp tải lên không phải là tệp Excel (.xlsx / .xlsm) hợp lệ!')
        self.names = set(self.z.namelist())
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
        for sh in wb.iter(f'{XL_NS}sheet'):
            name = sh.attrib.get('name', '').strip().lower()
            target = rels.get(sh.attrib.get(f'{REL_NS}id'), '')
            path = target.lstrip('/') if target.startswith('/') else 'xl/' + target
            if path not in self.names:
                continue
            if 'finding' in name:
                return path, 'findings'
            if name == 'checklist':
                checklist = path
        return (checklist, 'checklist') if checklist else (None, 'unknown')

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
        """[(anchor_element, start_row_1based, media_path_or_None, rels_dict)]"""
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
    return _Book(path).kind


def _is_finding_row(vals):
    return bool(str(vals.get('G', '')).strip())


def merge_findings_files(field_path, doc_path, output_path):
    """
    Builds the combined Findings workbook. Either path may be None (missing file).
    Returns (output_path, info) — info = {'field': n_findings|None, 'doc': n_findings|None}.
    """
    parts = [(slot, p) for slot, p in (('field', field_path), ('doc', doc_path)) if p and os.path.exists(p)]
    if not parts:
        raise ValueError('Vui lòng nạp ít nhất 1 file: File hiện trường hoặc File tài liệu.')
    books = {slot: _Book(p) for slot, p in parts}
    for slot, b in books.items():
        if b.kind != 'findings':
            if len(books) == 1:
                return None, {'passthrough': slot}  # Checklist or other format: parsed directly by engine
            raise ValueError(f"{SLOT_LABEL[slot]} không đúng mẫu 'EHS Audit Findings' (cần sheet 'Findings') nên không ghép được.")

    base_slot = parts[0][0]
    base = books[base_slot]
    other_slot = parts[1][0] if len(parts) > 1 else None
    other = books.get(other_slot) if other_slot else None

    sheet_xml = base.sheet_xml
    sheet_data = sheet_xml.find(f'{XL_NS}sheetData')
    rows = base.rows()
    info = {'field': None, 'doc': None}

    # 1) Base rows: fill blank cause
    n_base = 0
    for r_num, row_el in rows.items():
        if r_num < 7:
            continue
        vals = base.row_values(row_el)
        if _is_finding_row(vals):
            n_base += 1
            if not str(vals.get('H', '')).strip():
                set_xlsx_cell_value(row_el, 'H', r_num, DEFAULT_CAUSE[base_slot])
    info[base_slot] = n_base

    edited = {}
    new_parts = {}
    drawing_path = base.drawing_path
    drawing_xml = ET.fromstring(base.z.read(drawing_path)) if drawing_path else None
    drawing_rels_path = (f"{posixpath.dirname(drawing_path)}/_rels/{posixpath.basename(drawing_path)}.rels"
                         if drawing_path else None)
    drawing_rels = (ET.fromstring(base.z.read(drawing_rels_path)) if drawing_rels_path and drawing_rels_path in base.names
                    else None)
    ct_xml = ET.fromstring(base.z.read('[Content_Types].xml'))
    sheet_rels_path = f"{posixpath.dirname(base.sheet_path)}/_rels/{posixpath.basename(base.sheet_path)}.rels"
    sheet_rels = None

    # 2) Append the other file's finding rows (and their photos)
    if other is not None:
        orows = other.rows()
        last = max(rows) if rows else 6
        # Skip trailing empty pre-listed rows of the base: append right after its last meaningful row
        photo_rows = {r for _, r, _ in base.anchors()}
        meaningful = [r for r, el in rows.items() if r >= 7 and (_is_finding_row(base.row_values(el)) or r in photo_rows)]
        start = (max(meaningful) if meaningful else 6) + 1
        # Remove base rows from start..last that are empty, so appended rows do not collide
        for r in sorted(rows):
            if r >= start:
                if _is_finding_row(base.row_values(rows[r])) or r in photo_rows:
                    start = r + 1
                else:
                    sheet_data.remove(rows[r])
                    rows.pop(r)
        base_cell_xfs = _count_cell_xfs(base)
        mapping = {}
        nxt = start
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
            row_el = ET.Element(f'{XL_NS}row', {k: v for k, v in src.attrib.items() if k in ('ht', 'customHeight', 's', 'customFormat')})
            row_el.attrib['r'] = str(new_r)
            for c in src.findall(f'{XL_NS}c'):
                col = ''.join(ch for ch in c.attrib.get('r', '') if ch.isalpha())
                text = other.cell_text(c)
                nc = ET.SubElement(row_el, f'{XL_NS}c', {'r': f'{col}{new_r}'})
                s_attr = c.attrib.get('s')
                if s_attr is not None and int(s_attr) < base_cell_xfs:
                    nc.attrib['s'] = s_attr
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
                if not str(vals.get('H', '')).strip():
                    set_xlsx_cell_value(row_el, 'H', new_r, DEFAULT_CAUSE[other_slot])
            sheet_data.append(row_el)
            rows[new_r] = row_el
        info[other_slot] = n_other

        # Photos
        o_anchors = [(a, r, m) for a, r, m in other.anchors() if r in mapping and m]
        if o_anchors:
            if drawing_xml is None:
                drawing_path, drawing_xml, drawing_rels, drawing_rels_path, sheet_rels = _new_drawing(base, sheet_xml, sheet_rels_path, ct_xml)
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
                ET.SubElement(drawing_rels, f'{PKG_REL_NS}Relationship',
                              {'Id': rid, 'Type': IMAGE_REL, 'Target': posixpath.relpath(new_media, posixpath.dirname(drawing_path))})
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

        # Metadata rows 1-4: fill blanks of the base from the other file
        for r in (1, 2, 3, 4):
            if r in rows and r in orows:
                bv, ov = base.row_values(rows[r]), other.row_values(orows[r])
                if not str(bv.get('C', '')).strip() and str(ov.get('C', '')).strip():
                    set_xlsx_cell_value(rows[r], 'C', r, ov['C'])

    # 3) Renumber column A of finding rows: every finding gets its own number
    n = 0
    for r in sorted(rows):
        if r >= 7 and _is_finding_row(base.row_values(rows[r])):
            n += 1
            set_xlsx_cell_value(rows[r], 'A', r, n, is_number=True)

    # Keep the sheet's rows ordered and the used range / filters / validations covering them
    for el in sorted(sheet_data.findall(f'{XL_NS}row'), key=lambda e: int(e.attrib['r'])):
        sheet_data.remove(el)
        sheet_data.append(el)
    last_row = max(rows) if rows else 6
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

    part_bytes = {}
    if other is not None and other.drawing_path:
        for prefix, uri in re.findall(r'xmlns:(\w+)="([^"]+)"', other.z.read(other.drawing_path).decode('utf-8', 'ignore')):
            try:
                ET.register_namespace(prefix, uri)
            except ValueError:
                pass
    for name, root_el in edited.items():
        if name in base.names:
            tpl = base.z.read(name)
        elif name == drawing_path and other is not None and other.drawing_path:
            tpl = other.z.read(other.drawing_path)
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
    # calcChain is dropped: remove its references
    _drop_calc_chain(output_path)
    for b in books.values():
        b.z.close()
    return output_path, info


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
    return (b'<xdr:wsDr xmlns:xdr="http://schemas.openxmlformats.org/drawingml/2006/spreadsheetDrawing" '
            b'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
            b'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"></xdr:wsDr>')


def _new_drawing(base, sheet_xml, sheet_rels_path, ct_xml):
    """Creates a drawing part for a Findings sheet that had no photo yet (engine reads drawing1.xml)."""
    i = 1
    while f'xl/drawings/drawing{i}.xml' in base.names:
        i += 1
    drawing_path = f'xl/drawings/drawing{i}.xml'
    drawing_xml = ET.Element(f'{XDR_NS}wsDr')
    drawing_rels_path = f'xl/drawings/_rels/drawing{i}.xml.rels'
    drawing_rels = ET.Element(f'{PKG_REL_NS}Relationships')
    sheet_rels = (ET.fromstring(base.z.read(sheet_rels_path)) if sheet_rels_path in base.names
                  else ET.Element(f'{PKG_REL_NS}Relationships'))
    used = {r.attrib['Id'] for r in sheet_rels}
    n = 1
    while f'rIdD{n}' in used:
        n += 1
    rid = f'rIdD{n}'
    ET.SubElement(sheet_rels, f'{PKG_REL_NS}Relationship',
                  {'Id': rid, 'Type': DRAWING_REL, 'Target': posixpath.relpath(drawing_path, posixpath.dirname(base.sheet_path))})
    # Insert <drawing> at the schema position
    children = list(sheet_xml)
    pos = 0
    for idx, ch in enumerate(children):
        if ch.tag.replace(XL_NS, '') in _BEFORE_DRAWING:
            pos = idx + 1
    d_el = ET.Element(f'{XL_NS}drawing', {f'{REL_NS}id': rid})
    sheet_xml.insert(pos, d_el)
    ET.SubElement(ct_xml, f'{CT_NS}Override', {'PartName': '/' + drawing_path,
                                               'ContentType': 'application/vnd.openxmlformats-officedocument.drawing+xml'})
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
