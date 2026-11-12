"""
(I) PDF export and ZIP bundle.
- If LibreOffice is installed, the generated .docx is converted 1:1 to PDF.
- Otherwise the report is rendered as an A4 print layout that mirrors the Word template
  and printed to PDF with Google Chrome / Microsoft Edge / Chromium (headless).
- ZIP bundle = Findings file + Checklist (.xlsx) + Word report (.docx) + PDF.
© NGUYỄN NGỌC NGÔN — RBA 8.0.1 EHS Automation Suite
"""
import os
import html
import shutil
import zipfile
import tempfile
import subprocess
import pathlib

_PF = [os.environ.get('ProgramFiles', r'C:\Program Files'), os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)'),
       os.environ.get('LOCALAPPDATA', '')]
SOFFICE_CANDIDATES = ['soffice', 'libreoffice', '/Applications/LibreOffice.app/Contents/MacOS/soffice',
                      *[os.path.join(b, 'LibreOffice', 'program', 'soffice.exe') for b in _PF if b],
                      '/usr/bin/soffice', '/usr/local/bin/soffice', '/opt/homebrew/bin/soffice']
BROWSER_CANDIDATES = ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
                      '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
                      '/Applications/Chromium.app/Contents/MacOS/Chromium',
                      *[os.path.join(b, 'Google', 'Chrome', 'Application', 'chrome.exe') for b in _PF if b],
                      *[os.path.join(b, 'Microsoft', 'Edge', 'Application', 'msedge.exe') for b in _PF if b],
                      'google-chrome', 'google-chrome-stable', 'chromium', 'chromium-browser', 'microsoft-edge', 'msedge', 'chrome']


def _which(cands):
    for c in cands:
        p = c if os.path.isabs(c) else shutil.which(c)
        if p and os.path.exists(p):
            return p
    return None


def pdf_engine():
    s = _which(SOFFICE_CANDIDATES)
    if s:
        return {'engine': 'libreoffice', 'path': s, 'label': 'LibreOffice (chuyển đổi chính xác từ file Word)'}
    b = _which(BROWSER_CANDIDATES)
    if b:
        return {'engine': 'browser', 'path': b, 'label': 'Trình duyệt (bản in A4 theo mẫu Word)'}
    return None


from engine import audit_period, cap_violations_pair, _compact_violation_text, partner_profile, workforce_note


def _e(x):
    return html.escape(str(x if x is not None else ''))


def _fmt_ml(txt, prefix=''):
    lines = [ln.strip() for ln in str(txt or '').split('\n') if ln.strip()]
    if not lines:
        return ''
    first = prefix + _e(lines[0])
    if len(lines) == 1:
        return first
    rest = '<br/>'.join(f"<span class='tr'>{_e(ln)}</span>" for ln in lines[1:])
    return f"{first}<br/>{rest}"


def build_report_html(data, round2_summary=None, title='', lang_mode=None):
    if lang_mode:
        from translator import apply_export_lang_to_data
        data = apply_export_lang_to_data(data, lang_mode)
    m, s = data['metadata'], data['summary']
    year_str, _ = audit_period(m)

    def res_table(sm, gbm):
        c = sm['counts']
        return f"""<table class="t c"><thead><tr><th rowspan="2">GBM</th><th colspan="3">Số hạng mục vi phạm</th>
        <th rowspan="2">Kết quả đánh giá<br/>(Số vấn đề/Số vi phạm hạng mục bắt buộc)</th><th rowspan="2">Điểm đánh giá</th><th rowspan="2">Level xếp hạng</th></tr>
        <tr><th style="color:#FF0000">Priority</th><th><span style="background:#ff0000">Major</span></th><th><span style="background:#ffff00">Minor</span></th></tr></thead>
        <tbody><tr><td><b>{_e(gbm)}</b></td><td><b>{c['Priority']}</b></td><td><b>{c['Major']}</b></td><td><b>{c['Minor']}</b></td>
        <td>{sm['violated_items_count']} items/HMBB: {sm['mandatory_count']}</td><td><b>{_e(sm['total_score'])} điểm</b></td><td><b>{_e(sm['grade_level'])}</b></td></tr></tbody></table>"""

    gbm = m.get('gbm', 'Mobile')
    sec1 = f"<p class='i'>□ Kết quả{' lần 1' if round2_summary else ''}: Tổng <b>{_e(s['total_score'])} điểm</b></p><p class='i2'>* Checklist RBA 41 hạng mục EHS</p>"
    sec1 += res_table(s, gbm + (' (Lần 1)' if round2_summary else ''))
    if round2_summary:
        d = round(float(round2_summary['total_score']) - float(s['total_score']), 2)
        sec1 += (f"<p class='i'>□ Kết quả lần 2 (đánh giá lại): Tổng <b>{_e(round2_summary['total_score'])} điểm</b> "
                 f"({'+' if d >= 0 else ''}{d:g} điểm so với lần 1)</p>") + res_table(round2_summary, gbm + ' (Lần 2)')

    t3 = ''
    for sev in ('Priority', 'Major', 'Minor'):
        items = [x for x in data['checklist'] if x.get('significance') == sev]
        for i, x in enumerate(items):
            lbl = f"({len(items)})" if sev == 'Priority' else f"({len(items):02d})"
            if x.get('export_t3_lines'):
                bullets = '<br/>'.join(_fmt_ml(ln, prefix='- ') for ln in x['export_t3_lines'])
            else:
                fs = x.get('findings') or []
                if fs:
                    b_list = ['- ' + _e(_compact_violation_text(f.get('issue_vn', ''), 135)) for f in fs[:2]]
                    if len(fs) > 2:
                        b_list[-1] = b_list[-1].rstrip('.') + '...'
                    bullets = '<br/>'.join(b_list)
                else:
                    bullets = '- ' + _e(_compact_violation_text(x.get('evidence_text', ''), 135))
            first = f"<td rowspan='{len(items)}' class='c'>{sev}<br/>{lbl}</td>" if i == 0 else ''
            t3 += f"<tr>{first}<td>{bullets}</td><td class='c'>{_e(x['audit_id'])}</td></tr>"
    if not t3:
        t3 = f"<tr><td class='c'>—</td><td>{_fmt_ml(data.get('empty_t3_text', 'Không có lỗi vi phạm'))}</td><td class='c'>—</td></tr>"

    t4 = ''
    for k in (data.get('key_issues') or [])[:5]:
        ph = (k.get('photos') or [{}])[0].get('data_url', '')
        im = f"<img src='{ph}'/>" if str(ph).startswith('data:') else ''
        k_txt = _fmt_ml(k['export_issue_text']) if k.get('export_issue_text') else _e(_compact_violation_text(k['issue_vn'], 160))
        t4 += f"<tr><td class='ph'>{im}</td><td>[<span style='color:#FF0000'>{_e(k['significance'])}</span>] {k_txt}</td></tr>"
    if not t4:
        t4 = f"<tr><td class='ph'></td><td>{_fmt_ml(data.get('empty_key_issue_text', 'Không có vấn đề tồn đọng'))}</td></tr>"

    if data.get('doc_violations_export') is not None:
        doc_capped = data.get('doc_violations_export') or []
        fac_capped = data.get('facility_violations_export') or []
    else:
        doc_capped, fac_capped = cap_violations_pair(
            data.get('doc_violations'), data.get('facility_violations'), max_per_type=3, max_total=5
        )
    lis = lambda arr: ''.join(f"<li>{_fmt_ml(v)}</li>" for v in arr or [])
    overall_html = f"<p class='i'>□ Đánh giá chung: {_fmt_ml(data['export_overall'])}</p>" if data.get('export_overall') else ''
    return f"""<!DOCTYPE html><html lang="vi"><head><meta charset="utf-8"><title>{_e(title)}</title><style>
    @page {{ size: A4; margin: 11mm 13mm; }}
    body {{ font-family: "Times New Roman", "Malgun Gothic", "Apple SD Gothic Neo", "Noto Sans CJK KR", "Microsoft YaHei", "PingFang SC", "Noto Sans CJK SC", Times, serif; color:#000; font-size:10.5pt; line-height:1.28; margin:0; }}
    h1 {{ text-align:center; font-size:18pt; text-decoration:underline; margin:0; }}
    .sub {{ text-align:center; font-size:17pt; font-weight:bold; text-decoration:underline; margin:0 0 3px; }}
    .r {{ text-align:right; font-size:10pt; }} .row {{ display:flex; justify-content:space-between; font-size:10pt; margin-bottom:2px; }}
    .h {{ font-weight:bold; font-size:11.5pt; margin-top:5px; }} .i {{ margin:1px 0 1px 6px; }} .i2 {{ margin:1px 0 1px 20px; }}
    .tr {{ color:#1e293b; font-size:9.2pt; }}
    .t {{ width:100%; border-collapse:collapse; margin:3px 0 6px; font-size:9.5pt; page-break-inside:auto; }}
    .t th, .t td {{ border:1px solid #000; padding:2.5px 5px; vertical-align:middle; }} .t th {{ background:#e7e6e6; }}
    .t tr {{ page-break-inside:avoid; }} .c {{ text-align:center; }}
    .ph {{ width:36%; text-align:center; }} .ph img {{ max-width:100%; max-height:30mm; }}
    ul {{ margin:1px 0 3px 24px; padding:0; }}
    .thanks {{ text-align:center; font-weight:bold; color:#0000FF; font-size:12pt; margin-top:4px; font-family:"Agency FB", Arial, sans-serif; }}
    </style></head><body>
    <h1>{_e(title)}</h1><div class="sub">đối tác ({_e(m.get('vendor_short'))})</div>
    <div class="r">{_e(m.get('report_date'))}</div>
    <div class="row"><span>{_e(workforce_note(m))}</span><span>Samsung Vietnam EHS</span></div>
    <div class="h">1. Khái quát</div>
    <p class="i">□ Tên đối tác: {_e(m.get('vendor_short'))} {_e(partner_profile(m))}</p>
    <p class="i">□ Ngày kiểm tra: {_e(m.get('audit_date_raw'))} &nbsp;&nbsp; * Người kiểm tra: {_e(m.get('auditor_short'))}</p>
    {sec1}
    <p style="font-size:9pt;margin:1px 0">※[Chú thích] Level xếp hạng: A(90 điểm↑), B(80~89), C(70~79), D(69↓)</p>
    <div class="h">2. Kết quả đánh giá</div>
    {overall_html}
    <p class="i"><b>① Lỗi vi phạm Tài liệu:</b></p><ul>{lis(doc_capped)}</ul>
    <p class="i"><b>② Lỗi vi phạm Hiện trường:</b></p><ul>{lis(fac_capped)}</ul>
    <div class="h">3. Kế hoạch sau này</div>
    <p class="i">□ Theo dõi tình hình cải tiến của đối tác &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; ~ hàng tuần</p>
    <p class="i2">- Triển khai đốc thúc, theo dõi tiến độ và hướng dẫn cải tiến</p>
    <p class="i">※ Đính kèm: □ Kết quả đánh giá theo Checklist 41 hạng mục RBA.{_e(year_str)} ~1 bộ<br/>
    <span style="display:inline-block;margin-left:68px">□ Kết quả kiểm tra hiện trường và lịch trình cải tiến RBA.{_e(year_str)} ~1 bộ</span></p>
    <div style="text-align:center;font-weight:bold;margin:2px 0">– Hết –</div>
    <div class="h" style="text-align:center">【Nội dung vi phạm theo từng mức độ lỗi RBA 8.0.1】</div>
    <table class="t"><thead><tr><th style="width:80px">Phân loại</th><th>Nội dung chính</th><th style="width:60px">Code</th></tr></thead><tbody>{t3}</tbody></table>
    <div class="h">□ Vấn đề chính</div>
    <table class="t"><tbody>{t4}</tbody></table>
    <div class="thanks">--- Thank you ---</div>
    </body></html>"""


def make_pdf(docx_path, html_text, out_pdf):
    """Returns (pdf_path, engine_label). Raises RuntimeError if no converter is available."""
    eng = pdf_engine()
    if not eng:
        raise RuntimeError('Máy chủ chưa có công cụ tạo PDF. Vui lòng cài LibreOffice hoặc Google Chrome.')
    tmpdir = tempfile.mkdtemp(prefix='rba_pdf_')
    try:
        if eng['engine'] == 'libreoffice':
            subprocess.run([eng['path'], '--headless', '--convert-to', 'pdf', '--outdir', tmpdir, docx_path],
                           check=True, timeout=180, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            produced = os.path.join(tmpdir, os.path.splitext(os.path.basename(docx_path))[0] + '.pdf')
        else:
            src = os.path.join(tmpdir, 'report.html')
            with open(src, 'w', encoding='utf-8') as f:
                f.write(html_text)
            produced = os.path.join(tmpdir, 'report.pdf')
            subprocess.run([eng['path'], '--headless=new', '--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu',
                            f'--user-data-dir={os.path.join(tmpdir, "profile")}',
                            '--no-pdf-header-footer', '--no-first-run', f'--print-to-pdf={produced}', pathlib.Path(src).as_uri()],
                           check=True, timeout=180, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not os.path.exists(produced) or os.path.getsize(produced) < 500:
            raise RuntimeError('Không tạo được file PDF')
        shutil.move(produced, out_pdf)
        return out_pdf, eng['label']
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f'Công cụ tạo PDF lỗi (mã {e.returncode}). Nếu máy chủ chạy trong môi trường bị giới hạn, hãy chạy start_server.py bình thường.')
    except subprocess.TimeoutExpired:
        raise RuntimeError('Tạo PDF quá thời gian cho phép')
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def make_zip(entries, out_zip):
    """entries: list of (path, arcname)."""
    with zipfile.ZipFile(out_zip, 'w', zipfile.ZIP_DEFLATED) as z:
        for path, arc in entries:
            if path and os.path.exists(path):
                z.write(path, arc)
    return out_zip
