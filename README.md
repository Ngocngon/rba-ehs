# RBA 8.0.1 · EHS Audit — bản web

**Mở ứng dụng:** https://ngocngon.github.io/rba-ehs/

Chạy hoàn toàn trong trình duyệt (máy tính, điện thoại, máy tính bảng) — không cần cài đặt, không cần máy chủ.
Mã Python của hệ thống được chạy bằng [Pyodide](https://pyodide.org) ngay trên thiết bị.

## Nạp file Finding (2 mục)

| Mục | Nội dung | Phân loại khi tổng hợp |
|---|---|---|
| **File hiện trường** | Lỗi quan sát tại hiện trường, kèm ảnh | `facility` |
| **File tài liệu** | Lỗi hồ sơ, tài liệu, quy trình | `Administrative` |

- Chọn 1 hoặc cả 2 file (cùng mẫu *EHS Audit Findings*) → **Tổng hợp & chấm điểm**. Kết quả là tổng hợp của cả 2 file (ảnh đi theo từng dòng lỗi).
- **Thiếu 1 file vẫn tổng hợp được** — thanh *Nguồn dữ liệu* hiển thị “Thiếu file…”.
- **Bổ sung sau:** nút **📎 Bổ sung** ở thanh *Nguồn dữ liệu* hoặc trong *Kho lưu trữ*. Hệ thống tổng hợp lại, giữ các chỉnh sửa thủ công (thông tin nhà cung cấp, mức độ đã điều chỉnh) và lưu thành phiên bản mới.

## Dữ liệu được lưu ở đâu?

- Lưu **trên từng thiết bị / trình duyệt** (IndexedDB). Dữ liệu không gửi lên Internet.
- Chuyển dữ liệu sang máy khác: *Tài khoản → Sao lưu* → **Tạo bản sao lưu** (chọn “kèm kho lưu trữ”) → **Tải về**; trên máy mới: **Tải lên bản sao lưu** → **Khôi phục**.
- Xóa dữ liệu duyệt web (site data) của trang sẽ xóa dữ liệu — hãy sao lưu định kỳ.

## PDF

Nút **PDF** mở bản in A4 theo mẫu báo cáo → chọn **Lưu thành PDF** trong hộp thoại In.
(Gói ZIP trên bản web gồm Findings + Checklist + Word, không kèm PDF.)

## Cài như ứng dụng trên điện thoại

- **iPhone (Safari):** Chia sẻ → *Thêm vào MH chính*.
- **Android (Chrome):** menu ⋮ → *Cài đặt ứng dụng / Thêm vào màn hình chính*.

## Cấu trúc mã nguồn

```
src/           Mã nguồn gốc (chạy như server Python: cd src && python3 server.py)
  merge_findings.py   Gộp File hiện trường + File tài liệu (kèm ảnh)
web/           Phần chạy trong trình duyệt (Pyodide bridge, worker, service worker)
build_web.py   Đóng gói src/ + web/ → docs/
docs/          Bản phát hành cho GitHub Pages
```

Cập nhật bản web: sửa `src/` hoặc `web/` → `python3 build_web.py` → commit & push.

© NGUYỄN NGỌC NGÔN — RBA 8.0.1 EHS Automation Suite
