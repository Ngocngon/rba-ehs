"""
Emergency restore tool (works even when the web server cannot start).

    python3 restore_backup.py            # list backups
    python3 restore_backup.py latest     # restore the latest known-good version (code + data)
    python3 restore_backup.py <name.zip> # restore a specific backup
© NGUYỄN NGỌC NGÔN — RBA 8.0.1 EHS Automation Suite
"""
import sys
import backup


def main():
    items = backup.list_backups()
    if len(sys.argv) < 2:
        print("Các bản sao lưu hiện có (mới nhất trước):")
        for b in items:
            flag = " [ỔN ĐỊNH]" if b.get("known_good") else ""
            print(f"  {b['name']:<60} {b['size_mb']:>8} MB  {b['created_at']}{flag}")
        print("\nDùng: python3 restore_backup.py latest  |  python3 restore_backup.py <tên_file.zip>")
        return
    target = sys.argv[1]
    if target == "latest":
        good = backup.latest_good_backup()
        if not good:
            print("Không có bản sao lưu ổn định nào.")
            return
        target = good["name"]
    m = backup.restore_backup(target, actor="cli")
    print(f"Đã khôi phục {target} (tạo lúc {m.get('created_at')}). Hãy khởi động lại: python3 start_server.py")


if __name__ == "__main__":
    main()
