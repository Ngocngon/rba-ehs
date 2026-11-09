"""
Safe-start supervisor for the RBA 8.0.1 server.

    python3 start_server.py

- Runs server.py and restarts it when it exits with code 3 (restart requested,
  e.g. after an admin restores a backup).
- If the server crashes within 20 seconds of starting (typically a broken update),
  the latest known-good backup of the code is restored automatically and the
  server is started again (one automatic rollback per run).
© NGUYỄN NGỌC NGÔN — RBA 8.0.1 EHS Automation Suite
"""
import os
import sys
import time
import subprocess

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

# Windows consoles may not support Vietnamese characters: force UTF-8 output
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass


def log(msg):
    print(f"[supervisor {time.strftime('%H:%M:%S')}] {msg}", flush=True)


def main():
    rolled_back = False
    while True:
        started = time.time()
        log("Khởi động server.py ...")
        proc = subprocess.run([sys.executable, os.path.join(BASE_DIR, "server.py")], cwd=BASE_DIR,
                              env=dict(os.environ, RBA_SUPERVISED="1", PYTHONIOENCODING="utf-8"))
        code = proc.returncode
        alive = time.time() - started
        if code == 4:
            log("Cổng đang được sử dụng — hệ thống có thể đã chạy sẵn. Hãy mở trình duyệt tới địa chỉ của hệ thống, hoặc đóng cửa sổ đang chạy rồi thử lại.")
            sys.exit(4)
        if code == 3:
            log("Yêu cầu khởi động lại (code 3) — đang khởi động lại.")
            continue
        if code != 0 and alive < 20 and not rolled_back:
            try:
                import backup
                good = backup.latest_good_backup(exclude_hash=backup.code_hash())
            except Exception as e:  # backup module itself may be broken
                log(f"Không đọc được module backup: {e}")
                good = None
            if good:
                log(f"Server lỗi khi khởi động (code {code}). Tự động khôi phục bản ổn định: {good['name']}")
                import backup
                backup.restore_backup(good["name"], restore_code=True, restore_data=False, restore_storage=False, actor="supervisor")
                rolled_back = True
                continue
            log("Server lỗi khi khởi động và không có bản sao lưu ổn định để khôi phục.")
            sys.exit(code)
        if code != 0:
            log(f"Server dừng với mã lỗi {code}. Khởi động lại sau 3 giây...")
            time.sleep(3)
            continue
        log("Server đã dừng.")
        break


if __name__ == "__main__":
    main()
