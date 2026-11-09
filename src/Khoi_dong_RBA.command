#!/bin/bash
# RBA 8.0.1 EHS Audit Automation — Khởi động (macOS) · © NGUYỄN NGỌC NGÔN
cd "$(dirname "$0")"
# Chạy thử thật sự: macOS có sẵn lệnh python3 giả, chỉ để gợi ý cài công cụ của Apple
if ! python3 -c '' >/dev/null 2>&1; then
  osascript -e 'display alert "Chưa cài Python 3" message "Vui lòng cài Python 3 từ python.org, sau đó bấm đúp lại tệp này."'
  open "https://www.python.org/downloads/"
  exit 1
fi
PORT="${PORT:-8801}"
URL="http://127.0.0.1:$PORT"
if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  if curl -s -m 3 "$URL/" | grep -q 'RBA 8.0.1'; then
    echo "Hệ thống đã chạy sẵn — đang mở $URL"
    open "$URL"
    exit 0
  fi
  osascript -e "display alert \"Cổng $PORT đang bị ứng dụng khác sử dụng\" message \"Hãy đóng ứng dụng đó, hoặc chạy với cổng khác:  PORT=8802 ./Khoi_dong_RBA.command\""
  exit 1
fi
echo "=============================================="
echo "  RBA 8.0.1 EHS AUDIT AUTOMATION (OFFLINE)"
echo "  Bản quyền: NGUYỄN NGỌC NGÔN"
echo "  Địa chỉ: $URL"
echo "  Giữ cửa sổ này mở trong khi sử dụng."
echo "  Đóng cửa sổ (hoặc Ctrl+C) để tắt hệ thống."
echo "=============================================="
( for _ in $(seq 1 600); do curl -s -o /dev/null -m 1 "$URL/" && break; sleep 0.1; done; open "$URL" ) &
PORT="$PORT" python3 start_server.py
