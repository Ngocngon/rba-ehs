#!/bin/bash
# =====================================================================
#  RBA 8.0.1 — Tự khởi động cùng macOS (launchd) + địa chỉ cố định ngrok
#  © NGUYỄN NGỌC NGÔN
#
#  Cách dùng:
#    ./autostart_mac.sh install                 Bật tự khởi động hệ thống (máy chủ web)
#    ./autostart_mac.sh ngrok <token> <domain>  Kết nối địa chỉ cố định ngrok (tự khởi động)
#    ./autostart_mac.sh status                  Xem trạng thái
#    ./autostart_mac.sh restart                 Khởi động lại máy chủ
#    ./autostart_mac.sh uninstall               Tắt tự khởi động (cả máy chủ và ngrok)
# =====================================================================
set -e
APP_DIR="$(cd "$(dirname "$0")" && pwd)"
AGENTS="$HOME/Library/LaunchAgents"
LOGS="$APP_DIR/logs"
SERVER_LABEL="vn.rba801.server"
NGROK_LABEL="vn.rba801.ngrok"
TS_LABEL="vn.rba801.tailscale"
TS_APP_LABEL="vn.rba801.tailscale-app"
PY="$(command -v python3 || echo /usr/bin/python3)"
NGROK="$(command -v ngrok || echo /opt/homebrew/bin/ngrok)"
TS_BIN="/opt/homebrew/opt/tailscale/bin/tailscale"
TSD_BIN="/opt/homebrew/opt/tailscale/bin/tailscaled"
TS_DIR="$APP_DIR/database/tailscale"
TS_SOCK="$TS_DIR/tailscaled.sock"
TS_STATE="$TS_DIR/tailscaled.state"
PORT="${PORT:-8801}"
UID_NUM="$(id -u)"
mkdir -p "$AGENTS" "$LOGS" "$TS_DIR"

load_agent() {   # $1 = label
  launchctl bootout "gui/$UID_NUM/$1" 2>/dev/null || true
  launchctl bootstrap "gui/$UID_NUM" "$AGENTS/$1.plist"
  launchctl enable "gui/$UID_NUM/$1" 2>/dev/null || true
}

write_server_plist() {
cat > "$AGENTS/$SERVER_LABEL.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$SERVER_LABEL</string>
  <key>ProgramArguments</key><array>
    <string>/usr/bin/caffeinate</string><string>-i</string>
    <string>$PY</string><string>$APP_DIR/start_server.py</string>
  </array>
  <key>WorkingDirectory</key><string>$APP_DIR</string>
  <key>EnvironmentVariables</key><dict>
    <key>PORT</key><string>$PORT</string>
    <key>PYTHONIOENCODING</key><string>utf-8</string>
    <key>RBA_TRUST_PROXY</key><string>1</string>
    <key>PATH</key><string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>StandardOutPath</key><string>$LOGS/server.log</string>
  <key>StandardErrorPath</key><string>$LOGS/server.log</string>
</dict></plist>
EOF
}

write_ngrok_plist() {   # $1 = domain
cat > "$AGENTS/$NGROK_LABEL.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$NGROK_LABEL</string>
  <key>ProgramArguments</key><array>
    <string>$NGROK</string><string>http</string><string>--url=$1</string><string>$PORT</string>
    <string>--log=stdout</string><string>--log-level=warn</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>15</integer>
  <key>StandardOutPath</key><string>$LOGS/ngrok.log</string>
  <key>StandardErrorPath</key><string>$LOGS/ngrok.log</string>
</dict></plist>
EOF
}

write_tailscale_plist() {
cat > "$AGENTS/$TS_LABEL.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$TS_LABEL</string>
  <key>ProgramArguments</key><array>
    <string>$TSD_BIN</string>
    <string>--tun=userspace-networking</string>
    <string>--socket=$TS_SOCK</string>
    <string>--state=$TS_STATE</string>
    <string>--statedir=$TS_DIR</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>StandardOutPath</key><string>$LOGS/tailscale.log</string>
  <key>StandardErrorPath</key><string>$LOGS/tailscale.log</string>
</dict></plist>
EOF
}

# Mở ứng dụng Tailscale khi đăng nhập để link Funnel cố định tự chạy lại
write_tailscale_app_plist() {
cat > "$AGENTS/$TS_APP_LABEL.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$TS_APP_LABEL</string>
  <key>ProgramArguments</key><array>
    <string>/usr/bin/open</string><string>-g</string><string>-a</string><string>Tailscale</string>
  </array>
  <key>RunAtLoad</key><true/>
</dict></plist>
EOF
}

case "${1:-}" in
  install)
    write_server_plist
    load_agent "$SERVER_LABEL"
    if [ -d /Applications/Tailscale.app ]; then
      write_tailscale_app_plist
      load_agent "$TS_APP_LABEL"
      echo "✓ Ứng dụng Tailscale sẽ tự mở khi đăng nhập."
    fi
    echo "✓ Đã bật tự khởi động máy chủ RBA 8.0.1 (cổng $PORT)."
    echo "  Nhật ký: $LOGS/server.log"
    ;;
  tailscale-start)
    write_tailscale_plist
    load_agent "$TS_LABEL"
    sleep 2
    echo "✓ Đã bật dịch vụ ngầm Tailscale ($TS_LABEL)."
    ;;
  tailscale-funnel)
    "$TS_BIN" --socket="$TS_SOCK" set --accept-dns=false >/dev/null 2>&1 || true
    if [ -n "${2:-}" ]; then
      "$TS_BIN" --socket="$TS_SOCK" set --hostname="${2}"
      sleep 2
    fi
    TS_DOMAIN=$("$TS_BIN" --socket="$TS_SOCK" status --json | "$PY" -c 'import sys,json; d=json.load(sys.stdin); print(d.get("Self",{}).get("DNSName","").rstrip("."))' 2>/dev/null || true)
    echo "• Đang làm mới cấu hình Funnel cho tên miền: $TS_DOMAIN ..."
    "$TS_BIN" --socket="$TS_SOCK" funnel reset >/dev/null 2>&1 || true
    "$TS_BIN" --socket="$TS_SOCK" serve reset >/dev/null 2>&1 || true
    sleep 1
    "$TS_BIN" --socket="$TS_SOCK" funnel --bg "$PORT"
    if [ -n "$TS_DOMAIN" ]; then
      echo "• Đang cấp trước chứng chỉ bảo mật HTTPS cho $TS_DOMAIN (vui lòng đợi khoảng 20-35 giây)..."
      mkdir -p "$TS_DIR/certs"
      "$TS_BIN" --socket="$TS_SOCK" cert --cert-file="$TS_DIR/certs/$TS_DOMAIN.crt" --key-file="$TS_DIR/certs/$TS_DOMAIN.key" "$TS_DOMAIN"
      echo "$TS_DOMAIN" > "$APP_DIR/database/public_url.txt"
    fi
    launchctl kickstart -k "gui/$UID_NUM/$TS_LABEL" 2>/dev/null || true
    sleep 2
    echo "✓ Đã kích hoạt hoàn tất tên miền cố định: https://$TS_DOMAIN"
    ;;
  ngrok)
    TOKEN="${2:-}"; DOMAIN="${3:-}"
    if [ -z "$TOKEN" ] || [ -z "$DOMAIN" ]; then
      echo "Dùng: $0 ngrok <authtoken> <ten-mien.ngrok-free.app>"; exit 1
    fi
    DOMAIN="${DOMAIN#https://}"; DOMAIN="${DOMAIN%/}"
    "$NGROK" config add-authtoken "$TOKEN" >/dev/null
    write_ngrok_plist "$DOMAIN"
    load_agent "$NGROK_LABEL"
    echo "$DOMAIN" > "$APP_DIR/database/public_url.txt"
    echo "✓ Đã kết nối địa chỉ cố định: https://$DOMAIN"
    echo "  Nhật ký: $LOGS/ngrok.log"
    ;;
  status)
    for L in "$SERVER_LABEL" "$TS_LABEL" "$NGROK_LABEL"; do
      if launchctl print "gui/$UID_NUM/$L" >/dev/null 2>&1; then
        STATE=$(launchctl print "gui/$UID_NUM/$L" | awk -F'= ' '/state =/{print $2; exit}')
        echo "• $L: đã cài, trạng thái: ${STATE:-không rõ}"
      else
        echo "• $L: chưa cài"
      fi
    done
    "$TS_BIN" --socket="$TS_SOCK" set --accept-dns=false >/dev/null 2>&1 || true
    if [ -f "$APP_DIR/database/public_url.txt" ]; then
      PUB_HOST="$(cat "$APP_DIR/database/public_url.txt")"
      echo "• Địa chỉ cố định: https://$PUB_HOST"
      HTTP_CODE=$(curl -s -o /dev/null --connect-timeout 4 -m 6 -w "%{http_code}" "https://$PUB_HOST/" 2>/dev/null || true)
      echo "• Kiểm tra kết nối https://$PUB_HOST: HTTP $HTTP_CODE"
      if [ "$HTTP_CODE" != "200" ]; then
        echo "• Đang tự động làm mới kết nối Tailscale Funnel..."
        "$TS_BIN" --socket="$TS_SOCK" serve reset >/dev/null 2>&1 || true
        sleep 2
        "$TS_BIN" --socket="$TS_SOCK" funnel --bg "$PORT" >/dev/null 2>&1 || true
        sleep 3
        curl -v -s -o /dev/null --connect-timeout 5 -m 8 -w "• Kiểm tra lại https://$PUB_HOST: HTTP %{http_code} (IP: %{remote_ip})\n" "https://$PUB_HOST/" 2>&1 | grep -E "Trying|Connected to|SSL|HTTP/|Kiểm tra lại|error|Failed|timed out" || true
      fi
    fi
    curl -s -o /dev/null --connect-timeout 3 -m 5 -w "• Máy chủ trên máy (http://127.0.0.1:$PORT): HTTP %{http_code}\n" "http://127.0.0.1:$PORT/" || true
    curl -s -o /dev/null --connect-timeout 4 -m 6 -w "• Đường dẫn dự phòng Cloudflare (https://hired-dover-nyc-fame.trycloudflare.com): HTTP %{http_code}\n" "https://hired-dover-nyc-fame.trycloudflare.com/" || true
    "$TS_BIN" --socket="$TS_SOCK" funnel status 2>/dev/null || true
    ;;
  restart)
    launchctl kickstart -k "gui/$UID_NUM/$SERVER_LABEL" && echo "✓ Đã khởi động lại máy chủ."
    ;;
  uninstall)
    for L in "$SERVER_LABEL" "$TS_LABEL" "$TS_APP_LABEL" "$NGROK_LABEL"; do
      launchctl bootout "gui/$UID_NUM/$L" 2>/dev/null || true
      rm -f "$AGENTS/$L.plist"
    done
    echo "✓ Đã tắt tự khởi động. (Dữ liệu và báo cáo không bị ảnh hưởng.)"
    ;;
  *)
    sed -n '2,13p' "$0"
    ;;
esac
