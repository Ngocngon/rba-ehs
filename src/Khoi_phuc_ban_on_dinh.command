#!/bin/bash
# Khôi phục bản ổn định gần nhất khi hệ thống không khởi động được (macOS)
cd "$(dirname "$0")"
python3 restore_backup.py
echo
read -p "Nhập 'latest' để khôi phục bản ổn định gần nhất, hoặc tên tệp sao lưu (Enter để thoát): " CHOICE
if [ -n "$CHOICE" ]; then python3 restore_backup.py "$CHOICE"; fi
read -p "Nhấn Enter để đóng..."
