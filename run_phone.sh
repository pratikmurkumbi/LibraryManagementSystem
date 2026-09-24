#!/data/data/com.termux/files/usr/bin/bash
set -e
cd "$(dirname "$0")"
python -m py_compile app.py
echo "Starting Library Management System V9..."
python app.py
