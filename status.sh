#!/bin/bash
echo "=== Processes ==="
pgrep -af "collector.py|dorker.py|dashboard.py" 2>&1
echo -e "\n=== Dashboard ==="
curl -s -u Admin:$(grep DASHBOARD_PASS .env | cut -d= -f2) http://127.0.0.1:8787/ 2>&1 | grep -A1 "<h1>"
