#!/bin/bash
cd "$(dirname "$0")"
# Load env
export $(grep -v '^#' .env | xargs)
# Start in background
nohup python3 collector.py > /tmp/leakmon-collector.log 2>&1 &
echo "collector started: $!"
nohup python3 dorker.py > /tmp/leakmon-dorker.log 2>&1 &
echo "dorker started: $!"
nohup python3 dashboard.py > /tmp/leakmon-dashboard.log 2>&1 &
echo "dashboard started: $!"
echo "Dashboard: http://127.0.0.1:8787 (Admin/P@ssw0rd)"
