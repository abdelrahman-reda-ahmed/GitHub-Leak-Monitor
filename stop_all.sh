#!/bin/bash
pkill -f "collector.py|dorker.py|dashboard.py|alerts.py" 2>&1
echo "stopped"
