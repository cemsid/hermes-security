#!/bin/bash
while true; do
    echo "[$(date)] Starting Hermes Bot..."
    python3 /var/www/html/tg_bot.py
    echo "[$(date)] Bot crashed, restarting in 5s..."
    sleep 5
done
