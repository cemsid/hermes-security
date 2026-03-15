#!/bin/bash
while true; do
    echo "[$(date)] Starting Hermes API..."
    pkill -9 -f gunicorn 2>/dev/null
    fuser -k 5000/tcp 2>/dev/null
    sleep 2
    cd /var/www/html && gunicorn -w 4 -b 0.0.0.0:5000 --timeout 300 api:app
    echo "[$(date)] API crashed, restarting in 5s..."
    sleep 5
done
