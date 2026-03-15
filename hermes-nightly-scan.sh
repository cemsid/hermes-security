#!/bin/bash
DOMAIN="thebeautyfan.com"
TG_TOKEN="YOUR_TELEGRAM_BOT_TOKEN"
TG_CHAT="1069318856"
TIMESTAMP=$(date -u +"%Y-%m-%d %H:%M UTC")

# Full scan via Hermes API
RESULT=$(curl -s -X POST "http://localhost:5000/api/full-scan" \
  -H "Content-Type: application/json" \
  -d "{\"domain\":\"$DOMAIN\"}")

# Parse results
SCORE=$(echo $RESULT | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('score',0))")
CRITICAL=$(echo $RESULT | python3 -c "import sys,json; d=json.load(sys.stdin); print(len([f for f in d.get('findings',[]) if f['level']=='critical']))")
HIGH=$(echo $RESULT | python3 -c "import sys,json; d=json.load(sys.stdin); print(len([f for f in d.get('findings',[]) if f['level']=='high']))")
MEDIUM=$(echo $RESULT | python3 -c "import sys,json; d=json.load(sys.stdin); print(len([f for f in d.get('findings',[]) if f['level']=='medium']))")
TOP=$(echo $RESULT | python3 -c "import sys,json; d=json.load(sys.stdin); f=d.get('findings',[]); print(f[0]['title'] if f else 'No issues')")

# Score emoji
if [ "$SCORE" -ge 80 ]; then EMOJI="🟢"; RISK="LOW RISK"
elif [ "$SCORE" -ge 60 ]; then EMOJI="🟡"; RISK="MEDIUM RISK"
elif [ "$SCORE" -ge 40 ]; then EMOJI="🟠"; RISK="HIGH RISK"
else EMOJI="🔴"; RISK="CRITICAL"; fi

MSG="🌙 *HERMES NIGHTLY REPORT*
━━━━━━━━━━━━━━━━━━━━━━
🎯 *Target:* \`$DOMAIN\`
🕐 $TIMESTAMP

$EMOJI *Score: $SCORE/100* — $RISK

📋 *FINDINGS*
🔴 Critical: $CRITICAL  🟠 High: $HIGH  🟡 Medium: $MEDIUM

🔍 *Top Issue:*
$TOP

━━━━━━━━━━━━━━━━━━━━━━
🤖 _Hermes-4-405B Autonomous Agent_"

curl -s -X POST "https://api.telegram.org/bot${TG_TOKEN}/sendMessage" \
  -H "Content-Type: application/json" \
  -d "{\"chat_id\":\"$TG_CHAT\", \"text\":\"$MSG\", \"parse_mode\":\"Markdown\"}" > /dev/null

echo "[$TIMESTAMP] Scan complete — Score: $SCORE | Critical: $CRITICAL | High: $HIGH"
