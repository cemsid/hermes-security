import requests
import threading, json, time

TOKEN = 'YOUR_TELEGRAM_BOT_TOKEN'
BASE  = 'https://api.telegram.org/bot' + TOKEN
API   = 'http://127.0.0.1:5000'
offset = 0

chat_histories = {}

# ─────────────────────────────────────────
#  TELEGRAM HELPERS
# ─────────────────────────────────────────

def send(chat_id, text):
    try:
        r = requests.post(BASE + '/sendMessage', json={
            'chat_id': chat_id,
            'text': text,
            'parse_mode': 'HTML',
            'disable_web_page_preview': True
        }, timeout=10)
        if r.status_code == 400:
            # HTML parse hatası — parse_mode olmadan tekrar gönder
            r = requests.post(BASE + '/sendMessage', json={
                'chat_id': chat_id,
                'text': text,
                'disable_web_page_preview': True
            }, timeout=10)
        print(f'[send] status={r.status_code} response={r.text[:100]}')
    except Exception as e:
        print(f'[send] ERROR: {e}')

def send_typing(chat_id):
    try:
        requests.post(BASE + '/sendChatAction', json={
            'chat_id': chat_id,
            'action': 'typing'
        }, timeout=5)
    except:
        pass

def get_history(chat_id):
    return chat_histories.get(str(chat_id), [])

def add_to_history(chat_id, role, content):
    key = str(chat_id)
    if key not in chat_histories:
        chat_histories[key] = []
    chat_histories[key].append({'role': role, 'content': content})
    chat_histories[key] = chat_histories[key][-10:]

# ─────────────────────────────────────────
#  LOAD LAST SCAN FROM FILE
# ─────────────────────────────────────────

def load_scan():
    try:
        with open('/var/www/html/scan-results.json') as f:
            return json.load(f)
    except:
        return {}

# ─────────────────────────────────────────
#  COMMAND HANDLERS
# ─────────────────────────────────────────

def cmd_start(chat_id):
    send(chat_id,
        '⚕ <b>HERMES SECURITY BOT</b>\n\n'
        'Autonomous AI security agent powered by Hermes-4-405B.\n\n'
        '<b>📋 Commands:</b>\n'
        '/scan [domain] — Full security scan (30-60s)\n'
        '/summary [domain] — Risk overview\n'
        '/findings [domain] — All vulnerabilities found\n'
        '/domainintel [domain] — IP, DNS, SSL, subdomains\n'
        '/arxiv [query] — Academic CVE research\n'
        '/clear — Clear conversation history\n\n'
        '💬 Or just chat with me about security!\n\n'
        '🔗 hermes-intel.duckdns.org'
    )

def cmd_summary(chat_id, target=''):
    if target:
        cmd_scan(chat_id, target)
        return
    send(chat_id, '\U0001F4CA Please enter a domain:\n\nUsage: /summary example.com')
    return
def cmd_findings(chat_id, target=''):
    if target:
        cmd_scan(chat_id, target)
        return
    send(chat_id, '🔍 Please enter a domain:\n\nUsage: /findings example.com')
    return
def cmd_domainintel(chat_id, target):
    if not target:
        send(chat_id, '🌐 Please enter a domain:\n\nUsage: /domainintel example.com\n\nExample: /domainintel thebeautyfan.com')
        return
    send_typing(chat_id)
    send(chat_id, f'🌐 <b>DOMAIN INTEL — {target}</b>\n⏳ Running recon... (30-60s)')
    try:
        r = requests.post(API + '/domain-intel', json={'domain': target}, timeout=60).json()
        dns      = r.get('dns', {})
        ssl_cert = r.get('ssl_cert', {})
        subs     = r.get('subdomains', [])
        ai       = r.get('ai_analysis', {}) or {}
        a_rec    = ', '.join(dns.get('A', []))[:80] or 'N/A'
        mx_rec   = ', '.join(dns.get('MX', []))[:80] or 'N/A'
        ns_rec   = ', '.join(dns.get('NS', []))[:80] or 'N/A'
        if 'error' not in ssl_cert:
            issuer = ssl_cert.get('issuer', {}).get('organizationName', 'N/A')
            days   = ssl_cert.get('days_left', '?')
        else:
            issuer = '❌ ' + ssl_cert.get('error','')[:50]
            days   = 'N/A'
        risk     = ai.get('risk_level', '?')
        summary  = ai.get('summary', '')[:300]
        findings = '\n'.join([f'• {f}' for f in ai.get('key_findings', [])[:3]])
        subs_txt = ', '.join(subs[:5]) + (f' +{len(subs)-5} more' if len(subs)>5 else '') if subs else 'None found'
        send(chat_id,
            f'🌐 <b>DOMAIN INTEL — {target}</b>\n'
            f'━━━━━━━━━━━━━━━━━━━━━━\n'
            f'🔵 A Record: {a_rec}\n'
            f'📬 MX: {mx_rec}\n'
            f'🔧 NS: {ns_rec}\n\n'
            f'🔒 SSL Issuer: {issuer}\n'
            f'📅 Expires in: {days} days\n\n'
            f'🗂 Subdomains: {subs_txt}\n\n'
            f'🤖 AI Risk: <b>{risk}</b>\n'
            + (f'🔍 Findings:\n{findings}\n' if findings else '')
            + (f'\n💬 {summary}' if summary else '')
            + '\n\n🔗 hermes-intel.duckdns.org'
        )
    except Exception as e:
        send(chat_id, f'❌ Domain intel failed: {str(e)}')

def cmd_arxiv(chat_id, query):
    if not query:
        send(chat_id, '⚠️ Usage: /arxiv XSS vulnerabilities\nor /arxiv CVE-2023-44487')
        return
    send_typing(chat_id)
    send(chat_id, f'📚 <b>ARXIV RESEARCH</b>\n⏳ Searching: <i>{query}</i>... (30-60s)')
    try:
        r = requests.post(API + '/arxiv-search', json={'query': query}, timeout=60).json()
        papers  = r.get('papers', [])
        ai_note = r.get('ai_comment', '')
        if not papers:
            send(chat_id, f'📚 No papers found for: {query}')
            return
        lines = [f'📚 <b>ARXIV — {query}</b>\n']
        for i, p in enumerate(papers[:4], 1):
            title   = p.get('title', '?')[:80]
            authors = ', '.join(p.get('authors', []))[:60]
            date    = p.get('published', '?')
            link    = p.get('link', '')
            lines.append(f'{i}. <b>{title}</b>\n   👤 {authors} ({date})\n   🔗 {link}')
        if ai_note:
            lines.append(f'\n🤖 <i>{ai_note[:300]}</i>')
        send(chat_id, '\n\n'.join(lines))
    except Exception as e:
        send(chat_id, f'❌ ArXiv search failed: {str(e)}')

def cmd_scan(chat_id, target):
    if not target:
        send(chat_id, '⚠️ Usage: /scan example.com')
        return
    send(chat_id,
        f'🔍 <b>Hermes Agent scanning...</b>\n\n'
        f'🎯 Target: {target}\n'
        f'⏳ nmap + AI analysis running...\n\n'
        f'<i>This may take 30-60 seconds. Please wait.</i>'
    )
    try:
        r = requests.post(API + "/full-scan", json={"domain": target}, timeout=300).json()
        if r.get('error'):
            send(chat_id, '❌ Scan failed: ' + r.get('error', 'Unknown error'))
            return
        s        = r.get('score', 0)
        d        = r.get('domain', target)
        f_list   = r.get('findings', [])
        is_https = r.get('is_https', False)
        crit = sum(1 for f in f_list if f.get('level') == 'critical')
        high = sum(1 for f in f_list if f.get('level') == 'high')
        med  = sum(1 for f in f_list if f.get('level') == 'medium')
        low  = sum(1 for f in f_list if f.get('level') == 'low')
        riskBar   = '🟩🟩🟩🟩🟩' if s>=80 else '🟨🟨🟨🟩🟩' if s>=60 else '🟧🟧🟨🟩🟩' if s>=40 else '🟥🟥🟧🟨🟩'
        riskLabel = 'LOW RISK ✅' if s>=80 else 'MEDIUM RISK ⚠️' if s>=60 else 'HIGH RISK 🚨' if s>=40 else 'CRITICAL 🆘'
        top   = [f for f in f_list if f.get('level') in ['critical','high','medium']][:3]
        findings_text = '\n'.join([f'{i+1}. [{f.get("level","?").upper()}] {f.get("title","?")}' for i,f in enumerate(top)]) if top else '✅ No critical issues'
        ai     = r.get('hermes_analysis', {})
        threat = ai.get('threat_assessment', '')[:200] if ai else ''
        memory = ai.get('skill_learned', '')
        try:
            with open('/var/www/html/scan-results.json', 'w') as _f:
                json.dump(r, _f)
        except:
            pass
        if memory:
            try:
                skills_file = '/var/www/html/hermes-skills.json'
                try:
                    with open(skills_file) as _sf:
                        skills = json.load(_sf)
                    if not isinstance(skills, list):
                        skills = []
                except:
                    skills = []
                skills.append({'domain': d, 'skill': memory, 'timestamp': time.strftime('%Y-%m-%d %H:%M')})
                # Write to Hermes real memory
                try:
                    with open('/root/.hermes/memories/MEMORY.md', 'a') as _mf:
                        _mf.write(f'\n\ntopic: security scan {d}\n{memory}\nScanned: {time.strftime("%Y-%m-%d %H:%M")} | Score: {s}/100')
                except:
                    pass
                skills = skills[-50:]
                with open(skills_file, 'w') as _sf:
                    json.dump(skills, _sf)
            except:
                pass
        send(chat_id,
            f'⚕ <b>SCAN COMPLETE</b>\n'
            f'━━━━━━━━━━━━━━━━━━━━━━\n'
            f'🎯 <b>{d}</b>\n\n'
            f'{s}/100 {riskBar}\n'
            f'🏷 {riskLabel}\n'
            f'{"🔒" if is_https else "⚠️"} SSL: {"Valid ✅" if is_https else "MISSING ❌"}\n\n'
            f'🔴 Critical: {crit}  🟠 High: {high}\n'
            f'🟡 Medium: {med}  🔵 Low: {low}\n\n'
            f'🔍 <b>TOP ISSUES</b>\n{findings_text}'
            + (f'\n\n🤖 {threat}' if threat else '')
            + (f'\n\n🧠 <i>Memory: {memory}</i>' if memory else '')
            + '\n\n🔗 hermes-intel.duckdns.org'
        )
    except Exception as e:
        send(chat_id, '❌ Scan failed: ' + str(e))

# ─────────────────────────────────────────
#  AI CHAT — Nous Hermes-4
# ─────────────────────────────────────────

def _ai_chat_worker(chat_id, text):
    add_to_history(chat_id, 'user', text)
    try:
        r = requests.post(
            API + '/api/chat',
            json={'message': text, 'history': get_history(chat_id)[:-1]},
            timeout=120
        )
        if r.status_code == 200:
            full = r.json().get('reply', 'No response.')
            main = full.split('\n\n⏳')[0].strip()
            add_to_history(chat_id, 'assistant', main)
            # Telegram 4096 karakter limiti — böl
            msg = '⚕ ' + main
            if len(msg) <= 4096:
                send(chat_id, msg)
            else:
                chunks = [msg[i:i+4000] for i in range(0, len(msg), 4000)]
                for chunk in chunks:
                    send(chat_id, chunk)
        else:
            send(chat_id, '❌ Hermes AI unavailable.')
    except Exception as e:
        send(chat_id, '❌ Error: ' + str(e))

def ai_chat(chat_id, text):
    send_typing(chat_id)
    threading.Thread(target=_ai_chat_worker, args=(chat_id, text), daemon=True).start()

# ─────────────────────────────────────────
#  MESSAGE ROUTER
# ─────────────────────────────────────────

def handle(msg):
    text    = msg.get('text', '').strip()
    chat_id = msg['chat']['id']
    print(f'[handle] chat_id={chat_id} text={text[:50]}')
    if not text:
        return

    # Normalize: lowercase, strip @BotName suffix
    cmd_raw = text.split('@')[0].lower()
    parts   = cmd_raw.split()
    cmd     = parts[0]
    args    = ' '.join(parts[1:])

    if cmd in ['/start', '/help']:
        cmd_start(chat_id)

    elif cmd == '/clear':
        chat_histories.pop(str(chat_id), None)
        send(chat_id, '🗑 Conversation history cleared.')

    elif cmd == '/scan':
        cmd_scan(chat_id, args)

    elif cmd == '/summary':
        cmd_summary(chat_id, args)

    elif cmd == '/findings':
        cmd_findings(chat_id, args)

    elif cmd in ['/domainintel', '/domain_intel']:
        cmd_domainintel(chat_id, args)

    elif cmd in ['/arxiv', '/arxivresearch']:
        cmd_arxiv(chat_id, args)

    else:
        # Free AI chat with Nous Hermes-4
        ai_chat(chat_id, text)

# ─────────────────────────────────────────
#  MAIN LOOP
# ─────────────────────────────────────────

print('⚕ Hermes Bot started...')
# Başlangıçta bekleyen eski mesajları temizle
try:
    r = requests.get(BASE + '/getUpdates', params={'offset': -1, 'timeout': 1}, timeout=5)
    updates = r.json().get('result', [])
    if updates:
        offset = updates[-1]['update_id'] + 1
        print(f'⚕ Skipped old messages, starting from offset {offset}')
except:
    pass
while True:
    try:
        r = requests.get(BASE + '/getUpdates', params={'offset': offset, 'timeout': 30}, timeout=35)
        updates = r.json().get('result', [])
        for u in updates:
            offset = u['update_id'] + 1
            if 'message' in u:
                threading.Thread(target=handle, args=(u['message'],), daemon=True).start()
    except KeyboardInterrupt:
        break
    except Exception as e:
        print('Error: ' + str(e))
        time.sleep(5)
