# 🛡️ HERMES SECURITY — Autonomous Vulnerability Scanner

---

My family was going through financial difficulties.

When I saw this hackathon, I thought — maybe I can do something.
Did I join for the money? Yes, I'll be honest about that.
But I also genuinely saw a problem and wanted to solve it.

I've been working with WordPress sites for a long time.
While setting up and maintaining client sites, I always saw the same thing:
Site owners have no idea how exposed their websites are.
Getting a security audit done is either too expensive or too technical.

*Why can't everyone learn about the security of their own site?*

That question is what opened Hermes for me.

The hardest part of the hackathon was getting everything to work together —
nmap, Hermes-4-405B, frontend, Telegram, GitHub hunter, ArXiv, Excalidraw...
All of it running simultaneously on a real server.

When it worked, I felt proud. But I'm still not fully satisfied.
And that feeling didn't stop me — it kept me building.

🌐 **https://hermes-intel.duckdns.org**

---

## ⚕️ Hermes-4-405B — AI Making Decisions at Every Step

This is not a simple "scan and show results" tool.
Hermes-4-405B is active at every endpoint — analyzing, learning, writing fixes.

All AI calls go through `inference-api.nousresearch.com/v1/chat/completions`. The primary model is **Hermes-4-405B**; if it fails, it automatically falls back to **Hermes-3-70B**, then **Hermes-3-8B**. Each endpoint has a different system prompt — security analysis requires JSON output, chat mode uses natural language, ArXiv commentary produces a 2-sentence summary. Running at `max_tokens: 8000`, `temperature: 0.3` for consistent and technical output.

---

## 🔍 Full Scan — 8-Layer Real-Time Analysis Pipeline

The `/api/full-scan` endpoint runs 8 different checks with a single HTTP request:

**1. Reachability + SSL** — HTTPS connection tested via `requests.get()`. SSL errors, connection errors, and HTTP-only cases are caught separately. 5 critical HTTP security headers (CSP, X-Frame-Options, XCTO, HSTS, Referrer-Policy) are checked and `headers_score` is calculated as a percentage.

**2. nmap Port Scanning** — Real nmap call via `subprocess.run()`: `-T4 --open -sV -p 80,443,8080,8443,22,21,3306,5432,6379,27017`. Output is parsed with regex, extracting port/service/version. Timeout: 15 seconds.

**3. robots.txt Check** — Fetched using the correct protocol based on HTTP/HTTPS status. Presence and content length are verified.

**4. SSL Certificate Expiry** — Python's `ssl` and `socket` modules connect to port 443 to retrieve the certificate. `notAfter` field is parsed with `datetime` to calculate `ssl_days_left` and `ssl_expiry`.

**5. DNS/IP Change Detection** — Current IP retrieved via `socket.gethostbyname()`. Compared against the previous IP stored in `/tmp/hermes-dns-{domain}.txt`. If changed, `dns_changed: true` is returned.

**6. HTTP→HTTPS Redirect Check** — HTTP request sent with `allow_redirects=False`. For 301/302/307/308 status codes, the `Location` header is checked for HTTPS prefix.

**7. Google Safe Browsing** — A simple GET to Google Transparency Report searches for `dangerous` or `malware` keywords. Blacklist detection is performed.

**8. Defacement Detection** — MD5 hash of the first 5000 characters of the homepage is stored in `/tmp/hermes-content-{domain}.txt`. Compared on every scan. If changed, `content_changed: true` is returned.

All of this data is sent to Hermes-4-405B in a single prompt. The model returns JSON with 5-8 detailed `findings`, `score`, `threat_assessment`, `critical_actions`, and `auto_fix`.

---

## 🔬 38 Security Tests — Independent Frontend-Side Checks

Beyond the backend data, 38 separate security tests run via JavaScript inside `index.html`. Each test returns PASS / WARN / INFO:

- SSL/TLS certificate validity and days remaining
- HTTPS redirect enforcement
- HTTP Security Headers: CSP, X-Frame-Options, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- Exposed sensitive files: `.env`, `.git`, `wp-config.php`, `phpinfo.php`, `backup.zip`
- Directory listing detection
- Error message disclosure
- Password leakage in URL parameters
- SQL injection passive detection
- XSS reflection detection
- Admin panel exposure (`/admin`, `/wp-admin`, `/administrator`)
- Backup file checks (`.bak`, `.old`, `.backup`)
- Mixed content (HTTP resources on HTTPS pages)
- CORS policy analysis
- CSRF token presence
- CVE database lookup for detected service versions
- HTTP/2 and HTTP/3 support
- Cookie security flags (Secure, HttpOnly, SameSite)
- Clickjacking protection
- Content sniffing protection
- And more

---

## ⚡ delegate_task — True Parallel Agent Architecture

The `/api/delegate` endpoint uses Python `threading.Thread`. A separate thread is spawned for each domain — up to 3 parallel agents. Each thread independently runs an nmap scan and sends a separate analysis request to Hermes-4-405B. Threads are joined with a 90-second timeout. Results are collected in a `results` dict and returned as a single JSON response.

If the API is unreachable, a browser-side fallback activates automatically: a basic score is generated from SSL presence, and the user sees no error.

---

## 🤖 Autonomous Issue Hunter — Symphony #404 Inspired

The `_issue_hunter_loop()` function runs in a background daemon thread. It keeps running even when the page is refreshed.

**Flow:**

1. `_fetch_github_issues()` — Sends `GET /repos/{owner}/{repo}/issues` to the GitHub API. Filtered by `state=open` and specified labels.

2. **Claim** — Unclaimed issues are added to `_issue_hunter_state['claimed']` dict. `_add_label()` attaches a `hermes-claimed` label to the GitHub issue.

3. **Hermes Analysis** — Issue title and body are sent to Hermes-4-405B. The model returns JSON with: `understood`, `root_cause`, `fix_type` (patch/nginx_config/bash_script), `fix_code`, `test_commands`, `confidence` (HIGH/MEDIUM/LOW), `estimated_effort` (S/M/L/XL), `pr_title`.

4. **CI Simulation** — If `confidence` is HIGH or MEDIUM, CI PASS; if LOW, CI FAIL. A realistic CI pipeline behavior is simulated.

5. **PR Comment** — `_post_github_comment()` posts a comment to the GitHub issue containing the fix code, test commands, and CI result.

6. **Poll** — The loop repeats after the configured interval (default: 60 seconds).

**One-Shot Test** — The `/api/issue-hunter/analyze-one` endpoint allows analyzing any issue title + body pair without a live repo connection.

---

## 📡 Domain Intel — Passive Reconnaissance Engine

The `/api/domain-intel` endpoint collects data from 4 sources:

- **crt.sh** — Subdomain discovery via certificate transparency logs. All certificates fetched using `q=%.{domain}` pattern. Subdomains parsed from `name_value` field. Up to 40 unique subdomains returned.

- **Google DoH (DNS over HTTPS)** — A, AAAA, MX, NS, TXT, CNAME records fetched from `dns.google/resolve` API. No external libraries — pure HTTP requests.

- **SSL Certificate Details** — Python `ssl` + `socket` modules connect to port 443 to retrieve the certificate. Subject, issuer, notBefore, notAfter, SAN list (up to 15 entries), version, and days remaining are extracted.

- **Hermes AI Risk Analysis** — All data is combined into a single prompt sent to Hermes. Returns `risk_level`, `exposure_score`, `key_findings`, `recommendations`, `summary`.

---

## 📄 ArXiv Integration — Academic CVE Research

The `/api/arxiv-search` endpoint uses the ArXiv Atom API. The `search_query` parameter is built as `all:{term} AND (cat:cs.CR OR cat:cs.NI OR cat:cs.SE)`. Categories covered: `cs.CR` (Cryptography and Security), `cs.NI` (Networking and Internet Architecture), `cs.SE` (Software Engineering).

XML response is parsed with `xml.etree.ElementTree`. For each paper: title, summary (400 chars), link, PDF link, publication date, and first 3 authors are extracted. PDF link is automatically generated by converting `abs` → `pdf` in the URL.

Hermes-4-405B produces a 2-sentence relevance assessment for the top result.

---

## 🗺️ Excalidraw Diagram — AI-Powered Network Map

The `/api/diagram` endpoint generates Excalidraw JSON entirely in Python — no external libraries.

`rect()`, `text()`, `arrow()` functions produce dicts in Excalidraw element format. Every element includes a unique ID counter, `versionNonce`, `boundElements`, `strokeColor`, `backgroundColor`, `roundness`, and all required fields.

Color coding: score ≥80 → `#00875a` (green), ≥60 → `#ff991f` (orange), ≥40 → `#ff7452`, <40 → `#de350b` (red). Risky ports (21, 22, 23, 3306, 5432, 6379, 27017) are red; safe ports are blue. Critical/High findings are shown in separate boxes connected to the server with arrows.

Output can be exported as `.excalidraw` or `.svg`. Hermes AI produces a 2-3 sentence architectural analysis of the diagram.

---

## 🧠 AI Learning — Persistent Self-Improving Memory

After every scan, Hermes-4-405B extracts a reusable security rule from the scan results and stores it in `skill_learned`. This pattern is written to `/var/www/html/hermes-skills.json` with domain, score, and timestamp.

**How it works:**
- Each scan → Hermes analyzes findings → extracts 1 unique security rule
- Rules are categorized automatically: SSL/TLS, Port Security, HTTP Headers, SQLi/XSS, CDN/Proxy, Misconfig, DNS/Infra
- Duplicate detection: if the same skill already exists for that domain, it is skipped
- The last 50 skills are retained in memory

**Frontend visualization** (`🧠 AI Learning` tab):
- Skill accumulation over time chart (Chart.js line)
- Knowledge Category Radar — shows which security domains Hermes has mastered
- Knowledge Nodes — clickable category filters
- Memory Log — every learned pattern with domain, score, category badge, timestamp

**Proof of real learning:** 13 domains scanned, 13 unique patterns stored. Each one different — from "implement security headers" on low-score sites to "comprehensive multi-layer security posture" on perfect 100/100 scores.

The `/skills` GET endpoint returns all stored skills for dashboard consumption.

---

## 🧬 Recon Lab — Full Threat Intelligence

The Recon Lab tab provides a dedicated passive reconnaissance interface for any domain — independent of the main scan flow.

**Three modes:**
- **Full Recon** — runs all checks in parallel: WHOIS, DNS, SSL, subdomains, AI assessment
- **WHOIS** — registrar, creation/expiry dates, country, status via Hermes AI inference from HTTP headers
- **DNS/SSL** — Google DoH records + certificate chain details

**Output panels:**
- Hermes-4-405B Intelligence Assessment with key findings and recommendations
- WHOIS & Registration details
- Technology Stack detection (CMS, server, CDN/WAF, frontend/backend frameworks, analytics, security layers)
- DNS Records table (A, AAAA, MX, NS, TXT, CNAME)
- SSL Certificate details (issuer, subject, expiry, SAN list)
- Subdomain discovery via crt.sh certificate transparency (up to 40 subdomains)
- Recent targets history

Auto-fills domain from the last completed scan when the tab is opened.

---

## ✈️ Telegram Integration

Two-layer Telegram system:

**1. tg_bot.py** — Standalone Python bot using long polling. Handles `/scan`, `/summary`, `/findings`, `/domainintel`, `/arxiv` commands. Last 10 messages per user stored in `chat_histories` dict. Non-command messages are routed to `/api/chat` for natural language conversation with Hermes-4-405B.

**2. hermes-addons.js** — The Telegram button in the frontend calls `sendTelegramAlert()`. Score, risk bar, SSL status, top findings, domain intel, and ArXiv results are POST-ed in Markdown format to `api.telegram.org/bot{TOKEN}/sendMessage`.

---

## ⏰ Nightly Cron — Personalized Automated Scanning

The `/api/cronjob` endpoint dynamically generates a bash script for each user and registers it in crontab. Script name format: `hermes-scan-{domain}-{chat_id}.sh` — unique per user/domain pair.

Multiple users are automatically staggered: existing `hermes-scan-` entries are counted, each new entry shifts by 2 minutes (02:00, 02:02, 02:04...). Log files are kept separately at `/var/log/hermes-scan-{domain}.log`.

Inside each script, all values are parsed from `/api/full-scan` output using Python3 one-liners: score, critical/high/medium/low counts, port list, HTTPS status, SSL expiry, DNS IP, defacement status, Google blacklist.

---

## 🔧 SWE Agent — Automatic Fix Generation

The `/api/swe-agent` endpoint takes a vulnerability + target domain and assigns Hermes-4-405B the "mini-swe-agent" role. The model produces:

- `understanding` — Why the vulnerability exists
- `fix_type` — nginx_config / bash_script / code_patch
- `fix_code` — Complete, deploy-ready fix code
- `test_commands` — List of commands to verify the fix
- `before_after` — Vulnerable vs. secure config comparison
- `confidence` — HIGH / MEDIUM / LOW

On the frontend, clicking the "Auto-Fix" button next to any finding calls this endpoint and displays the result immediately.

---

## 📊 PDF Export

jsPDF library is used inside `hermes-addons.js`. Dark theme: background `#040c10`, header bar `rgba(0,255,136,0.15)`, score color dynamic. Score ring drawn as SVG. Vuln counts read from DOM via `data-hermes-{level}` attributes. Log lines color-coded by OK/WARN/ERROR status. File name auto-generated as `hermes-report-{domain}-{timestamp}.pdf`.

---

## 💎 Wallet Guard — On-Chain Security Analysis

Live on-chain data fetched via Etherscan API: ETH balance, transaction count, token list, wallet age. Overview, Transactions, and Token/NFT tabs displayed separately. All data sent to Hermes-4-405B for behavioral risk analysis. Risk Score calculated from 0-100, wallet profile determined (HODLer, Trader, Suspicious, etc.).

---

## 📊 Live Stats API — Real-Time Dashboard

Two new endpoints power the live threat dashboard:

**`GET /api/stats`** — Returns aggregated data from scan history logs: total scans, last scan result (domain, score, SSL status, findings breakdown), skills count, uptime, and top scanned domains.

**`GET /api/scan-history?days=N`** — Parses nightly cron log files to build a daily scan count + average score timeline for the last N days. Used to render the live dashboard charts.

Both endpoints feed the live dashboard with real server-side data — no mock values.

---

## 🏗️ Technical Stack

```
Backend     → Python 3 / Flask / Flask-CORS / gunicorn (4 workers)
AI          → Hermes-4-405B (primary) → Hermes-3-70B → Hermes-3-8B (fallback)
AI API      → inference-api.nousresearch.com/v1/chat/completions
Port Scan   → nmap (-T4 --open -sV)
DNS         → Google DoH (dns.google/resolve)
Subdomains  → crt.sh certificate transparency
ArXiv       → export.arxiv.org Atom API + xml.etree.ElementTree
Diagram     → Native Python Excalidraw JSON generation
PDF         → jsPDF (browser-side)
Blockchain  → Etherscan API
Bot         → Python requests + long polling
Infra       → Ubuntu 24, nginx reverse proxy, systemd, crontab
Frontend    → Vanilla JS, IBM Plex font, Chart.js
Memory      → hermes-skills.json (persistent skill storage)
```

---

As a student, my reasons for joining this hackathon were both personal and technical.
But in the end, what emerged was something that surpassed me.

*Security should be accessible to people who don't know the terminal.*
*Anyone with a WordPress site should be able to use this.*
*Hermes makes that possible.*

🌐 **https://hermes-intel.duckdns.org**
⚕️ **Powered by Hermes-4-405B — Nous Research**
