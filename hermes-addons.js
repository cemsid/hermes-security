// ═══════════════════════════════════════════════════════════════
//  HERMES SECURITY — PDF Export + Telegram Alert
//  /var/www/html/hermes-addons.js
//
//  KURULUM:
//  1. Bu dosyayı /var/www/html/hermes-addons.js olarak yükle
//  2. index.html </body> öncesine ekle:
//     <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>
//     <script src="hermes-addons.js"></script>
//  3. TELEGRAM_BOT_TOKEN ve TELEGRAM_CHAT_ID değerlerini doldur
// ═══════════════════════════════════════════════════════════════

// ── CONFIG — bunları doldur ───────────────────────────────────
const HERMES_CONFIG = {
  TELEGRAM_BOT_TOKEN: 'YOUR_TELEGRAM_BOT_TOKEN',   // @BotFather'dan al
  TELEGRAM_CHAT_ID:   '1069318856',     // @userinfobot'tan al
  SITE_NAME: 'Hermes Security Scanner',
  VERSION: 'v2.0'
};

// ═══════════════════════════════════════════════════════════════
//  TELEGRAM ALERT
// ═══════════════════════════════════════════════════════════════
async function sendTelegramAlert(scanData) {
  const { target, score, vulns, ssl, timestamp, findings, domainIntel, issueHunter, arxiv } = scanData;
  const scoreEmoji = score >= 80 ? '🟢' : score >= 60 ? '🟡' : score >= 40 ? '🟠' : '🔴';
  const sslEmoji = ssl ? '🔒' : '⚠️';
  const riskBar = score >= 80 ? '🟩🟩🟩🟩🟩' : score >= 60 ? '🟨🟨🟨🟩🟩' : score >= 40 ? '🟧🟧🟨🟩🟩' : '🟥🟥🟧🟨🟩';
  const total = (vulns?.critical||0)+(vulns?.high||0)+(vulns?.medium||0)+(vulns?.low||0);
  const topFindings = (findings||[]).filter(f=>['critical','high','medium'].includes(f.level)).slice(0,3);
  const findingsText = topFindings.length > 0 ? topFindings.map((f,i)=>`${i+1}. [${f.level.toUpperCase()}] ${f.title}`).join('\n') : '✅ No critical issues';
  const intelText = domainIntel ? `🌍 IP: ${domainIntel.ip||'N/A'} | 📍 ${domainIntel.country||'N/A'} | 🏢 ${domainIntel.org||'N/A'}` : '🌍 Not available';
  const issueText = issueHunter?.length > 0 ? issueHunter.slice(0,2).map(i=>`🐛 ${i}`).join('\n') : '🐛 No issues detected';
  const arxivText = arxiv?.length > 0 ? arxiv.slice(0,2).map(a=>`📄 ${a.title||a}`).join('\n') : '📄 No related papers';
  const msg = `⚕ *HERMES SECURITY REPORT*
━━━━━━━━━━━━━━━━━━━━━━
🎯 *Target:* \`${target}\`
🕐 ${new Date(timestamp||Date.now()).toLocaleString()}

${scoreEmoji} *Score: ${score}/100* ${riskBar}
🏷 *Risk:* ${score>=80?'LOW RISK ✅':score>=60?'MEDIUM RISK ⚠️':score>=40?'HIGH RISK 🚨':'CRITICAL 🆘'}
${sslEmoji} SSL: ${ssl?'Valid ✅':'MISSING ❌'}

━━━━━━━━━━━━━━━━━━━━━━
📋 *FINDINGS (${total} total)*
🔴 Critical: ${vulns?.critical||0}  🟠 High: ${vulns?.high||0}
🟡 Medium: ${vulns?.medium||0}  🔵 Low: ${vulns?.low||0}

🔍 *TOP ISSUES*
${findingsText}

━━━━━━━━━━━━━━━━━━━━━━
🌐 *DOMAIN INTEL*
${intelText}

🐛 *ISSUE HUNTER*
${issueText}

📚 *ARXIV RESEARCH*
${arxivText}

━━━━━━━━━━━━━━━━━━━━━━
🤖 _Hermes-4-405B — Nous Research Hackathon 2025_
🔗 hermes-intel.duckdns.org`.trim();

  try {
    const res = await fetch(
      `https://api.telegram.org/bot${HERMES_CONFIG.TELEGRAM_BOT_TOKEN}/sendMessage`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: HERMES_CONFIG.TELEGRAM_CHAT_ID,
          text: msg,
          parse_mode: 'Markdown'
        })
      }
    );
    const data = await res.json();
    if (data.ok) {
      showToast('✓ Telegram alert sent!', 'green');
      addLog('OK', 'Telegram alert sent successfully');
    } else {
      console.error('[Hermes] Telegram error:', data);
      showToast('✗ Telegram failed: ' + data.description, 'red');
    }
  } catch (err) {
    console.error('[Hermes] Telegram fetch error:', err);
    showToast('✗ Telegram unreachable', 'red');
  }
}

// ═══════════════════════════════════════════════════════════════
//  PDF EXPORT
// ═══════════════════════════════════════════════════════════════

function exportPDF() {
  // Scan verilerini DOM'dan oku
  const target    = document.getElementById('targetInput')?.value
                 || document.querySelector('.scan-target, [data-target]')?.textContent
                 || 'Unknown Target';
  const score     = document.querySelector('.score-number')?.textContent || '—';
  const grade     = document.querySelector('.score-grade')?.textContent  || '—';
  const ssl       = document.querySelector('[data-hermes-ssl], .ssl-status')?.textContent || '—';
  const timestamp = new Date().toLocaleString();

  // Log satırlarını topla
  const logLines = [];
  document.querySelectorAll('.log-entry, .t-line, [data-log]').forEach(el => {
    logLines.push(el.textContent.trim());
  });

  // jsPDF
  if (!window.jspdf) {
    showToast('⟳ Loading PDF library...', 'yellow');
    const script = document.createElement('script');
    script.src = 'https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js';
    script.onload = () => { window.jspdf = window.jspdf || jspdf; exportPDF(); };
    document.head.appendChild(script);
    return;
  }

  const { jsPDF } = window.jspdf;
  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });

  const W = 210, margin = 20;
  let y = margin;

  // ── Arka plan ──
  doc.setFillColor(4, 12, 16);
  doc.rect(0, 0, W, 297, 'F');

  // ── Header bar ──
  doc.setFillColor(0, 255, 136, 0.15);
  doc.rect(0, 0, W, 35, 'F');

  doc.setFont('courier', 'bold');
  doc.setFontSize(18);
  doc.setTextColor(0, 255, 136);
  doc.text('HERMES SECURITY REPORT', margin, 15);

  doc.setFontSize(8);
  doc.setTextColor(74, 85, 104);
  doc.text('AUTONOMOUS VULNERABILITY SCANNER // NOUS RESEARCH HACKATHON 2025', margin, 22);
  doc.text(`Generated: ${timestamp}`, margin, 28);

  y = 45;

  // ── Score section ──
  const scoreNum = parseInt(score) || 0;
  const scoreColor = scoreNum >= 80 ? [0,255,136] : scoreNum >= 60 ? [255,204,0] : scoreNum >= 40 ? [255,102,0] : [255,34,68];

  doc.setFillColor(15, 25, 35);
  doc.rect(margin, y, W - margin*2, 40, 'F');
  doc.setDrawColor(...scoreColor);
  doc.rect(margin, y, W - margin*2, 40);

  doc.setFont('courier', 'bold');
  doc.setFontSize(36);
  doc.setTextColor(...scoreColor);
  doc.text(score, margin + 10, y + 25);

  doc.setFontSize(9);
  doc.setTextColor(200, 210, 220);
  doc.text('SECURITY SCORE', margin + 10, y + 33);

  doc.setFontSize(14);
  doc.setTextColor(...scoreColor);
  doc.text(grade || (scoreNum >= 80 ? 'EXCELLENT — SECURE' : scoreNum >= 60 ? 'WARNING' : 'AT RISK'), margin + 55, y + 22);

  doc.setFontSize(9);
  doc.setTextColor(74, 85, 104);
  doc.text(`SSL: ${ssl}`, margin + 55, y + 32);

  y += 50;

  // ── Target info ──
  doc.setFont('courier', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(74, 85, 104);
  doc.text('// TARGET', margin, y);
  y += 5;
  doc.setFontSize(11);
  doc.setTextColor(0, 170, 255);
  doc.text(target, margin, y);
  y += 12;

  // ── Divider ──
  doc.setDrawColor(30, 42, 56);
  doc.line(margin, y, W - margin, y);
  y += 8;

  // ── Vuln summary ──
  doc.setFontSize(8);
  doc.setTextColor(74, 85, 104);
  doc.text('// VULNERABILITY SUMMARY', margin, y);
  y += 7;

  const vulnItems = [
    { label: 'CRITICAL', color: [255, 34, 68] },
    { label: 'HIGH',     color: [255, 102, 0] },
    { label: 'MEDIUM',   color: [255, 204, 0] },
    { label: 'LOW',      color: [0, 255, 136] },
  ];

  vulnItems.forEach((v, i) => {
    const x = margin + i * 42;
    const count = document.querySelector(`[data-hermes-${v.label.toLowerCase()}], .vuln-${v.label.toLowerCase()}-count`)?.textContent || '0';
    doc.setFillColor(15, 25, 35);
    doc.rect(x, y, 38, 18, 'F');
    doc.setDrawColor(...v.color);
    doc.rect(x, y, 38, 18);
    doc.setFont('courier', 'bold');
    doc.setFontSize(16);
    doc.setTextColor(...v.color);
    doc.text(count, x + 5, y + 12);
    doc.setFont('courier', 'normal');
    doc.setFontSize(6);
    doc.setTextColor(74, 85, 104);
    doc.text(v.label, x + 5, y + 16);
  });

  y += 26;

  // ── Divider ──
  doc.setDrawColor(30, 42, 56);
  doc.line(margin, y, W - margin, y);
  y += 8;

  // ── Log lines ──
  doc.setFontSize(8);
  doc.setTextColor(74, 85, 104);
  doc.text('// HERMES AGENT LOG', margin, y);
  y += 6;

  const printLines = logLines.slice(-30); // son 30 satır
  doc.setFont('courier', 'normal');
  doc.setFontSize(6.5);

  printLines.forEach(line => {
    if (y > 275) return;
    const isOK   = line.includes('OK') || line.includes('✓');
    const isWarn = line.includes('WARN') || line.includes('⚠');
    const isErr  = line.includes('ERROR') || line.includes('✗') || line.includes('CRITICAL');
    doc.setTextColor(
      isErr  ? 255 : isWarn ? 255 : isOK ? 0   : 74,
      isErr  ? 34  : isWarn ? 204 : isOK ? 200 : 85,
      isErr  ? 68  : isWarn ? 0   : isOK ? 120 : 104
    );
    doc.text(line.substring(0, 90), margin, y);
    y += 4.5;
  });

  y += 5;

  // ── Footer ──
  doc.setDrawColor(30, 42, 56);
  doc.line(margin, 282, W - margin, 282);
  doc.setFontSize(7);
  doc.setTextColor(74, 85, 104);
  doc.text('HERMES SECURITY SCANNER v2.0 — NOUS RESEARCH HACKATHON 2025', margin, 288);
  doc.text(`SCAN TIME: ${timestamp}`, W - margin - 60, 288);

  // ── Kaydet ──
  const filename = `hermes-report-${target.replace(/[^a-z0-9]/gi, '-')}-${Date.now()}.pdf`;
  doc.save(filename);
  showToast('✓ PDF exported: ' + filename, 'green');
  addLog('OK', 'Security report exported as PDF');
}

// ═══════════════════════════════════════════════════════════════
//  HELPERS
// ═══════════════════════════════════════════════════════════════

function showToast(msg, type = 'green') {
  const colors = { green: '#00ff88', red: '#ff2244', yellow: '#ffaa00' };
  const toast = document.createElement('div');
  toast.textContent = msg;
  toast.style.cssText = `
    position: fixed; bottom: 2rem; right: 2rem; z-index: 9999;
    background: #0f1923; border: 1px solid ${colors[type]};
    color: ${colors[type]}; font-family: monospace; font-size: 0.75rem;
    padding: 0.8rem 1.2rem; letter-spacing: 0.1em;
    animation: fadeUp 0.3s ease;
    box-shadow: 0 0 20px ${colors[type]}33;
  `;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 4000);
}

function addLog(level, text) {
  // Mevcut log container'a satır ekle
  const container = document.getElementById("logBody");
  if (!container) return;
  const row = document.createElement('div');
  row.className = "log-line";
  const time = new Date().toLocaleTimeString();
  const colors = { OK: '#00ff88', WARN: '#ffaa00', ERROR: '#ff2244', INFO: '#00aaff' };
  row.innerHTML = `
    <span style="color:#4a5568">${time}</span>
    <span style="background:${colors[level]||'#4a5568'};color:#000;padding:1px 6px;font-size:0.6rem;font-weight:bold;margin:0 8px">${level}</span>
    <span style="color:#e8edf3">${text}</span>
  `;
  container.appendChild(row);
  container.scrollTop = container.scrollHeight;
}

// ═══════════════════════════════════════════════════════════════
//  BUTONLARI INJECT ET
// ═══════════════════════════════════════════════════════════════

function injectButtons() {
  // Scan butonunun yanına ekle
  const scanBtn = document.getElementById('scanBtn') || document.querySelector('.scan-btn');
  if (!scanBtn) return;

  // PDF butonu
  const pdfBtn = document.createElement('button');
  pdfBtn.id = 'pdfExportBtn';
  pdfBtn.textContent = '⬇ EXPORT PDF';
  pdfBtn.style.cssText = scanBtn.style.cssText || '';
  pdfBtn.style.cssText += `
    background: transparent;
    border: 1px solid rgba(0,170,255,0.4);
    color: #00aaff;
    font-family: monospace;
    font-size: 0.7rem;
    letter-spacing: 0.15em;
    padding: 0 1.5rem;
    height: 48px;
    cursor: pointer;
    margin-left: 8px;
    transition: all 0.2s;
    text-transform: uppercase;
  `;
  pdfBtn.onmouseover = () => pdfBtn.style.background = 'rgba(0,170,255,0.1)';
  pdfBtn.onmouseout  = () => pdfBtn.style.background = 'transparent';
  pdfBtn.onclick     = exportPDF;

  // Telegram butonu
  const tgBtn = document.createElement('button');
  tgBtn.id = 'telegramBtn';
  tgBtn.textContent = '✈ TELEGRAM ALERT';
  tgBtn.style.cssText = `
    background: transparent;
    border: 1px solid rgba(0,136,204,0.4);
    color: #0088cc;
    font-family: monospace;
    font-size: 0.7rem;
    letter-spacing: 0.15em;
    padding: 0 1.5rem;
    height: 48px;
    cursor: pointer;
    margin-left: 8px;
    transition: all 0.2s;
    text-transform: uppercase;
  `;
  tgBtn.onmouseover = () => tgBtn.style.background = 'rgba(0,136,204,0.1)';
  tgBtn.onmouseout  = () => tgBtn.style.background = 'transparent';
  tgBtn.onclick     = () => {
    const score = parseInt(document.querySelector('.score-number')?.textContent || 0);
    const target = document.getElementById('targetInput')?.value || 'unknown';
    const ssl = document.querySelector('[data-hermes-ssl]')?.textContent?.includes('VALID');
    sendTelegramAlert({ target, score, ssl, vulns: { critical: 0, high: 0, medium: 0, low: 0 }, timestamp: Date.now() });
  };

  scanBtn.parentNode.insertBefore(pdfBtn, scanBtn.nextSibling);
  scanBtn.parentNode.insertBefore(tgBtn, pdfBtn.nextSibling);
}

// ── Scan bitince otomatik Telegram at ────────────────────────
