// ═══════════════════════════════════════════════════════
//  HERMES SECURITY — Live Data Integration
//  /var/www/html/hermes-live.js
//  index.html </body> öncesine ekle:
//  <script src="hermes-live.js"></script>
// ═══════════════════════════════════════════════════════

(function () {

  // ── JSON'u parse et & skor hesapla ─────────────────────
  function parseScan(data) {
    const ports = data.open_ports || [];
    let score = 100;
    let high = 0, medium = 0, low = 0;

    const riskyPorts = { 21: 25, 23: 30, 3306: 20, 5432: 20, 27017: 25, 6379: 25, 3389: 15, 8080: 5, 8443: 3 };

    ports.forEach(p => {
      if (riskyPorts[p.port]) {
        score -= riskyPorts[p.port];
        if (p.port <= 23 || p.port === 3389) high++;
        else medium++;
      }
    });

    const info = data.additional_information || {};
    if (info.filtered_ports > 5) { score -= 5; low++; }

    // SSL var mı kontrol (443 açıksa iyi)
    const hasSSL = ports.some(p => p.port === 443);
    if (!hasSSL) { score -= 15; high++; }

    score = Math.max(0, Math.min(100, score));
    return { target: data.scan_target, ports, score, high, medium, low, hasSSL, info, date: data.scan_date };
  }

  // ── Renk hesapla ───────────────────────────────────────
  function scoreColor(s) {
    if (s >= 80) return '#00ff88';
    if (s >= 60) return '#ffaa00';
    if (s >= 40) return '#ff6600';
    return '#ff2244';
  }

  function scoreLabel(s) {
    if (s >= 80) return 'SECURE';
    if (s >= 60) return 'WARNING';
    if (s >= 40) return 'AT RISK';
    return 'CRITICAL';
  }

  // ── UI Güncelle ────────────────────────────────────────
  function updateUI(scan) {
    const color = scoreColor(scan.score);

    // Score sayısı (sitede .score-number veya benzeri class'a yaz)
    document.querySelectorAll('.score-number, .score-value, [data-hermes-score]').forEach(el => {
      el.textContent = scan.score;
      el.style.color = color;
    });

    // SVG Ring güncelle
    document.querySelectorAll('circle.progress, .ring-progress, [data-hermes-ring]').forEach(ring => {
      const r = parseFloat(ring.getAttribute('r') || ring.r?.baseVal?.value || 70);
      const circ = 2 * Math.PI * r;
      ring.style.stroke = color;
      ring.style.transition = 'stroke-dashoffset 1.5s ease, stroke 0.5s ease';
      ring.style.strokeDasharray = circ;
      ring.style.strokeDashoffset = circ - (scan.score / 100) * circ;
    });

    // Vuln sayaçları
    const map = { high: scan.high, medium: scan.medium, low: scan.low, critical: 0 };
    Object.entries(map).forEach(([k, v]) => {
      document.querySelectorAll(`[data-hermes-${k}], .vuln-${k}-count, #${k}Count`).forEach(el => {
        el.textContent = v;
      });
    });

    // SSL badge
    document.querySelectorAll('[data-hermes-ssl], .ssl-status, #sslBadge').forEach(el => {
      el.textContent = scan.hasSSL ? '✓ VALID' : '✗ MISSING';
      el.style.color = scan.hasSSL ? '#00ff88' : '#ff2244';
    });

    // Status label
    document.querySelectorAll('[data-hermes-label], .score-label, #securityLabel').forEach(el => {
      el.textContent = scoreLabel(scan.score);
      el.style.color = color;
    });

    // Hermes terminal'e yaz
    injectTerminalLines(scan, color);

    // Port tablosunu doldur
    renderPortTable(scan.ports);

    // Timestamp
    document.querySelectorAll('[data-hermes-time], .scan-time, #lastScan').forEach(el => {
      el.textContent = 'HERMES SCAN: ' + new Date(scan.date).toLocaleString();
    });
  }

  // ── Terminal satırları ────────────────────────────────
  function injectTerminalLines(scan, color) {
    const term = document.querySelector('.terminal, #terminal, [data-hermes-terminal]');
    if (!term) return;

    const lines = [
      { cls: 't-prompt', text: '$ hermes --scan ' + scan.target + ' --live' },
      { cls: 't-muted',  text: '  Loading scan-results.json...' },
      { cls: 't-success',text: '  ✓ Hermes nmap data loaded' },
      { cls: 't-info',   text: `  Target: ${scan.target}` },
      { cls: 't-info',   text: `  Open ports: ${scan.ports.length} detected` },
      ...scan.ports.map(p => ({
        cls: (p.port === 8080 || p.port === 8443) ? 't-warn' : 't-success',
        text: `  ↳ ${p.port}/${p.protocol || 'TCP'} — ${p.service} (${p.version})`
      })),
      { cls: scan.hasSSL ? 't-success' : 't-warn', text: `  SSL: ${scan.hasSSL ? '✓ VALID (port 443)' : '✗ NOT DETECTED'}` },
      { cls: 't-muted',  text: `  Filtered ports: ${scan.info.filtered_ports || 0}` },
      { cls: scan.score >= 80 ? 't-success' : 't-warn', text: `  ► Security Score: ${scan.score}/100 — ${scoreLabel(scan.score)}` },
      { cls: 't-prompt', text: '$ _' },
    ];

    // Mevcut terminal'in altına ekle
    lines.forEach((l, i) => {
      setTimeout(() => {
        const div = document.createElement('div');
        div.className = `t-line ${l.cls}`;
        div.textContent = l.text;
        div.style.opacity = '0';
        div.style.animation = 'typeIn 0.3s forwards';
        term.appendChild(div);
        term.scrollTop = term.scrollHeight;
      }, 500 + i * 100);
    });
  }

  // ── Port tablosu ──────────────────────────────────────
  function renderPortTable(ports) {
    const container = document.querySelector('[data-hermes-ports], .ports-table, #portsContainer');
    if (!container) return;

    container.innerHTML = `
      <table style="width:100%;border-collapse:collapse;font-size:0.7rem;font-family:monospace">
        <tr style="color:#4a5568;border-bottom:1px solid #1e2a38">
          <th style="text-align:left;padding:0.4rem">PORT</th>
          <th style="text-align:left;padding:0.4rem">PROTO</th>
          <th style="text-align:left;padding:0.4rem">SERVICE</th>
          <th style="text-align:left;padding:0.4rem">VERSION</th>
          <th style="text-align:left;padding:0.4rem">RISK</th>
        </tr>
        ${ports.map(p => {
          const risky = [21,23,3306,5432,27017,6379,3389].includes(p.port);
          const warn  = [8080,8443].includes(p.port);
          const risk  = risky ? '🔴 HIGH' : warn ? '🟡 MED' : '🟢 LOW';
          const color = risky ? '#ff4444' : warn ? '#ffaa00' : '#00ff88';
          return `<tr style="border-bottom:1px solid #0d1117;transition:background 0.2s" 
                      onmouseover="this.style.background='#0f1923'" 
                      onmouseout="this.style.background='transparent'">
            <td style="padding:0.5rem;color:${color};font-weight:bold">${p.port}</td>
            <td style="padding:0.5rem;color:#4a5568">${p.protocol || 'TCP'}</td>
            <td style="padding:0.5rem;color:#e8edf3">${p.service}</td>
            <td style="padding:0.5rem;color:#00bfff;font-size:0.65rem">${p.version}</td>
            <td style="padding:0.5rem">${risk}</td>
          </tr>`;
        }).join('')}
      </table>
    `;
  }

  // ── HERMES LIVE DATA butonu inject et ────────────────
  function injectButton() {
    // Butonu ekleyecek alan: scan input'un yanı veya header
    const target = document.querySelector('.scan-controls, .input-row, header, .container');
    if (!target) return;

    const btn = document.createElement('button');
    btn.id = 'hermesLiveBtn';
    btn.textContent = '⚡ HERMES LIVE DATA';
    btn.style.cssText = `
      background: rgba(0,255,136,0.1);
      border: 1px solid rgba(0,255,136,0.4);
      color: #00ff88;
      font-family: monospace;
      font-size: 0.7rem;
      letter-spacing: 0.15em;
      padding: 0.6rem 1.2rem;
      cursor: pointer;
      transition: all 0.2s;
      text-transform: uppercase;
      margin-top: 0.5rem;
    `;
    btn.onmouseover = () => btn.style.background = 'rgba(0,255,136,0.2)';
    btn.onmouseout  = () => btn.style.background = 'rgba(0,255,136,0.1)';
    btn.onclick     = loadHermesData;

    target.appendChild(btn);
  }

  // ── JSON fetch & çalıştır ─────────────────────────────
  function loadHermesData() {
    const btn = document.getElementById('hermesLiveBtn');
    if (btn) { btn.textContent = '⟳ LOADING...'; btn.style.opacity = '0.6'; }

    fetch('/scan-results.json?t=' + Date.now())
      .then(r => {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
      })
      .then(data => {
        const scan = parseScan(data);
        updateUI(scan);
        if (btn) { btn.textContent = '✓ HERMES DATA LOADED'; btn.style.color = '#00ff88'; btn.style.opacity = '1'; }
        console.log('[Hermes] Live data loaded:', scan);
      })
      .catch(err => {
        console.error('[Hermes] Load failed:', err);
        if (btn) { btn.textContent = '✗ LOAD FAILED'; btn.style.color = '#ff2244'; btn.style.opacity = '1'; }
      });
  }

  // ── Init ──────────────────────────────────────────────
  window.addEventListener('load', () => {
    injectButton();

    // Otomatik yükle (isteğe bağlı — kapatmak için bu satırı sil)
    setTimeout(loadHermesData, 1500);
  });

  // Global erişim
  window.hermesLoadLiveData = loadHermesData;

})();
