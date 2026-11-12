/* AegisReview dashboard — views, routing, interactions. */
(() => {
  const state = {
    view: 'dashboard',
    scans: [],
    projects: [],
    stats: null,
    rules: null,
    currentScan: null,
    filters: { severity: 'all', q: '', showTriage: 'open' },
    authMode: 'login',
  };

  const view = () => document.getElementById('view');
  const $ = (sel) => document.querySelector(sel);

  const PAGES = {
    dashboard: ['Overview', 'Security posture across your projects'],
    scan: ['New scan', 'Paste code, drop a file, or upload a repository archive'],
    findings: ['Findings', 'Every issue from your scans, with remediation'],
    projects: ['Projects', 'Group scans by application'],
    rules: ['Rule catalog', 'What the engine detects and why'],
    api: ['API & CI', 'Automate Aegis in your pipeline'],
  };

  const SAMPLE = `import hashlib, pickle, sqlite3
from flask import Flask, request, send_file
import os

app = Flask(__name__)
app.secret_key = "s3cr3t"
conn = sqlite3.connect("shop.db")
UPLOADS = "/var/www/uploads"

@app.route("/login", methods=["POST"])
def login():
    email = request.form["email"]
    password = request.form["password"]
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE email = '{email}'")
    row = cur.fetchone()
    if row and row[2] == hashlib.md5(password.encode()).hexdigest():
        return {"ok": True, "user": row[0]}
    return {"ok": False}, 401

@app.route("/export")
def export():
    return send_file(os.path.join(UPLOADS, request.args["name"]))

@app.route("/import", methods=["POST"])
def restore():
    return {"restored": len(pickle.loads(request.data))}
`;

  /* ------------------------------------------------------------------ *
   * routing
   * ------------------------------------------------------------------ */
  function go(next) {
    if (!PAGES[next]) next = 'dashboard';
    state.view = next;
    document.querySelectorAll('.nav-item').forEach(el =>
      el.classList.toggle('active', el.dataset.view === next));
    const [title, sub] = PAGES[next];
    $('#page-title').textContent = title;
    $('#page-sub').textContent = sub;
    history.replaceState(null, '', `#${next}`);
    render();
  }

  async function render() {
    const host = view();
    host.innerHTML = `<div class="view">${UI.skeletonRows(6)}</div>`;
    try {
      if (state.view === 'dashboard') await renderDashboard(host);
      else if (state.view === 'scan') await renderScan(host);
      else if (state.view === 'findings') await renderFindings(host);
      else if (state.view === 'projects') await renderProjects(host);
      else if (state.view === 'rules') await renderRules(host);
      else if (state.view === 'api') renderApi(host);
    } catch (err) {
      host.innerHTML = `<div class="view">${UI.empty('Could not load this view', err.message)}</div>`;
    }
  }

  /* ------------------------------------------------------------------ *
   * dashboard
   * ------------------------------------------------------------------ */
  async function renderDashboard(host) {
    const [stats, scans, projects] = await Promise.all([
      AegisAPI.stats(), AegisAPI.scans(20), AegisAPI.projects(),
    ]);
    state.stats = stats; state.scans = scans; state.projects = projects;

    const latest = scans[0];
    const c = stats.by_severity;
    const totalFindings = Object.values(c).reduce((a, b) => a + b, 0);
    const trendDelta = scans.length > 1 ? scans[0].score - scans[scans.length - 1].score : 0;

    host.innerHTML = `<div class="view">
      <div class="grid g-hero">
        <div class="panel">
          <div class="panel-head"><h3>${UI.icon('shield', 15)} Latest scan</h3>
            <span class="sub">${latest ? UI.timeAgo(latest.created_at) : '—'}</span></div>
          <div class="panel-body" style="display:grid;place-items:center;gap:14px">
            ${UI.scoreRing(latest ? latest.score : 100, latest ? latest.grade : 'A+')}
            <div style="text-align:center">
              <div style="font-weight:650;font-size:14px;color:${latest && latest.score < 55 ? 'var(--critical)' : 'var(--good)'}">
                ${latest ? UI.esc(latest.verdict) : 'No scans yet'}</div>
              <div class="hint mt-8">${latest ? UI.esc(latest.target) : 'Run your first scan to get a score'}</div>
            </div>
            <div class="row" style="gap:6px;flex-wrap:wrap;justify-content:center">
              <span class="chip ${state.filters.showTriage === 'open' ? 'on' : ''}">${totalFindings} findings</span>
              <span class="chip">${stats.total_scans} scans</span>
              ${trendDelta !== 0 ? `<span class="chip" style="color:${trendDelta > 0 ? 'var(--good)' : 'var(--critical)'};border-color:${trendDelta > 0 ? 'var(--good)' : 'var(--critical)'}44">
                ${trendDelta > 0 ? '▲' : '▼'} ${Math.abs(trendDelta)} pts</span>` : ''}
            </div>
          </div>
        </div>

        <div class="grid" style="gap:16px">
          <div class="grid g-4">
            ${statTile('Scans run', stats.total_scans, `${stats.files_scanned} files analysed`, 'chart')}
            ${statTile('Findings', totalFindings, `all scans · ${c.critical || 0} critical`, 'alert', c.critical ? 'var(--critical)' : null)}
            ${statTile('Avg score', stats.avg_score, 'across all scans', 'shield')}
            ${statTile('Rules active', stats.rules_available, 'deterministic checks', 'bolt')}
          </div>

          <div class="panel">
            <div class="panel-head"><h3>${UI.icon('chart', 15)} Score trend</h3>
              <span class="sub">last ${stats.trend.length} scan${stats.trend.length === 1 ? '' : 's'}</span></div>
            <div class="panel-body tight">${UI.sparkline(stats.trend)}</div>
          </div>

          <div class="grid g-2">
            <div class="panel">
              <div class="panel-head"><h3>Severity mix</h3><span class="sub">all scans</span></div>
              <div class="panel-body">${UI.severityBars(c)}</div>
            </div>
            <div class="panel">
              <div class="panel-head"><h3>Top rules tripped</h3><span class="sub">all scans</span></div>
              <div class="panel-body tight">
                ${stats.top_rules.length ? stats.top_rules.slice(0, 4).map(r => `
                  <div class="list-row" style="padding:8px 4px;cursor:default">
                    <div class="lr-main">
                      <div class="lr-title" style="font-size:12.5px">${UI.esc(r.title)}</div>
                      <div class="lr-meta mono" style="font-size:10.5px">${UI.esc(r.rule_id)}</div>
                    </div>
                    <span class="bar-count">${r.count}</span>
                  </div>`).join('') : UI.empty('Nothing tripped yet')}
              </div>
            </div>
          </div>
        </div>
      </div>

      <div class="grid g-split mt-16">
        <div class="panel">
          <div class="panel-head"><h3>${UI.icon('clock', 15)} Recent scans</h3>
            <span class="sub">${scans.length} total</span></div>
          <div class="panel-body flush">
            ${scans.length ? scans.slice(0, 6).map(s => `
              <div class="list-row" data-scan="${s.id}">
                ${UI.scoreChip(s.score, s.grade)}
                <div class="lr-main">
                  <div class="lr-title">${UI.esc(s.target)}</div>
                  <div class="lr-meta">
                    ${s.n_critical ? `<span style="color:var(--critical)">${s.n_critical} critical</span> · ` : ''}
                    ${s.n_high ? `<span style="color:var(--high)">${s.n_high} high</span> · ` : ''}
                    ${s.files_scanned} files · ${UI.timeAgo(s.created_at)}
                  </div>
                </div>
                <span class="chev">${UI.icon('chev', 14)}</span>
              </div>`).join('') : UI.empty('No scans yet', 'Start with the New scan tab')}
          </div>
        </div>

        <div class="panel">
          <div class="panel-head"><h3>${UI.icon('folder', 15)} Projects</h3></div>
          <div class="panel-body flush">
            ${projects.length ? projects.slice(0, 5).map(p => `
              <div class="list-row" data-project="${p.id}">
                <div class="avatar" style="background:linear-gradient(140deg,var(--accent-2),#c4b5fd);color:#0b0518">${UI.esc(p.name.slice(0, 2).toUpperCase())}</div>
                <div class="lr-main">
                  <div class="lr-title">${UI.esc(p.name)}</div>
                  <div class="lr-meta">${p.scan_count} scans · ${p.open_findings} open</div>
                </div>
                ${p.latest_score != null ? UI.scoreChip(p.latest_score, p.latest_grade) : '<span class="hint">—</span>'}
              </div>`).join('') : UI.empty('No projects', 'Group scans by app to track regressions')}
          </div>
        </div>
      </div>
    </div>`;

    host.querySelectorAll('[data-scan]').forEach(el =>
      el.addEventListener('click', () => openScan(el.dataset.scan)));
    host.querySelectorAll('[data-project]').forEach(el =>
      el.addEventListener('click', () => go('projects')));
  }

  function statTile(label, value, meta, iconName, color) {
    return `<div class="panel stat">
      <div class="row between"><span class="stat-label">${UI.esc(label)}</span>
        <span style="color:${color || 'var(--text-mute)'};opacity:.8">${UI.icon(iconName, 15)}</span></div>
      <div class="stat-value" style="${color ? `color:${color}` : ''}">${value}</div>
      <div class="stat-meta">${UI.esc(meta)}</div>
    </div>`;
  }

  /* ------------------------------------------------------------------ *
   * scan view
   * ------------------------------------------------------------------ */
  async function renderScan(host) {
    const rules = state.rules || (state.rules = await AegisAPI.rules().catch(() => []));
    const langCount = new Set(rules.flatMap(r => r.languages)).size;
    host.innerHTML = `<div class="view">
      <div class="grid g-split">
        <div class="panel">
          <div class="panel-head">
            <h3>${UI.icon('upload', 15)} Analyse code</h3>
            <div class="tabs" style="margin-left:auto">
              <button class="tab on" data-mode="paste">Paste</button>
              <button class="tab" data-mode="upload">File / ZIP</button>
              <button class="tab" data-mode="repo">Repository</button>
            </div>
          </div>
          <div class="panel-body">
            <div id="mode-paste">
              <div class="field">
                <div class="row between">
                  <label for="code">Source code</label>
                  <span class="hint">Ctrl/⌘ + Enter to scan</span>
                </div>
                <textarea id="code" class="input-mono" style="min-height:290px" spellcheck="false"
                  placeholder="Paste code here…">${UI.esc(SAMPLE)}</textarea>
              </div>
              <div class="grid g-2 mt-16">
                <div class="field"><label for="filename">Filename (drives language detection)</label>
                  <input id="filename" value="app/views.py" class="input-mono"></div>
              </div>
              <div class="row mt-16">
                <button class="btn btn-primary" id="run-scan">${UI.icon('bolt', 14)} Run analysis</button>
                <button class="btn" id="load-sample">Load vulnerable sample</button>
                <span class="hint" style="margin-left:auto">Runs locally — nothing leaves your server</span>
              </div>
            </div>

            <div id="mode-repo" class="hide">
              <div class="field">
                <label for="repo-url">Public repository URL</label>
                <input id="repo-url" class="input-mono" placeholder="https://github.com/owner/repository" spellcheck="false">
                <div class="hint">Shallow-cloned, then analysed with all ${rules.length} rules. GitHub, GitLab, Bitbucket and Codeberg only.</div>
              </div>
              <div class="grid g-2 mt-16">
                <div class="field"><label>What happens</label>
                  <div class="hint" style="line-height:1.7">
                    1. URL validated against an allowlist<br>
                    2. <span class="mono" style="font-size:11px">git clone --depth 1</span>, symlinks disabled<br>
                    3. Tests, docs and vendored code excluded<br>
                    4. Shipped source analysed, clone deleted
                  </div>
                </div>
                <div class="field"><label>Limits</label>
                  <div class="hint" style="line-height:1.7">
                    60 MB / 12,000 files per repo<br>
                    90 s clone timeout<br>
                    10 repository scans per hour
                  </div>
                </div>
              </div>
              <div class="row mt-16">
                <button class="btn btn-primary" id="run-repo">${UI.icon('code', 14)} Clone &amp; analyse</button>
                <span class="hint" id="repo-status"></span>
              </div>
            </div>

            <div id="mode-upload" class="hide">
              <div class="dropzone" id="dropzone">
                ${UI.icon('upload', 30)}
                <div class="dz-title">Drop a file or .zip archive</div>
                <div class="dz-sub">Up to 5 MB per file · 25 MB per archive · node_modules excluded</div>
              </div>
              <input type="file" id="file-input" class="hide">
              <div class="row mt-16">
                <button class="btn btn-primary" id="browse">${UI.icon('folder', 14)} Choose file</button>
                <span class="hint" id="file-name"></span>
              </div>
            </div>
          </div>
        </div>

        <div class="grid" style="gap:16px;align-content:start">
          <div class="panel">
            <div class="panel-head"><h3>${UI.icon('shield', 15)} What gets checked</h3></div>
            <div class="panel-body">
              <div class="prose">${rules.length} deterministic rules across ${langCount} languages, mapped to CWE and OWASP Top 10. Every finding carries a data-flow trace when a value can be proven to flow from a request source into a dangerous sink.</div>
              <div class="sep"></div>
              <div class="row wrap" style="gap:6px">
                ${['SQLi', 'XSS', 'Command injection', 'Path traversal', 'Insecure deserialisation', 'Hardcoded secrets', 'Weak crypto', 'SSRF', 'XXE', 'IDOR', 'Open redirect', 'Buffer overflow', 'ReDoS', 'Zip-slip'].map(t => `<span class="chip" style="cursor:default">${t}</span>`).join('')}
              </div>
            </div>
          </div>
          <div class="panel">
            <div class="panel-head"><h3>${UI.icon('code', 15)} CLI equivalent</h3></div>
            <div class="panel-body">
              <div class="code-block" style="max-height:none"><div class="code-line"><span class="lc" style="color:var(--accent)">$</span><span class="lc" style="text-align:left;width:auto;padding-right:0">python -m aegis ./src --max-critical 0</span></div></div>
              <div class="hint mt-8">Same engine, same rules, exit code 1 on policy violation.</div>
            </div>
          </div>
        </div>
      </div>
    </div>`;

    host.querySelectorAll('[data-mode]').forEach(tab => tab.addEventListener('click', () => {
      host.querySelectorAll('[data-mode]').forEach(t => t.classList.toggle('on', t === tab));
      const mode = tab.dataset.mode;
      for (const m of ['paste', 'upload', 'repo']) {
        host.querySelector(`#mode-${m}`).classList.toggle('hide', m !== mode);
      }
    }));

    const repoBtn = host.querySelector('#run-repo');
    repoBtn.addEventListener('click', async () => {
      const url = host.querySelector('#repo-url').value.trim();
      if (!url) return UI.toast('Paste a repository URL first', 'err');
      const status = host.querySelector('#repo-status');
      repoBtn.disabled = true;
      repoBtn.innerHTML = `<span class="spinner"></span> Cloning…`;
      status.textContent = 'Cloning — this can take a few seconds.';
      try {
        const scan = await AegisAPI.scanRepo(url);
        UI.toast(`Scanned ${scan.files_scanned} files — score ${scan.score}/100`, 'ok');
        openScan(scan.id);
      } catch (e) {
        status.textContent = e.message;
        UI.toast(e.message, 'err');
        repoBtn.disabled = false;
        repoBtn.innerHTML = `${UI.icon('code', 14)} Clone &amp; analyse`;
      }
    });

    const runBtn = host.querySelector('#run-scan');
    runBtn.addEventListener('click', async () => {
      const code = host.querySelector('#code').value;
      const filename = host.querySelector('#filename').value || 'snippet.py';
      if (!code.trim()) return UI.toast('Paste some code first', 'err');
      runBtn.disabled = true;
      runBtn.innerHTML = `<span class="spinner"></span> Analysing…`;
      try {
        const scan = await AegisAPI.scanSnippet(code, filename);
        UI.toast(`Scan complete — ${scan.n_critical + scan.n_high + scan.n_medium + scan.n_low} findings`, scan.n_critical ? 'err' : 'ok');
        openScan(scan.id);
      } catch (e) {
        UI.toast(e.message, 'err');
        runBtn.disabled = false;
        runBtn.innerHTML = `${UI.icon('bolt', 14)} Run analysis`;
      }
    });

    host.querySelector('#load-sample').addEventListener('click', () => {
      host.querySelector('#code').value = SAMPLE;
      host.querySelector('#filename').value = 'app/views.py';
      UI.toast('Loaded a deliberately vulnerable Flask sample');
    });

    host.querySelector('#code').addEventListener('keydown', (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') runBtn.click();
    });

    const dz = host.querySelector('#dropzone');
    const fileInput = host.querySelector('#file-input');
    host.querySelector('#browse').addEventListener('click', () => fileInput.click());
    dz.addEventListener('click', () => fileInput.click());
    ['dragenter', 'dragover'].forEach(ev => dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.add('over'); }));
    ['dragleave', 'drop'].forEach(ev => dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.remove('over'); }));
    dz.addEventListener('drop', e => { if (e.dataTransfer.files.length) uploadFile(e.dataTransfer.files[0]); });
    fileInput.addEventListener('change', () => { if (fileInput.files.length) uploadFile(fileInput.files[0]); });

    async function uploadFile(file) {
      host.querySelector('#file-name').textContent = `${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
      UI.toast(`Analysing ${file.name}…`);
      try {
        const scan = await AegisAPI.scanUpload(file);
        UI.toast(`Scan complete — score ${scan.score}/100`, 'ok');
        openScan(scan.id);
      } catch (e) { UI.toast(e.message, 'err'); }
    }
  }

  /* ------------------------------------------------------------------ *
   * scan detail
   * ------------------------------------------------------------------ */
  async function openScan(id) {
    state.view = 'detail';
    document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
    $('#page-title').textContent = 'Scan result';
    $('#page-sub').textContent = 'Loading…';
    history.replaceState(null, '', `#scan/${id}`);
    const host = view();
    host.innerHTML = `<div class="view">${UI.skeletonRows(6)}</div>`;
    try {
      const scan = await AegisAPI.scan(id);
      state.currentScan = scan;
      renderScanDetail(host, scan);
    } catch (e) {
      host.innerHTML = `<div class="view">${UI.empty('Scan not found', e.message)}</div>`;
    }
  }

  function findingRow(f) {
    const trace = f.evidence && f.evidence.length > 1 ? `
      <div class="trace">
        <span class="tag src">source</span>
        <code class="mono" style="font-size:11.5px">${UI.esc(f.evidence[0].code)}</code>
        <span>→</span>
        <span class="tag sink">sink</span>
        <span class="mono" style="font-size:11.5px">line ${f.line}</span>
      </div>` : '';

    const lines = [f.line];
    if (f.evidence && f.evidence.length > 1) lines.unshift(f.evidence[0].line);
    const codeCtx = (f.evidence && f.evidence.length > 1)
      ? `<div class="code-block">
           <div class="code-line src"><span class="ln">${f.evidence[0].line}</span><span class="lc">${UI.esc(f.evidence[0].code)}</span></div>
           <div class="code-line hit"><span class="ln">${f.line}</span><span class="lc">${UI.esc(f.code)}</span></div>
         </div>`
      : `<div class="code-block"><div class="code-line hit"><span class="ln">${f.line}</span><span class="lc">${UI.esc(f.code)}</span></div></div>`;

    return `<div class="finding sev-${f.severity}" data-finding="${f.id}">
      <div class="finding-head">
        <span class="chev">${UI.icon('chev', 14)}</span>
        <div class="fh-main">
          <div class="fh-title">${UI.esc(f.title)} ${UI.sevBadge(f.severity)}</div>
          <div class="fh-meta">
            <span class="fh-loc">${UI.esc(f.file)}:${f.line}</span>
            <span class="mono">${UI.esc(f.rule_id)}</span>
            <span>${UI.esc(f.cwe)}</span>
            <span class="hint">${UI.esc(f.confidence)} confidence</span>
            ${f.status !== 'open' ? `<span class="badge" style="--sc:var(--good)">${UI.esc(f.status)}</span>` : ''}
          </div>
        </div>
      </div>
      <div class="finding-body">
        ${codeCtx}
        ${trace}
        <div class="section-label">Why it matters</div>
        <div class="prose">${UI.rich(f.why)}</div>
        <div class="section-label">How to fix it</div>
        <div class="prose">${UI.rich(f.fix_hint)}</div>
        <div class="diff">
          <div class="diff-col diff-bad"><div class="diff-head">Vulnerable</div><pre>${UI.esc(f.vuln_example)}</pre></div>
          <div class="diff-col diff-good"><div class="diff-head">Fixed</div><pre>${UI.esc(f.fix_example)}</pre></div>
        </div>
        <div class="kv">
          <span><b>OWASP</b> ${UI.esc(f.owasp)}</span>
          <span><b>CWE</b> <a href="https://cwe.mitre.org/data/definitions/${UI.esc((f.cwe || '').replace(/\D/g, ''))}.html" target="_blank" rel="noopener">${UI.esc(f.cwe)}</a></span>
          <span><b>Language</b> ${UI.esc(f.language)}</span>
          <span><b>Fingerprint</b> <code class="mono">${UI.esc(f.fingerprint)}</code></span>
        </div>
        <div class="triage">
          <button class="btn btn-sm" data-triage="fixed" data-id="${f.id}">${UI.icon('check', 13)} Mark fixed</button>
          <button class="btn btn-sm" data-triage="false-positive" data-id="${f.id}">False positive</button>
          <button class="btn btn-sm" data-triage="ignored" data-id="${f.id}">Ignore</button>
          <input placeholder="Add a note…" data-note="${f.id}" value="${UI.esc(f.note || '')}">
        </div>
      </div>
    </div>`;
  }

  function renderScanDetail(host, scan) {
    const repoMeta = scan.meta && scan.meta.repo;
    $('#page-sub').textContent = repoMeta
      ? `${repoMeta.url} · ${scan.files_scanned} files · ${scan.lines_scanned} lines · ${repoMeta.size_mb} MB`
      : `${scan.target} · ${scan.files_scanned} files · ${scan.lines_scanned} lines`;

    const c = { critical: scan.n_critical, high: scan.n_high, medium: scan.n_medium, low: scan.n_low, info: scan.n_info };
    const breakdown = scan.rule_breakdown || [];

    host.innerHTML = `<div class="view">
      <div class="row between wrap" style="margin-bottom:16px">
        <button class="btn btn-sm btn-ghost" id="back">${UI.icon('chev', 13)} Back</button>
        <div class="row" style="gap:7px">
          <button class="btn btn-sm" data-export="html">${UI.icon('download', 13)} HTML</button>
          <button class="btn btn-sm" data-export="markdown">${UI.icon('download', 13)} Markdown</button>
          <button class="btn btn-sm" data-export="sarif">${UI.icon('download', 13)} SARIF</button>
          <button class="btn btn-sm" data-export="json">${UI.icon('download', 13)} JSON</button>
        </div>
      </div>

      <div class="grid g-hero">
        <div class="panel">
          <div class="panel-head"><h3>${UI.icon('shield', 15)} Result</h3>
            <span class="sub">${UI.timeAgo(scan.created_at)}</span></div>
          <div class="panel-body" style="display:grid;place-items:center;gap:12px">
            ${UI.scoreRing(scan.score, scan.grade, 150)}
            <div style="text-align:center">
              <div style="font-weight:650;color:${scan.score < 55 ? 'var(--critical)' : 'var(--good)'}">${UI.esc(scan.verdict)}</div>
              <div class="hint mt-8">${scan.files_scanned} files · ${scan.lines_scanned} lines · ${scan.duration_ms} ms</div>
            </div>
          </div>
        </div>

        <div class="grid" style="gap:16px;align-content:start">
          <div class="grid g-4">
            ${statTile('Critical', c.critical, 'immediate risk', 'alert', c.critical ? 'var(--critical)' : null)}
            ${statTile('High', c.high, 'fix before merge', 'alert', c.high ? 'var(--high)' : null)}
            ${statTile('Medium', c.medium, 'needs attention', 'chart', c.medium ? 'var(--medium)' : null)}
            ${statTile('Low', c.low, 'cleanup', 'chart', c.low ? 'var(--low)' : null)}
          </div>
          <div class="panel">
            <div class="panel-head"><h3>Rule breakdown</h3><span class="sub">${breakdown.length} distinct</span></div>
            <div class="panel-body tight">
              ${breakdown.length ? breakdown.slice(0, 5).map(r => `
                <div class="list-row" style="padding:8px 4px;cursor:default">
                  <i class="sev-dot sev-${r.severity}"></i>
                  <div class="lr-main">
                    <div class="lr-title" style="font-size:12.5px">${UI.esc(r.title)}</div>
                    <div class="lr-meta mono" style="font-size:10.5px">${UI.esc(r.rule_id)} · ${UI.esc(r.cwe)}</div>
                  </div>
                  <span class="bar-count">×${r.count}</span>
                </div>`).join('') : UI.empty('No findings', 'This code passed every rule')}
            </div>
          </div>
        </div>
      </div>

      <div class="panel mt-16">
        <div class="panel-head"><h3>Findings</h3>
          <span class="sub">${scan.findings.length} total</span></div>
        <div class="filters">
          <div class="row wrap" style="gap:6px" id="sev-filters">
            <button class="chip on" data-sev="all">All <span class="n">${scan.findings.length}</span></button>
            ${UI.SEV.filter(s => c[s]).map(s =>
              `<button class="chip" data-sev="${s}">${s} <span class="n">${c[s]}</span></button>`).join('')}
          </div>
          <div class="search">
            ${UI.icon('search', 14)}
            <input placeholder="Filter by title, file or rule…" id="f-search">
          </div>
        </div>
        <div class="panel-body flush" id="finding-list">
          ${scan.findings.length ? scan.findings.map(findingRow).join('') : UI.empty('Clean bill of health', 'No rule matched this code')}
        </div>
      </div>
    </div>`;

    $('#back').addEventListener('click', () => go('dashboard'));
    host.querySelectorAll('[data-export]').forEach(btn => btn.addEventListener('click', async () => {
      try { await AegisAPI.downloadExport(scan.id, btn.dataset.export); UI.toast('Report downloaded', 'ok'); }
      catch (e) { UI.toast(e.message, 'err'); }
    }));

    host.querySelectorAll('.finding-head').forEach(head => head.addEventListener('click', () => {
      head.parentElement.classList.toggle('open');
    }));

    host.querySelectorAll('[data-triage]').forEach(btn => btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const note = host.querySelector(`[data-note="${btn.dataset.id}"]`)?.value || null;
      try {
        await AegisAPI.triage(btn.dataset.id, btn.dataset.triage, note);
        UI.toast(`Marked ${btn.dataset.triage}`, 'ok');
        openScan(scan.id);
      } catch (err) { UI.toast(err.message, 'err'); }
    }));

    const list = host.querySelector('#finding-list');
    const applyFilters = () => {
      const q = (host.querySelector('#f-search').value || '').toLowerCase();
      const sev = host.querySelector('#sev-filters .chip.on')?.dataset.sev || 'all';
      scan.findings.forEach(f => {
        const el = list.querySelector(`[data-finding="${f.id}"]`);
        if (!el) return;
        const hay = `${f.title} ${f.file} ${f.rule_id} ${f.cwe}`.toLowerCase();
        const show = (sev === 'all' || f.severity === sev) && (!q || hay.includes(q));
        el.style.display = show ? '' : 'none';
      });
    };
    host.querySelector('#f-search').addEventListener('input', applyFilters);
    host.querySelectorAll('#sev-filters .chip').forEach(chip => chip.addEventListener('click', () => {
      host.querySelectorAll('#sev-filters .chip').forEach(c => c.classList.toggle('on', c === chip));
      applyFilters();
    }));
  }

  /* ------------------------------------------------------------------ *
   * findings (cross-scan)
   * ------------------------------------------------------------------ */
  async function renderFindings(host) {
    const scans = await AegisAPI.scans(30);
    const details = await Promise.all(scans.slice(0, 8).map(s => AegisAPI.scan(s.id).catch(() => null)));
    const all = [];
    details.filter(Boolean).forEach(s => s.findings.forEach(f => all.push({ ...f, scanId: s.id, scanTarget: s.target })));

    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    all.sort((a, b) => order[a.severity] - order[b.severity]);
    const counts = UI.SEV.reduce((acc, s) => (acc[s] = all.filter(f => f.severity === s).length, acc), {});

    host.innerHTML = `<div class="view">
      <div class="panel">
        <div class="panel-head"><h3>${UI.icon('alert', 15)} All findings</h3>
          <span class="sub">${all.length} across ${scans.length} scans</span></div>
        <div class="filters">
          <div class="row wrap" style="gap:6px" id="g-sev">
            <button class="chip on" data-sev="all">All <span class="n">${all.length}</span></button>
            ${UI.SEV.filter(s => counts[s]).map(s => `<button class="chip" data-sev="${s}">${s} <span class="n">${counts[s]}</span></button>`).join('')}
          </div>
          <div class="search">${UI.icon('search', 14)}<input id="g-search" placeholder="Search findings…"></div>
        </div>
        <div class="panel-body flush" id="g-list">
          ${all.length ? all.slice(0, 120).map(f => `
            <div class="list-row" data-scan="${f.scanId}">
              <i class="sev-dot sev-${f.severity}"></i>
              <div class="lr-main">
                <div class="lr-title">${UI.esc(f.title)}</div>
                <div class="lr-meta">
                  <span class="mono">${UI.esc(f.file)}:${f.line}</span> ·
                  ${UI.esc(f.scanTarget)} · ${UI.esc(f.cwe)}
                </div>
              </div>
              ${UI.sevBadge(f.severity)}
            </div>`).join('') : UI.empty('No findings yet', 'Run a scan to populate this list')}
        </div>
      </div>
    </div>`;

    host.querySelectorAll('[data-scan]').forEach(el => el.addEventListener('click', () => openScan(el.dataset.scan)));
    const apply = () => {
      const q = host.querySelector('#g-search').value.toLowerCase();
      const sev = host.querySelector('#g-sev .chip.on').dataset.sev;
      host.querySelectorAll('#g-list .list-row').forEach((row, i) => {
        const f = all[i];
        if (!f) return;
        const show = (sev === 'all' || f.severity === sev) &&
          (!q || `${f.title} ${f.file} ${f.cwe}`.toLowerCase().includes(q));
        row.style.display = show ? '' : 'none';
      });
    };
    host.querySelector('#g-search').addEventListener('input', apply);
    host.querySelectorAll('#g-sev .chip').forEach(c => c.addEventListener('click', () => {
      host.querySelectorAll('#g-sev .chip').forEach(x => x.classList.toggle('on', x === c));
      apply();
    }));
  }

  /* ------------------------------------------------------------------ *
   * projects
   * ------------------------------------------------------------------ */
  async function renderProjects(host) {
    const projects = await AegisAPI.projects();
    state.projects = projects;
    host.innerHTML = `<div class="view">
      <div class="grid g-split">
        <div class="panel">
          <div class="panel-head"><h3>${UI.icon('folder', 15)} Projects</h3>
            <span class="sub">${projects.length}</span></div>
          <div class="panel-body flush">
            ${projects.length ? projects.map(p => `
              <div class="list-row" style="cursor:default">
                <div class="avatar" style="background:linear-gradient(140deg,var(--accent-2),#c4b5fd);color:#0b0518">${UI.esc(p.name.slice(0, 2).toUpperCase())}</div>
                <div class="lr-main">
                  <div class="lr-title">${UI.esc(p.name)}</div>
                  <div class="lr-meta">${p.scan_count} scans · ${p.open_findings} open findings</div>
                </div>
                ${p.latest_score != null ? UI.scoreChip(p.latest_score, p.latest_grade) : '<span class="hint">no scans</span>'}
                <button class="btn btn-ghost btn-icon" data-del="${p.id}" title="Delete">${UI.icon('trash', 14)}</button>
              </div>`).join('') : UI.empty('No projects yet', 'Create one to group related scans')}
          </div>
        </div>
        <div class="panel">
          <div class="panel-head"><h3>${UI.icon('plus', 15)} New project</h3></div>
          <div class="panel-body">
            <div class="field"><label for="p-name">Name</label>
              <input id="p-name" placeholder="Payments API"></div>
            <div class="field mt-16"><label for="p-desc">Description</label>
              <textarea id="p-desc" placeholder="What this service does…" style="min-height:70px"></textarea></div>
            <div class="field mt-16"><label for="p-lang">Primary language</label>
              <select id="p-lang">
                <option value="">Auto-detect</option>
                ${['Python','JavaScript','TypeScript','Java','C','C++','PHP','Ruby','Go','C#','Rust','Kotlin'].map(l => `<option>${l}</option>`).join('')}
              </select></div>
            <button class="btn btn-primary mt-16" id="create-project" style="width:100%">${UI.icon('plus', 14)} Create project</button>
          </div>
        </div>
      </div>
    </div>`;

    host.querySelector('#create-project').addEventListener('click', async () => {
      const name = host.querySelector('#p-name').value.trim();
      if (!name) return UI.toast('Give the project a name', 'err');
      try {
        await AegisAPI.createProject(name, host.querySelector('#p-desc').value || null,
          host.querySelector('#p-lang').value || null);
        UI.toast('Project created', 'ok');
        renderProjects(host);
      } catch (e) { UI.toast(e.message, 'err'); }
    });

    host.querySelectorAll('[data-del]').forEach(btn => btn.addEventListener('click', async () => {
      if (!confirm('Delete this project and all its scans?')) return;
      try { await AegisAPI.deleteProject(btn.dataset.del); UI.toast('Deleted', 'ok'); renderProjects(host); }
      catch (e) { UI.toast(e.message, 'err'); }
    }));
  }

  /* ------------------------------------------------------------------ *
   * rules
   * ------------------------------------------------------------------ */
  async function renderRules(host) {
    const rules = state.rules || (state.rules = await AegisAPI.rules());
    const counts = UI.SEV.reduce((a, s) => (a[s] = rules.filter(r => r.severity === s).length, a), {});

    host.innerHTML = `<div class="view">
      <div class="grid g-4" style="margin-bottom:16px">
        ${UI.SEV.slice(0, 4).map(s => statTile(s, counts[s], 'rules', 'shield', `var(--${s})`)).join('')}
      </div>
      <div class="panel">
        <div class="panel-head"><h3>${UI.icon('code', 15)} ${rules.length} rules</h3>
          <div class="search" style="margin-left:auto;max-width:260px">${UI.icon('search', 14)}
            <input id="r-search" placeholder="Search rules, CWE, OWASP…"></div></div>
        <div class="panel-body flush" id="rule-list">
          ${rules.map(r => `
            <div class="finding" data-rule>
              <div class="finding-head">
                <span class="chev">${UI.icon('chev', 14)}</span>
                <div class="fh-main">
                  <div class="fh-title">${UI.esc(r.title)} ${UI.sevBadge(r.severity)}</div>
                  <div class="fh-meta">
                    <span class="mono">${UI.esc(r.id)}</span>
                    <span>${UI.esc(r.cwe)}</span>
                    <span class="hint">${UI.esc(r.owasp)}</span>
                  </div>
                </div>
              </div>
              <div class="finding-body">
                <div class="section-label">Why it matters</div>
                <div class="prose">${UI.rich(r.why)}</div>
                <div class="section-label">Fix</div>
                <div class="prose">${UI.rich(r.fix_hint)}</div>
                <div class="row wrap mt-16" style="gap:6px">
                  ${r.languages.slice(0, 8).map(l => `<span class="chip" style="cursor:default">${UI.esc(l)}</span>`).join('')}
                  ${r.tags.map(t => `<span class="chip" style="cursor:default;color:var(--text-mute)">#${UI.esc(t)}</span>`).join('')}
                </div>
              </div>
            </div>`).join('')}
        </div>
      </div>
    </div>`;

    host.querySelectorAll('.finding-head').forEach(h => h.addEventListener('click', () =>
      h.parentElement.classList.toggle('open')));
    host.querySelector('#r-search').addEventListener('input', (e) => {
      const q = e.target.value.toLowerCase();
      host.querySelectorAll('[data-rule]').forEach(el => {
        el.style.display = el.textContent.toLowerCase().includes(q) ? '' : 'none';
      });
    });
  }

  /* ------------------------------------------------------------------ *
   * API docs
   * ------------------------------------------------------------------ */
  function renderApi(host) {
    const base = location.origin;
    const snippet = `# Scan a directory and fail the build on any critical finding
python -m aegis ./src --max-critical 0 --max-high 3

# Machine-readable output for GitHub code scanning
python -m aegis ./src -f sarif -o aegis.sarif

# Scan via the API (no auth needed for snippets)
curl -s ${base}/api/scans/snippet \\
  -H 'Content-Type: application/json' \\
  -d '{"code":"os.system(input())","filename":"x.py"}' | jq .score`;

    host.innerHTML = `<div class="view">
      <div class="grid g-split">
        <div class="panel">
          <div class="panel-head"><h3>${UI.icon('code', 15)} CLI &amp; CI</h3>
            <button class="btn btn-sm btn-ghost" id="copy-cli" style="margin-left:auto">${UI.icon('copy', 13)} Copy</button></div>
          <div class="panel-body">
            <div class="code-block" style="max-height:none;padding:12px"><pre style="margin:0;white-space:pre-wrap;font-family:var(--mono);font-size:12px;line-height:1.7">${UI.esc(snippet)}</pre></div>
          </div>
        </div>
        <div class="panel">
          <div class="panel-head"><h3>${UI.icon('bolt', 15)} GitHub Actions</h3></div>
          <div class="panel-body">
            <div class="code-block" style="max-height:none;padding:12px"><pre style="margin:0;white-space:pre-wrap;font-family:var(--mono);font-size:12px;line-height:1.7">${UI.esc(`- name: Aegis security gate
  run: |
    pip install -r requirements.txt
    python -m aegis ./src \\
      --max-critical 0 --max-high 0 --min-score 80

- name: Upload SARIF
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: aegis.sarif`)}</pre></div>
            <div class="hint mt-8">Exit code 1 fails the job, so insecure code cannot merge.</div>
          </div>
        </div>
      </div>

      <div class="panel mt-16">
        <div class="panel-head"><h3>Endpoints</h3>
          <a href="/docs" target="_blank" class="btn btn-sm" style="margin-left:auto">OpenAPI docs ↗</a></div>
        <div class="panel-body flush">
          ${[
            ['POST', '/api/scans/snippet', 'Scan an inline code snippet (no auth required)'],
            ['POST', '/api/scans/upload', 'Scan an uploaded file or .zip archive'],
            ['GET', '/api/scans', 'List your scans'],
            ['GET', '/api/scans/{id}', 'Full report with findings'],
            ['GET', '/api/scans/{id}/export?fmt=sarif', 'Export: sarif · json · markdown · html'],
            ['PATCH', '/api/findings/{id}', 'Triage: fixed / ignored / false-positive'],
            ['POST', '/api/ci/gate', 'Policy gate — returns 409 when the build should fail'],
            ['GET', '/api/stats', 'Aggregated posture metrics'],
            ['GET', '/api/rules', 'Full rule catalog'],
            ['POST', '/api/auth/login', 'JWT login'],
          ].map(([m, p, d]) => `
            <div class="list-row" style="cursor:default">
              <span class="badge" style="--sc:${m === 'GET' ? 'var(--accent)' : m === 'POST' ? 'var(--good)' : 'var(--medium)'};width:56px;justify-content:center">${m}</span>
              <div class="lr-main">
                <div class="lr-title mono" style="font-size:12.5px">${p}</div>
                <div class="lr-meta">${d}</div>
              </div>
            </div>`).join('')}
        </div>
      </div>
    </div>`;

    host.querySelector('#copy-cli').addEventListener('click', () => {
      navigator.clipboard.writeText(snippet).then(() => UI.toast('Copied to clipboard', 'ok'));
    });
  }

  /* ------------------------------------------------------------------ *
   * auth
   * ------------------------------------------------------------------ */
  function showAuth(mode = 'login') {
    state.authMode = mode;
    document.getElementById('auth-screen').classList.remove('hide');
    document.getElementById('app').classList.add('hide');
    const isLogin = mode === 'login';
    document.getElementById('auth-title').textContent = isLogin ? 'Sign in' : 'Create account';
    document.getElementById('auth-title').className = 'auth';
    document.getElementById('auth-sub').textContent = isLogin
      ? 'Continue to your security workspace.'
      : 'The first account created becomes the workspace admin.';
    document.getElementById('name-field').classList.toggle('hide', isLogin);
    document.getElementById('auth-submit').textContent = isLogin ? 'Sign in' : 'Create account';
    document.getElementById('auth-switch-text').textContent = isLogin ? 'No account?' : 'Already registered?';
    document.getElementById('auth-switch-link').textContent = isLogin ? 'Create one' : 'Sign in';
    document.getElementById('auth-error').classList.remove('show');
  }

  function showApp() {
    document.getElementById('auth-screen').classList.add('hide');
    document.getElementById('app').classList.remove('hide');
    const u = AegisAPI.user();
    if (u) {
      document.getElementById('user-name').textContent = u.full_name;
      document.getElementById('user-role').textContent = u.role;
      document.getElementById('user-avatar').textContent = (u.full_name || 'U').slice(0, 1).toUpperCase();
    }
    const hash = location.hash.replace('#', '');
    if (hash.startsWith('scan/')) openScan(hash.slice(5));
    else go(PAGES[hash] ? hash : 'dashboard');
  }

  async function boot() {
    document.querySelectorAll('.nav-item').forEach(el =>
      el.addEventListener('click', () => go(el.dataset.view)));
    document.getElementById('quick-scan').addEventListener('click', () => go('scan'));
    document.getElementById('logout').addEventListener('click', () => {
      AegisAPI.logout();
      showAuth('login');
    });

    document.getElementById('theme-toggle').addEventListener('click', (e) => {
      const btn = e.target.closest('[data-theme-set]');
      if (!btn) return;
      const theme = btn.dataset.themeSet;
      document.documentElement.setAttribute('data-theme', theme);
      localStorage.setItem('aegis.theme', theme);
      document.querySelectorAll('[data-theme-set]').forEach(b => b.classList.toggle('on', b === btn));
    });

    const savedTheme = localStorage.getItem('aegis.theme') || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);
    document.querySelectorAll('[data-theme-set]').forEach(b =>
      b.classList.toggle('on', b.dataset.themeSet === savedTheme));

    document.getElementById('auth-switch-link').addEventListener('click', (e) => {
      e.preventDefault();
      showAuth(state.authMode === 'login' ? 'register' : 'login');
    });
    document.getElementById('fill-demo').addEventListener('click', (e) => {
      e.preventDefault();
      document.getElementById('auth-email').value = 'demo@aegis.dev';
      document.getElementById('auth-password').value = 'aegis-demo-2024';
    });

    document.getElementById('auth-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = document.getElementById('auth-email').value;
      const password = document.getElementById('auth-password').value;
      const errBox = document.getElementById('auth-error');
      const submit = document.getElementById('auth-submit');
      submit.disabled = true;
      submit.innerHTML = '<span class="spinner"></span>';
      errBox.classList.remove('show');
      try {
        if (state.authMode === 'login') await AegisAPI.login(email, password);
        else await AegisAPI.register(email, document.getElementById('auth-name').value || email.split('@')[0], password);
        UI.toast('Welcome back', 'ok');
        showApp();
      } catch (err) {
        errBox.textContent = err.message;
        errBox.classList.add('show');
      } finally {
        submit.disabled = false;
        submit.textContent = state.authMode === 'login' ? 'Sign in' : 'Create account';
      }
    });

    if (AegisAPI.isAuthed()) {
      try {
        const u = await AegisAPI.me();
        AegisAPI.setAuth({
          access_token: AegisAPI.tokens.access,
          refresh_token: AegisAPI.tokens.refresh,
          user: u,
        });
        showApp();
      } catch {
        AegisAPI.logout();
        showAuth('login');
      }
    } else {
      showAuth('login');
    }
  }

  window.AegisGo = go;
  window.AegisOpenScan = openScan;
  document.addEventListener('DOMContentLoaded', boot);
})();
