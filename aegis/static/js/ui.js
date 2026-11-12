/* Small render helpers: escaping, icons, charts, toasts. */
const UI = (() => {
  const esc = (s) => String(s ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

  /* Escape first, then re-introduce a tiny, safe inline-markup subset so rule
     explanations can use `code` and **bold** without shipping an HTML sanitiser
     or trusting rule text as markup. */
  function rich(text) {
    return esc(text)
      .replace(/`([^`]{1,120})`/g, '<code class="inline">$1</code>')
      .replace(/\*\*([^*]{1,160})\*\*/g, '<strong>$1</strong>');
  }

  const SEV = ['critical', 'high', 'medium', 'low', 'info'];
  const SEV_COLOR = { critical: 'var(--critical)', high: 'var(--high)', medium: 'var(--medium)', low: 'var(--low)', info: 'var(--info)' };

  const icon = (name, size = 16) => {
    const paths = {
      shield: '<path d="M12 3 5 6v5.5c0 4.4 2.9 8.2 7 9.5 4.1-1.3 7-5.1 7-9.5V6l-7-3z"/><path d="m9 12 2 2 4-4"/>',
      alert: '<path d="M12 9v4M12 17h.01"/><path d="M10.3 3.9 2.6 17a2 2 0 0 0 1.7 3h15.4a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/>',
      code: '<path d="m8 9-3 3 3 3M16 9l3 3-3 3M13.5 5l-3 14"/>',
      file: '<path d="M14 3v5h5"/><path d="M6 2h8l6 6v12a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V3a1 1 0 0 1 1-1z"/>',
      check: '<path d="m5 13 4 4L19 7"/>',
      x: '<path d="M18 6 6 18M6 6l12 12"/>',
      chev: '<path d="m9 6 6 6-6 6"/>',
      search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
      upload: '<path d="M12 16V4M7 9l5-5 5 5"/><path d="M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2"/>',
      download: '<path d="M12 4v12M7 11l5 5 5-5"/><path d="M4 20h16"/>',
      plus: '<path d="M12 5v14M5 12h14"/>',
      trash: '<path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13"/>',
      clock: '<circle cx="12" cy="12" r="9"/><path d="M12 8v4l3 2"/>',
      chart: '<path d="M4 20V10M10 20V4M16 20v-7M22 20H2"/>',
      folder: '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7z"/>',
      bolt: '<path d="m13 2-9 12h7l-1 8 9-12h-7l1-8z"/>',
      copy: '<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/>',
      lock: '<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>',
    };
    return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="${size}" height="${size}">${paths[name] || ''}</svg>`;
  };

  function toast(message, kind = '', ms = 4200) {
    const host = document.getElementById('toasts');
    const el = document.createElement('div');
    el.className = `toast ${kind}`;
    el.innerHTML = `<span style="flex:none;margin-top:1px">${kind === 'err' ? icon('alert', 15) : kind === 'ok' ? icon('check', 15) : icon('bolt', 15)}</span><div>${esc(message)}</div>`;
    host.appendChild(el);
    setTimeout(() => { el.style.opacity = '0'; el.style.transform = 'translateX(20px)'; el.style.transition = '.25s'; setTimeout(() => el.remove(), 260); }, ms);
  }

  /* ---------------- score ring ---------------- */
  function scoreRing(score, grade, size = 168) {
    const r = size / 2 - 12;
    const c = 2 * Math.PI * r;
    const pct = Math.max(0, Math.min(100, score)) / 100;
    const color = score >= 90 ? 'var(--good)' : score >= 75 ? 'var(--accent)' : score >= 55 ? 'var(--medium)' : score >= 35 ? 'var(--high)' : 'var(--critical)';
    return `
      <div class="score-ring" style="width:${size}px;height:${size}px">
        <svg width="${size}" height="${size}" style="color:${color}">
          <circle class="track" cx="${size / 2}" cy="${size / 2}" r="${r}" fill="none" stroke-width="9"/>
          <circle class="fill" cx="${size / 2}" cy="${size / 2}" r="${r}" fill="none" stroke="currentColor"
                  stroke-width="9" stroke-dasharray="${c}" stroke-dashoffset="${c * (1 - pct)}"/>
        </svg>
        <div class="score-center">
          <div class="score-num" style="color:${color}">${score}</div>
          <div class="score-cap">score /100</div>
          <div class="score-grade" style="background:color-mix(in srgb, ${color} 16%, transparent);color:${color}">${esc(grade)}</div>
        </div>
      </div>`;
  }

  /* ---------------- severity bars ---------------- */
  function severityBars(counts) {
    const max = Math.max(1, ...SEV.map(s => counts[s] || 0));
    return `<div class="bars">${SEV.map(s => {
      const n = counts[s] || 0;
      return `<div class="bar-row sev-${s}">
        <span class="row" style="gap:6px"><i class="sev-dot"></i>${s}</span>
        <span class="bar-track"><span class="bar-fill" style="width:${(n / max) * 100}%;display:block"></span></span>
        <span class="bar-count">${n}</span>
      </div>`;
    }).join('')}</div>`;
  }

  /* ---------------- sparkline ---------------- */
  function sparkline(points, { height = 72, color = 'var(--accent)' } = {}) {
    if (!points.length) return `<div class="empty" style="padding:18px">No history yet</div>`;
    if (points.length === 1) {
      // a single scan has no trend: show the value instead of a misleading flat line
      const p = points[0];
      return `<div style="display:flex;align-items:center;justify-content:space-between;padding:10px 6px;height:${height}px">
        <div>
          <div style="font-size:24px;font-weight:700;letter-spacing:-.03em;color:${color}">${p.score}<span style="font-size:12px;opacity:.6;font-weight:600">/100</span></div>
          <div class="hint">${esc(p.target)} · ${timeAgo(p.date)}</div>
        </div>
        <div class="hint" style="text-align:right;max-width:150px">Run another scan to see the trend</div>
      </div>`;
    }
    const w = 100, h = height;
    const vals = points.map(p => p.score);
    const min = Math.min(...vals, 40) - 5, max = Math.max(...vals, 100);
    const span = Math.max(1, max - min);
    const step = points.length > 1 ? w / (points.length - 1) : 0;
    const coords = vals.map((v, i) => [i * step, h - ((v - min) / span) * (h - 10) - 5]);
    const line = coords.map((c, i) => `${i ? 'L' : 'M'}${c[0].toFixed(2)},${c[1].toFixed(2)}`).join(' ');
    const area = `${line} L${w},${h} L0,${h} Z`;
    const id = 'sp' + Math.random().toString(36).slice(2, 7);
    return `<svg class="spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">
      <defs><linearGradient id="${id}" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="${color}" stop-opacity=".35"/>
        <stop offset="100%" stop-color="${color}" stop-opacity="0"/>
      </linearGradient></defs>
      <path d="${area}" fill="url(#${id})"/>
      <path d="${line}" fill="none" stroke="${color}" stroke-width="1.6" vector-effect="non-scaling-stroke" stroke-linejoin="round"/>
      ${coords.map((c, i) => `<circle cx="${c[0]}" cy="${c[1]}" r="1.6" fill="${color}" vector-effect="non-scaling-stroke"><title>${esc(points[i].target)} — ${points[i].score}</title></circle>`).join('')}
    </svg>`;
  }

  function sevBadge(sev) {
    return `<span class="badge sev-${esc(sev)}"><i class="sev-dot" style="width:5px;height:5px"></i>${esc(sev)}</span>`;
  }

  function timeAgo(iso) {
    const d = new Date(iso.endsWith('Z') || iso.includes('+') ? iso : iso + 'Z');
    const s = Math.floor((Date.now() - d.getTime()) / 1000);
    if (s < 45) return 'just now';
    if (s < 3600) return `${Math.floor(s / 60)}m ago`;
    if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
    if (s < 604800) return `${Math.floor(s / 86400)}d ago`;
    return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  }

  function scoreChip(score, grade) {
    const color = score >= 90 ? 'var(--good)' : score >= 75 ? 'var(--accent)' : score >= 55 ? 'var(--medium)' : score >= 35 ? 'var(--high)' : 'var(--critical)';
    return `<span class="mini-score" style="color:${color};border-color:${color}44;background:${color}11">${score} <span style="opacity:.65;font-size:10.5px">${esc(grade)}</span></span>`;
  }

  const empty = (msg, sub = '') => `<div class="empty">${icon('shield', 34)}<div style="font-weight:600;color:var(--text-dim)">${esc(msg)}</div>${sub ? `<div style="font-size:12px;margin-top:4px">${esc(sub)}</div>` : ''}</div>`;

  const skeletonRows = (n = 4) => Array.from({ length: n }, () =>
    `<div style="padding:12px 16px;display:flex;gap:12px;align-items:center">
       <div class="skeleton" style="width:26px;height:26px;border-radius:7px"></div>
       <div style="flex:1"><div class="skeleton" style="height:11px;width:62%"></div>
       <div class="skeleton" style="height:9px;width:38%;margin-top:6px"></div></div>
     </div>`).join('');

  return { esc, rich, icon, toast, scoreRing, severityBars, sparkline, sevBadge, sevColor: SEV_COLOR, SEV, timeAgo, scoreChip, empty, skeletonRows };
})();
