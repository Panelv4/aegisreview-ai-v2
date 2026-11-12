/* API client: token storage, refresh, typed errors. */
const AegisAPI = (() => {
  const KEY = 'aegis.tokens';
  let tokens = null;
  try { tokens = JSON.parse(localStorage.getItem(KEY) || 'null'); } catch { tokens = null; }

  const save = () => {
    if (tokens) localStorage.setItem(KEY, JSON.stringify(tokens));
    else localStorage.removeItem(KEY);
  };

  const setAuth = (data) => { tokens = { access: data.access_token, refresh: data.refresh_token, user: data.user }; save(); };

  class ApiError extends Error {
    constructor(message, status, body) { super(message); this.status = status; this.body = body; }
  }

  async function raw(path, options = {}, retry = true) {
    const headers = { ...(options.headers || {}) };
    if (tokens?.access) headers.Authorization = `Bearer ${tokens.access}`;
    if (options.body && !(options.body instanceof FormData)) headers['Content-Type'] = 'application/json';

    const res = await fetch(`/api${path}`, { ...options, headers });

    if (res.status === 401 && retry && tokens?.refresh) {
      const ok = await refresh();
      if (ok) return raw(path, options, false);
    }
    if (res.status === 204) return null;

    const type = res.headers.get('content-type') || '';
    const body = type.includes('application/json') ? await res.json() : await res.text();
    if (!res.ok) {
      let msg = 'Request failed';
      if (typeof body === 'string') msg = body;
      else if (Array.isArray(body?.detail)) msg = body.detail.map(d => d.msg).join(', ');
      else if (body?.detail) msg = body.detail;
      throw new ApiError(msg, res.status, body);
    }
    return body;
  }

  async function refresh() {
    try {
      const res = await fetch('/api/auth/refresh', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: tokens.refresh }),
      });
      if (!res.ok) throw new Error('refresh failed');
      setAuth(await res.json());
      return true;
    } catch {
      tokens = null; save(); return false;
    }
  }

  return {
    ApiError,
    get tokens() { return tokens; },
    user: () => tokens?.user || null,
    isAuthed: () => !!tokens?.access,
    setAuth,
    logout() { tokens = null; save(); },

    login: (email, password) => raw('/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) }).then(d => (setAuth(d), d)),
    register: (email, full_name, password) => raw('/auth/register', { method: 'POST', body: JSON.stringify({ email, full_name, password }) }).then(d => (setAuth(d), d)),
    me: () => raw('/auth/me'),

    scanSnippet: (code, filename, language) => raw('/scans/snippet', { method: 'POST', body: JSON.stringify({ code, filename, language }) }),
    scanRepo: (url) => raw('/scans/repo', { method: 'POST', body: JSON.stringify({ url }) }),
    scanUpload: (file, projectId) => {
      const fd = new FormData(); fd.append('file', file);
      if (projectId) fd.append('project_id', projectId);
      return raw('/scans/upload', { method: 'POST', body: fd });
    },
    scans: (limit = 50) => raw(`/scans?limit=${limit}`),
    scan: (id) => raw(`/scans/${id}`),
    deleteScan: (id) => raw(`/scans/${id}`, { method: 'DELETE' }),
    triage: (id, status, note) => raw(`/findings/${id}`, { method: 'PATCH', body: JSON.stringify({ status, note }) }),

    projects: () => raw('/projects'),
    createProject: (name, description, language) => raw('/projects', { method: 'POST', body: JSON.stringify({ name, description, language }) }),
    deleteProject: (id) => raw(`/projects/${id}`, { method: 'DELETE' }),

    stats: () => raw('/stats'),
    rules: () => raw('/rules'),
    health: () => raw('/health'),

    exportUrl: (id, fmt) => `/api/scans/${id}/export?fmt=${fmt}`,
    downloadExport: async (id, fmt) => {
      const res = await fetch(`/api/scans/${id}/export?fmt=${fmt}`, {
        headers: tokens?.access ? { Authorization: `Bearer ${tokens.access}` } : {},
      });
      if (!res.ok) throw new ApiError('Export failed', res.status);
      const blob = await res.blob();
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `aegis-${id.slice(0, 8)}.${fmt === 'markdown' ? 'md' : fmt}`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 4000);
    },
  };
})();
