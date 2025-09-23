// app.js
// Global helpers: session bootstrap + fetch wrapper with CSRF for /api/admin/*
// Works offline. Requires backend route: GET /api/session/bootstrap

(function () {
  const state = {
    csrf: null,
    bootstrapped: false,
    bootstrapping: null, // Promise
    defaultTimeoutMs: 30000
  };

  // --- Utilities ---
  function sleep(ms) { return new Promise(res => setTimeout(res, ms)); }
  function isAdminApi(url) { try { return new URL(url, location.origin).pathname.startsWith('/api/admin/'); } catch { return (url || '').startsWith('/api/admin/'); } }
  function isUnsafe(method) { const m = (method || 'GET').toUpperCase(); return m === 'POST' || m === 'PUT' || m === 'PATCH' || m === 'DELETE'; }

  // --- Session / CSRF bootstrap ---
  async function bootstrapSession(force = false) {
    if (state.bootstrapping && !force) return state.bootstrapping;

    state.bootstrapping = (async () => {
      try {
        const r = await fetch('/api/session/bootstrap', { method: 'GET', credentials: 'include' });
        if (!r.ok) throw new Error('Bootstrap failed: ' + r.status);
        const j = await r.json();
        state.csrf = j.csrf || null;
        state.bootstrapped = !!state.csrf;
        // Expose for other scripts (optional)
        window.__csrf = state.csrf;
        return state.csrf;
      } catch (e) {
        state.csrf = null;
        state.bootstrapped = false;
        throw e;
      } finally {
        state.bootstrapping = null;
      }
    })();

    return state.bootstrapping;
  }

  // Boot immediately (best-effort). If it fails, api() will retry on demand.
  bootstrapSession().catch(() => { /* ignore; handled on first POST */ });

  // --- Core fetch with timeout ---
  async function fetchWithTimeout(url, opts, timeoutMs) {
    const ctrl = new AbortController();
    const id = setTimeout(() => ctrl.abort(), timeoutMs || state.defaultTimeoutMs);
    try {
      return await fetch(url, { ...opts, signal: ctrl.signal });
    } finally {
      clearTimeout(id);
    }
  }

  // --- Public API wrapper ---
  async function api(url, method = 'GET', body = null, extraHeaders = {}) {
    method = (method || 'GET').toUpperCase();

    // Ensure session/CSRF before unsafe admin calls
    if (isUnsafe(method) && isAdminApi(url)) {
      if (!state.csrf) {
        try { await bootstrapSession(); } catch { /* fallback: will try once more on 403 */ }
      }
    }

    const headers = { 'Accept': 'application/json', ...extraHeaders };
    let payload = undefined;

    if (body !== null && body !== undefined) {
      // Assume JSON by default
      headers['Content-Type'] = headers['Content-Type'] || 'application/json';
      payload = (headers['Content-Type'] === 'application/json') ? JSON.stringify(body) : body;
    }

    // Attach CSRF only for unsafe admin endpoints
    if (isUnsafe(method) && isAdminApi(url)) {
      headers['X-CSRF-Token'] = state.csrf || '';
    }

    const opts = { method, headers, credentials: 'include', body: payload };

    // First attempt
    let res = await fetchWithTimeout(url, opts);
    // If CSRF/session expired, bootstrap and retry ONCE
    if (res.status === 403 && isUnsafe(method) && isAdminApi(url)) {
      try { await bootstrapSession(true); } catch { /* ignore */ }
      headers['X-CSRF-Token'] = state.csrf || '';
      res = await fetchWithTimeout(url, { ...opts, headers });
    }

    // Parse JSON when possible
    let json;
    const ct = res.headers.get('content-type') || '';
    if (ct.includes('application/json')) {
      try { json = await res.json(); } catch { json = null; }
    } else {
      // For non-JSON (e.g., PDF downloads), return the Response as-is to caller.
      if (res.ok) return res;
      // If error and not JSON, synthesize a message
      const text = await res.text().catch(() => '');
      const err = new Error(text || `HTTP ${res.status}`);
      err.status = res.status;
      throw err;
    }

    if (!res.ok) {
      const err = new Error((json && (json.message || json.error)) || `HTTP ${res.status}`);
      err.status = res.status;
      err.body = json;
      throw err;
    }

    // Some APIs wrap { ok:false } with 200; normalize
    if (json && json.ok === false) {
      const err = new Error(json.message || 'Operation failed');
      err.status = 200;
      err.body = json;
      throw err;
    }

    return json;
  }

  // Expose globally
  window.api = api;
  window.bootstrapSession = bootstrapSession;
})();
