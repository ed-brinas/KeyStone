// Minimal fetch helper used by admin/selfservice pages.
// Auto-downloads PDF responses.
async function api(url, method = 'GET', body) {
  const opts = { method, headers: {} };
  if (body && method !== 'GET') {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(url, opts);
  const ctype = res.headers.get('content-type') || '';
  if (!res.ok) {
    let msg = 'Request failed';
    try { const j = await res.json(); if (j && j.error) msg = j.error; } catch {}
    throw new Error(msg);
  }
  if (ctype.includes('application/pdf')) {
    const blob = await res.blob();
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'summary.pdf';
    document.body.appendChild(a); a.click(); a.remove();
    return { ok: true };
  }
  if (ctype.includes('application/json')) return await res.json();
  return await res.text();
}
