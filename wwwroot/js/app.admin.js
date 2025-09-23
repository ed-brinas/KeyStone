(function injectStyles() {
  const css = `
    .icon-actions .btn-icon { padding: .25rem .35rem; line-height: 1; border: 0; background: transparent; }
    .icon-actions .btn-icon:focus { outline: none; box-shadow: none; }
    .text-mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
  `;
  const s = document.createElement('style'); s.textContent = css; document.head.appendChild(s);
})();

// Modals
function showInfo(title, html) {
  document.getElementById('infoModalTitle').textContent = title || 'Notice';
  document.getElementById('infoModalBody').innerHTML = html || '';
  new bootstrap.Modal(document.getElementById('infoModal')).show();
}
function confirmAction(title, html) {
  return new Promise(resolve => {
    document.getElementById('confirmModalTitle').textContent = title || 'Confirm';
    document.getElementById('confirmModalBody').innerHTML = html || '';
    const modalEl = document.getElementById('confirmModal');
    const okBtn = document.getElementById('confirmModalOk');
    const modal = new bootstrap.Modal(modalEl);
    const cleanup = () => { okBtn.removeEventListener('click', onOk); modalEl.removeEventListener('hidden.bs.modal', onHide); };
    const onOk = () => { cleanup(); modal.hide(); resolve(true); };
    const onHide = () => { cleanup(); resolve(false); };
    okBtn.addEventListener('click', onOk);
    modalEl.addEventListener('hidden.bs.modal', onHide, { once: true });
    modal.show();
  });
}
function initTooltips(scope=document) {
  const list = [].slice.call(scope.querySelectorAll('[data-bs-toggle="tooltip"]'));
  list.forEach(el => new bootstrap.Tooltip(el, { container: 'body' }));
}

// Domains
async function populateDomains() {
  let domains = [];
  try { domains = await api('/api/config/domains'); } catch {}
  const opts = (list, all=false) => {
    if (!Array.isArray(list) || !list.length) return '<option value="" disabled selected>(no domains configured)</option>';
    let s = list.map(d => `<option>${d}</option>`).join('');
    if (all) s = `<option value="">(all domains)</option>` + s;
    return s;
  };
  $('#c_domain').html(opts(domains));
  $('#u_domain').html(opts(domains, true)).on('change', loadUsers);
}

// Users grid
async function loadUsers(){
  const data = await api('/api/admin/users');
  const q = ($('#q').val() || '').toLowerCase();
  const domFilter = ($('#u_domain').val() || '');
  const tbody = $('#users tbody').empty();

  const adminBaseSet = new Set(
    data
      .filter(u => u.isPrivileged && (u.samAccountName || '').toLowerCase().endsWith('-a'))
      .map(u => (u.samAccountName || '').toLowerCase().replace(/-a$/i, ''))
  );

  data
    .filter(u => !domFilter || u.domain === domFilter)
    .filter(u => (u.samAccountName || '').toLowerCase().includes(q))
    .forEach(u => {
      const status = (u.enabled ? 'Enabled' : 'Disabled') + (u.isLocked ? ' - Locked' : '');
      const isPriv = !!u.isPrivileged;
      const base = (u.samAccountName || '').toLowerCase();
      const hasAdmin = !isPriv && adminBaseSet.has(base);
      const adminBadgeHtml = isPriv
        ? '<span class="badge bg-secondary">—</span>'
        : (hasAdmin ? '<span class="badge bg-success">✓</span>' : '<span class="badge bg-danger">✗</span>');

      const actions = $('<div class="icon-actions d-flex align-items-center justify-content-center"></div>');
      actions.append(
        $('<button class="btn-icon text-secondary me-2" aria-label="Unlock" data-bs-toggle="tooltip" title="Unlock"><i class="bi bi-unlock"></i></button>')
          .click(async () => {
            const ok = await confirmAction('Unlock Account', `Unlock <code>${u.samAccountName}</code> on <code>${u.domain}</code>?`);
            if (!ok) return;
            await api('/api/admin/unlock','POST',{domain:u.domain,samAccountName:u.samAccountName});
            showInfo('Unlocked', `Account <code>${u.samAccountName}</code> was unlocked.`);
            loadUsers();
          })
      );
      actions.append(
        $('<button class="btn-icon text-success me-2" aria-label="Enable" data-bs-toggle="tooltip" title="Enable"><i class="bi bi-check-circle"></i></button>')
          .click(async () => {
            const ok = await confirmAction('Enable Account', `Enable <code>${u.samAccountName}</code>?`);
            if (!ok) return;
            await api('/api/admin/enable','POST',{domain:u.domain,samAccountName:u.samAccountName,enable:true});
            showInfo('Enabled', `Account <code>${u.samAccountName}</code> is now enabled.`);
            loadUsers();
          })
      );
      actions.append(
        $('<button class="btn-icon text-warning me-2" aria-label="Disable" data-bs-toggle="tooltip" title="Disable"><i class="bi bi-slash-circle"></i></button>')
          .click(async () => {
            const ok = await confirmAction('Disable Account', `Disable <code>${u.samAccountName}</code>?`);
            if (!ok) return;
            await api('/api/admin/enable','POST',{domain:u.domain,samAccountName:u.samAccountName,enable:false});
            showInfo('Disabled', `Account <code>${u.samAccountName}</code> is now disabled.`);
            loadUsers();
          })
      );
      actions.append(
        $('<button class="btn-icon text-primary me-2" aria-label="Reset Password" data-bs-toggle="tooltip" title="Reset Password"><i class="bi bi-key"></i></button>')
          .click(async () => {
            const ok = await confirmAction('Reset Password', `Reset password for <code>${u.samAccountName}</code>? This will also unlock the account.`);
            if (!ok) return;
            const r = await api('/api/admin/reset-password','POST',{domain:u.domain,samAccountName:u.samAccountName,unlock:true});
            showInfo('Password Reset', `New password for <code>${u.samAccountName}</code>:<br><code>${r.password}</code>`);
            loadUsers();
          })
      );
      if (!isPriv && hasAdmin) {
        const adminSam = `${u.samAccountName}-a`;
        actions.append(
          $(`<button class="btn-icon text-danger" aria-label="Reset Admin Password" data-bs-toggle="tooltip" title="Reset Admin Password (${adminSam})"><i class="bi bi-shield-lock"></i></button>`)
            .click(async () => {
              const ok = await confirmAction('Reset Admin Password', `Reset password for admin account <code>${adminSam}</code>?`);
              if (!ok) return;
              const r = await api('/api/admin/reset-password','POST',{domain:u.domain,samAccountName:adminSam,unlock:true});
              showInfo('Admin Password Reset', `New password for <code>${adminSam}</code>:<br><code>${r.password}</code>`);
              loadUsers();
            })
        );
      }

      const tr = $('<tr>');
      tr.append(`<td>${u.domain}</td>`);
      tr.append(`<td class="text-mono">${u.samAccountName}</td>`);
      tr.append(`<td>${u.displayName}</td>`);
      tr.append(`<td>${status}</td>`);
      tr.append(`<td>${u.expirationDate || ''}</td>`);
      tr.append(`<td class="text-center">${adminBadgeHtml}</td>`);
      tr.append($('<td class="text-center">').append(actions));
      tbody.append(tr);
    });

  initTooltips(document);
}

function formDataOrInvalid() {
  const form = document.getElementById('userForm');
  if (!form.checkValidity()) { form.classList.add('was-validated'); return null; }
  return {
    domain: $('#c_domain').val(),
    firstName: $('#c_fn').val(),
    lastName: $('#c_ln').val(),
    birthdate: $('#c_dob').val(),
    expirationDate: $('#c_exp').val(),
    mobileNumber: $('#c_mobile').val(),   // ← include mobile
    samAccountName: $('#c_sam').val(),
    createPrivileged: $('#c_priv').is(':checked')
  };
}

// Created summary modal
let __lastCreatePayload = null;
function openCreatedSummaryModal(payload) {
  __lastCreatePayload = payload;
  const r = payload.result;
  const a = payload.admin || { created:false };
  const lines = [];
  lines.push("=== Regular Account ===");
  lines.push(`Domain            : ${r.domain}`);
  lines.push(`Username (SAM)    : ${r.samAccountName}`);
  lines.push(`Display Name      : ${r.displayName}`);
  lines.push(`Mobile Number     : ${r.mobileNumber || '(not set)'}`); // ← show mobile
  lines.push(`OU                : ${r.ouCreatedIn}`);
  lines.push(`Enabled/Locked    : ${r.enabled ? "Enabled" : "Disabled"} / ${r.isLocked ? "Locked" : "Unlocked"}`);
  lines.push(`Expires           : ${r.expirationDate || "(none)"}`);
  lines.push(`Groups            : ${r.groupsAdded && r.groupsAdded.length ? r.groupsAdded.join(", ") : "(none)"}`);
  lines.push(`Initial Password  : ${r.initialPassword}`);
  lines.push("");
  lines.push(`Must change password at next logon: Yes`);
  if (a.created) {
    lines.push("");
    lines.push("=== Admin Account (-a) ===");
    lines.push(`Username (SAM)    : ${a.sam}`);
    lines.push(`Initial Password  : ${a.password}`);
    lines.push(`Note              : Admin account is not forced to change password at first logon.`);
  }
  document.getElementById('createdModalPre').textContent = lines.join('\n');
  new bootstrap.Modal(document.getElementById('createdModal')).show();
}

async function copyCreatedSummaryToClipboard() {
  const text = document.getElementById('createdModalPre').textContent;
  try {
    await navigator.clipboard.writeText(text);
    showInfo('Copied', 'The summary has been copied to your clipboard.');
  } catch {
    const ta = document.createElement('textarea'); ta.value = text; document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); showInfo('Copied', 'The summary has been copied to your clipboard.'); }
    finally { document.body.removeChild(ta); }
  }
}
async function exportCreatedPdf() {
  if (!__lastCreatePayload || !__lastCreatePayload.result) return;
  await api('/api/admin/create-user/export-pdf', 'POST', __lastCreatePayload.result);
}

// Create / Update
$('#create').click(async ()=>{
  const body = formDataOrInvalid();
  if (!body) return;
  const ok = await confirmAction('Create User', 'Proceed to create this user? A summary with credentials will be shown.');
  if (!ok) return;
  const payload = await api('/api/admin/create-user','POST', body);
  openCreatedSummaryModal(payload);
  loadUsers();
});
$('#update').click(async ()=>{
  const body = formDataOrInvalid();
  if (!body) return;
  const ok = await confirmAction('Update User', `Update account <code>${body.samAccountName}</code>?`);
  if (!ok) return;
  await api('/api/admin/update-user','POST', body);
  showInfo('Updated', `Account <code>${body.samAccountName}</code> has been updated.`);
  loadUsers();
});
$('#loadLogs').click(async ()=>{ const r = await api('/api/admin/logs'); $('#logs').text(r.entries.join('\n')); });
$('#refresh').click(loadUsers);
$('#q').on('input', loadUsers);
document.getElementById('copyCreatedSummary').addEventListener('click', copyCreatedSummaryToClipboard);
document.getElementById('exportCreatedPdf').addEventListener('click', exportCreatedPdf);

// Init
(async () => { await populateDomains(); await loadUsers(); })();
