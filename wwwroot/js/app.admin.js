(function injectStyles() {
  const css = `
    .icon-actions .btn-icon { padding: .25rem .35rem; line-height: 1; border: 0; background: transparent; }
    .icon-actions .btn-icon:focus { outline: none; box-shadow: none; }
    .text-mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
  `;
  const s = document.createElement('style'); s.textContent = css; document.head.appendChild(s);
})();

// -------- Modals (info/confirm) --------
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

// -------- Permissions --------
let userPermissions = { canCreatePrivileged: false };
async function checkPermissions() {
    try {
        userPermissions = await api('/api/session/permissions');
    } catch (err) {
        console.error("Failed to check permissions:", err);
        userPermissions = { canCreatePrivileged: false };
    }
}

// -------- Domains & optional groups --------
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

async function loadOptionalGroups(domain) {
    $('#c_general_groups').empty();
    $('#c_priv_groups').empty();
    if (!domain) return;
    try {
        const data = await api('/api/config/optional-groups?domain=' + encodeURIComponent(domain));
        if (data.optionalGeneralAccessGroup && Array.isArray(data.optionalGeneralAccessGroup)) {
            data.optionalGeneralAccessGroup.forEach(g => $('#c_general_groups').append(`<option value="${g}">${g}</option>`));
        }
        if (data.optionalPrivilegeGroup && Array.isArray(data.optionalPrivilegeGroup)) {
            data.optionalPrivilegeGroup.forEach(g => $('#c_priv_groups').append(`<option value="${g}">${g}</option>`));
        }
    } catch (err) {
        console.error("Failed to load optional groups:", err);
        showInfo('Error', 'Could not load optional groups. Please check the application configuration and logs.');
    }
}


// -------- Users grid --------
async function loadUsers(){
  // ... existing loadUsers implementation ...
}

// -------- Form helpers --------
function formDataOrInvalid() {
  // ... existing formDataOrInvalid implementation ...
}


// -------- Created summary modal --------
let __lastCreatePayload = null;
function openCreatedSummaryModal(payload) {
  // ... existing openCreatedSummaryModal implementation ...
}
async function copyCreatedSummaryToClipboard() {
  // ... existing copyCreatedSummaryToClipboard implementation ...
}
async function exportCreatedPdf() {
  // ... existing exportCreatedPdf implementation ...
}

// -------- Audit Log Modal Logic --------
async function loadAndDisplayLogs() {
    // ... existing loadAndDisplayLogs implementation ...
}


// -------- Wire up buttons --------
$('#create').click(async ()=>{
  const body = formDataOrInvalid();
  if (!body) return;
  const ok = await confirmAction('Create User', 'Proceed to create this user? A summary with credentials will be shown.');
  if (!ok) return;
  try {
    const payload = await api('/api/admin/create-user','POST', body);
    openCreatedSummaryModal(payload);
    loadUsers();
    bootstrap.Modal.getInstance(document.getElementById('userFormModal')).hide();
    document.getElementById('userForm').reset();
    $('#privileged-options').hide();
  } catch (err) {
      if (err.status === 403) {
          showInfo('Permission Denied', 'You do not have permission to create a privileged account.');
      } else {
          showInfo('Error', `Failed to create user. ${err.message || ''}`);
      }
  }
});

// ... other button wiring ...

// -------- Init --------
(async () => {
  try { 
    await bootstrapSession(); 
    await checkPermissions();
  } catch(err) {
      // If session fails, redirect to home page, as they are not authenticated.
      window.location.href = '/';
      return;
  }
  
  if (!userPermissions.canCreatePrivileged) {
      $('#c_priv_container').hide();
  }

  await populateDomains();
  
  const initialDomain = $('#c_domain').val();
  if (initialDomain) {
      await loadOptionalGroups(initialDomain);
  }
  
  await loadUsers();
})();

