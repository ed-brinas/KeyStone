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

// -------- Edit User Modal --------
async function openEditModal(domain, sam) {
    try {
        const user = await api(`/api/admin/user-details?domain=${encodeURIComponent(domain)}&sam=${encodeURIComponent(sam)}`);
        $('#e_domain').val(user.domain);
        $('#e_sam').val(user.samAccountName);
        $('#e_fn').val(user.firstName);
        $('#e_ln').val(user.lastName);
        $('#e_dob').val(user.birthdate);
        $('#e_exp').val(user.expirationDate ? user.expirationDate.split('T')[0] : '');
        $('#e_mobile').val(user.mobileNumber);
        
        new bootstrap.Modal(document.getElementById('editUserModal')).show();
    } catch (err) {
        showInfo('Error', `Failed to load user details. ${err.message || ''}`);
    }
}

// -------- Users grid --------
async function loadUsers(){
  try {
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
      .filter(u => (u.samAccountName || '').toLowerCase().includes(q) || (u.displayName || '').toLowerCase().includes(q))
      .forEach(u => {
        const status = (u.enabled ? 'Enabled' : 'Disabled') + (u.isLocked ? ' - Locked' : '');
        const isPriv = !!u.isPrivileged;
        const base = (u.samAccountName || '').toLowerCase();
        const hasAdmin = !isPriv && adminBaseSet.has(base);
        const adminBadgeHtml = isPriv
          ? '<span class="badge bg-secondary">—</span>'
          : (hasAdmin ? '<span class="badge bg-success">✓</span>' : '<span class="badge bg-danger">✗</span>');

        const actions = $('<div class="icon-actions d-flex align-items-center justify-content-center"></div>');
        
        if (!isPriv) {
            actions.append(
              $('<button class="btn-icon text-info me-2" aria-label="Edit" data-bs-toggle="tooltip" title="Edit User"><i class="bi bi-pencil-square"></i></button>')
                .click(() => openEditModal(u.domain, u.samAccountName))
            );
        }

        actions.append(
          $('<button class="btn-icon text-secondary me-2" aria-label="Unlock" data-bs-toggle="tooltip" title="Unlock"><i class="bi bi-unlock"></i></button>')
            .click(async () => {
              const ok = await confirmAction('Unlock Account', `Unlock <code>${u.samAccountName}</code> on <code>${u.domain}</code>?`);
              if (!ok) return;
              await api('/api/admin/reset-password','POST',{domain:u.domain,samAccountName:u.samAccountName, unlock: true});
              showInfo('Unlocked', `Account <code>${u.samAccountName}</code> was unlocked.`);
              loadUsers();
            })
        );
        actions.append(
          $('<button class="btn-icon text-primary me-2" aria-label="Reset Password" data-bs-toggle="tooltip" title="Reset Password"><i class="bi bi-key"></i></button>')
            .click(async () => {
              const ok = await confirmAction('Reset Password', `Reset password for <code>${u.samAccountName}</code>? This will also unlock the account.`);
              if (!ok) return;
              const r = await api('/api/admin/reset-password','POST',{domain:u.domain,samAccountName:u.samAccountName,unlock:true});
              showInfo('Password Reset', `New password for <code>${u.samAccountName}</code>:<br><code class="text-mono">${r.password}</code>`);
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
                showInfo('Admin Password Reset', `New password for <code>${adminSam}</code>:<br><code class="text-mono">${r.password}</code>`);
                loadUsers();
              })
          );
        }

        const tr = $('<tr>');
        tr.append(`<td>${u.domain}</td>`);
        tr.append(`<td class="text-mono">${u.samAccountName}</td>`);
        tr.append(`<td>${u.displayName}</td>`);
        tr.append(`<td>${status}</td>`);
        tr.append(`<td>${u.expirationDate ? u.expirationDate.split('T')[0] : 'Never'}</td>`);
        tr.append(`<td class="text-center">${adminBadgeHtml}</td>`);
        tr.append($('<td class="text-center">').append(actions));
        tbody.append(tr);
      });

    initTooltips(document);
  } catch (err) {
      showInfo('Error Loading Users', `There was a problem retrieving the user list from the server. Please check the application logs for more details.<br><br><i><small>${err.message || 'No additional details available.'}</small></i>`);
  }
}

// -------- Form helpers --------
function getCreateFormData() {
  const form = document.getElementById('userForm');
  if (!form.checkValidity()) {
    form.classList.add('was-validated');
    return null;
  }
  return {
    domain: $('#c_domain').val(),
    firstName: $('#c_fn').val(),
    lastName: $('#c_ln').val(),
    birthdate: $('#c_dob').val(),
    expirationDate: $('#c_exp').val(),
    mobileNumber: $('#c_mobile').val(),
    samAccountName: $('#c_sam').val(),
    createPrivileged: $('#c_priv').is(':checked'),
    selectedPrivilegedGroupCn: $('#c_priv_group').val() || null,
    makeSelectedPrimary: $('#c_priv_primary').is(':checked'),
    selectedGeneralAccessGroups: $('#c_general_groups').val() || [],
    selectedPrivilegeAccessGroups: $('#c_priv_groups').val() || []
  };
}

function getEditFormData() {
  const form = document.getElementById('editUserForm');
  if (!form.checkValidity()) {
    form.classList.add('was-validated');
    return null;
  }
  return {
    domain: $('#e_domain').val(),
    samAccountName: $('#e_sam').val(),
    firstName: $('#e_fn').val(),
    lastName: $('#e_ln').val(),
    birthdate: $('#e_dob').val(),
    expirationDate: $('#e_exp').val(),
    mobileNumber: $('#e_mobile').val()
  };
}


// -------- Created summary modal --------
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
  lines.push(`Mobile Number     : ${r.mobileNumber || '(not set)'}`);
  lines.push(`OU                : ${r.ouCreatedIn}`);
  lines.push(`Expires           : ${r.expirationDate ? r.expirationDate.split('T')[0] : "Never"}`);
  lines.push(`Groups Added      : ${r.groupsAdded && r.groupsAdded.length ? r.groupsAdded.join(", ") : "(none)"}`);
  lines.push(`Initial Password  : ${r.initialPassword}`);
  lines.push("");
  lines.push(`Must change password at next logon: Yes`);
  if (a.created) {
    lines.push("");
    lines.push("=== Admin Account (-a) ===");
    lines.push(`Username (SAM)    : ${a.sam}`);
    lines.push(`Initial Password  : ${a.password}`);
    lines.push(`Note              : Admin account does not expire and is not forced to change password.`);
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

// -------- Audit Log Modal Logic --------
async function loadAndDisplayLogs() {
    try {
        const r = await api('/api/admin/logs');
        $('#logs').text(r.entries.join('\n'));
    } catch (err) {
        $('#logs').text(`Failed to load logs: ${err.message || 'Unknown error'}`);
    }
}

// -------- Wire up buttons --------
$('#createUserBtn').click(() => {
    // Reset form for new entry
    document.getElementById('userForm').classList.remove('was-validated');
    document.getElementById('userForm').reset();
    $('#c_priv_container').toggle(userPermissions.canCreatePrivileged);
    $('#privileged-options').hide();
    const domain = $('#c_domain').val();
    loadOptionalGroups(domain);
});

$('#create').click(async ()=>{
  const body = getCreateFormData();
  if (!body) return;
  const ok = await confirmAction('Create User', 'Proceed to create this user? A summary with credentials will be shown.');
  if (!ok) return;
  try {
    const payload = await api('/api/admin/create-user','POST', body);
    openCreatedSummaryModal(payload);
    loadUsers();
    bootstrap.Modal.getInstance(document.getElementById('userFormModal')).hide();
  } catch (err) {
      if (err.status === 403) {
          showInfo('Permission Denied', 'You do not have permission to create a privileged account.');
      } else {
          showInfo('Error', `Failed to create user. ${err.message || ''}`);
      }
  }
});

$('#saveEdit').click(async () => {
    const body = getEditFormData();
    if (!body) return;
    try {
        await api('/api/admin/update-user', 'POST', body);
        showInfo('Success', `User <code>${body.samAccountName}</code> has been updated.`);
        loadUsers();
        bootstrap.Modal.getInstance(document.getElementById('editUserModal')).hide();
    } catch (err) {
        showInfo('Error', `Failed to update user. ${err.message || ''}`);
    }
});


$('#openLogsBtn').click(() => loadAndDisplayLogs());
$('#refreshLogs').click(() => loadAndDisplayLogs());
$('#refresh').click(loadUsers);
$('#q').on('input', loadUsers);
$('#logoutBtn').click(async () => {
    await api('/api/admin/logout', 'POST');
    window.location.href = '/';
});

document.getElementById('copyCreatedSummary').addEventListener('click', copyCreatedSummaryToClipboard);
document.getElementById('exportCreatedPdf').addEventListener('click', exportCreatedPdf);

// -------- Wire up form element events --------
$('#c_domain').on('change', function(){
  loadOptionalGroups(this.value);
});

$('#c_priv').on('change', function() {
    $('#privileged-options').toggle(this.checked);
});


// -------- Init --------
(async () => {
  try { 
    await bootstrapSession(); 
    await checkPermissions();
  } catch(err) {
      window.location.href = '/';
      return;
  }
  
  await populateDomains();
  
  const initialDomain = $('#c_domain').val();
  if (initialDomain) {
      await loadOptionalGroups(initialDomain);
  }
  
  await loadUsers();
})();

