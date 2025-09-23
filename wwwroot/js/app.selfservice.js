// Helpers (reuse admin modal helpers pattern)
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

// Load domains for dropdown
async function loadDomains() {
  try {
    const domains = await api('/api/config/domains');
    const sel = document.getElementById('ss_domain');
    sel.innerHTML = domains.map(d => `<option>${d}</option>`).join('');
  } catch {
    const sel = document.getElementById('ss_domain');
    sel.innerHTML = '<option value="" disabled selected>(no domains configured)</option>';
  }
}

// Form → payload or null (shows HTML5 validation)
function formDataOrInvalid() {
  const form = document.getElementById('ssForm');
  if (!form.checkValidity()) {
    form.classList.add('was-validated');
    return null;
  }
  const domain = document.getElementById('ss_domain').value;
  const sam = document.getElementById('ss_user').value.trim();
  const dob = document.getElementById('ss_dob').value; // yyyy-mm-dd from input[type=date]
  const p1 = document.getElementById('ss_new').value;
  const p2 = document.getElementById('ss_new2').value;

  if (/-a\s*$/i.test(sam)) {
    showInfo('Blocked', 'Privileged accounts (ending with <code>-a</code>) cannot use self-service password reset. Please contact the helpdesk.');
    return null;
  }
  if (p1 !== p2) {
    showInfo('Mismatch', 'New password and Retype do not match.');
    return null;
  }
  return { domain, samAccountName: sam, birthdate: dob, newPassword: p1 };
}

// Submit handler
async function submitSelfService() {
  const body = formDataOrInvalid();
  if (!body) return;

  const ok = await confirmAction('Confirm Password Change',
    `Change password for <code>${body.samAccountName}</code> on <code>${body.domain}</code>?<br/>` +
    `Your account will be unlocked and enabled if required.`);
  if (!ok) return;

  try {
    // Backend verifies identity (DOB), rejects -a, sets new password, unlocks & enables.
    await api('/api/selfservice/reset-password', 'POST', body);
    showInfo('Password Updated', 'Your password has been changed successfully. You can now sign in.');
    // Clear fields
    document.getElementById('ssForm').reset();
    document.getElementById('ssForm').classList.remove('was-validated');
  } catch (e) {
    showInfo('Failed', (e && e.message) ? e.message : 'Password change failed.');
  }
}

// Wire up UI
document.getElementById('ss_submit').addEventListener('click', submitSelfService);
document.getElementById('ss_clear').addEventListener('click', () => {
  document.getElementById('ssForm').reset();
  document.getElementById('ssForm').classList.remove('was-validated');
});

// Init
(async () => {
  await loadDomains();
})();
