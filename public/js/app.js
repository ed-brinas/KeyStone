// ModalHandler
document.addEventListener('DOMContentLoaded', () => {
  const errorModalId = @json(session('open_modal'));

  if (errorModalId) {
    const modalElement = document.querySelector(errorModalId);
    if (modalElement) new bootstrap.Modal(modalElement).show();
  }

  const firstNameInput = document.getElementById('first_name');
  const lastNameInput = document.getElementById('last_name');
  const displayNameInput = document.getElementById('display_name');

  const toSentenceCase = str => str ? str.charAt(0).toUpperCase() + str.slice(1).toLowerCase() : '';

  const updateDisplayName = () => {
    if (firstNameInput && lastNameInput && displayNameInput) {
      const firstName = firstNameInput.value.trim();
      const lastName = lastNameInput.value.trim();
      displayNameInput.value = `${toSentenceCase(firstName)} ${toSentenceCase(lastName)}`.trim();
    }
  };

  if (firstNameInput && lastNameInput) {
    firstNameInput.addEventListener('input', updateDisplayName);
    lastNameInput.addEventListener('input', updateDisplayName);
  }
});

// UserResetPassword
$(function () {
  let selectedUserId = null;
  let selectedUsername = null;

  const showModal = id => $(id).modal('show');
  const hideModal = id => $(id).modal('hide');

  // Open confirmation modal
  $('.reset-password-btn').on('click', function () {
    selectedUserId = $(this).data('id');
    selectedUsername = $(this).data('username');
    showModal('#confirmResetModal');
  });

  // Confirm reset
  $('#confirmResetBtn').on('click', function () {
    hideModal('#confirmResetModal');

    fetch(`/admin/users/${selectedUserId}/reset-password`, {
      method: 'POST',
      headers: {
        'X-CSRF-TOKEN': '{{ csrf_token() }}',
        'Accept': 'application/json'
      }
    })
      .then(res => res.json())
      .then(data => {
        $('#resultUsername').text(selectedUsername);
        $('#resultPassword').text(data.new_password);
        showModal('#resultModal');
      })
      .catch(() => alert('Error resetting password.'));
  });

  // Copy button
  $('#copyPasswordBtn').on('click', function () {
    const pwd = $('#resultPassword').text();
    navigator.clipboard.writeText(pwd);
    $(this).text('✅ Copied');
    setTimeout(() => $(this).text('📋'), 1500);
  });
});
