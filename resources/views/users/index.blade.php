<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>KeyStone - AD User Management</title>

    <!-- MODIFIED START - 2025-10-11 09:06 - Added CSRF token meta tag required for AJAX POST requests. -->
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <!-- MODIFIED END -->

    <link href="{{ asset('css/bootstrap.min.css') }}" rel="stylesheet">
    <link href="{{ asset('css/bootstrap-icons/bootstrap-icons.min.css') }}" rel="stylesheet">

    <style>
        body {
            background-color: #f8f9fa;
        }
        .table-actions .btn-link {
            color: var(--bs-secondary);
            text-decoration: none;
            padding: 0.5rem;
            line-height: 1;
        }
        .table-actions .btn-link:hover {
            color: var(--bs-dark);
        }
        .navbar-search-form .form-select {
            max-width: 170px;
        }
        .navbar-search-form .form-control {
            width: 250px;
        }
        .dropdown-toggle::after {
            display: none;
        }
        .table-actions .bi {
            font-size: 1.2rem;
        }
        #resetPassword.form-control-plaintext {
            font-family: monospace;
            font-size: 1.1rem;
            background-color: #e9ecef;
            padding: 0.5rem;
            border-radius: 0.25rem;
        }
    </style>
</head>
<body>

<nav class="navbar navbar-expand-md navbar-dark bg-dark">
    <div class="container-fluid">
        <a class="navbar-brand" href="{{ route('users.index') }}">KeyStone</a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarCollapse" aria-controls="navbarCollapse" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarCollapse">
            <ul class="navbar-nav me-auto mb-2 mb-md-0">
                 <li class="nav-item">
                    <a class="nav-link" href="{{ route('users.index') }}" title="Users">
                        <i class="bi bi-people-fill" style="font-size: 1.5rem;"></i>
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="#" title="Audit Log">
                        <i class="bi bi-journal-text" style="font-size: 1.5rem;"></i>
                    </a>
                </li>
            </ul>

            <form class="d-flex navbar-search-form" action="{{ route('users.index') }}" method="GET">
                <select name="domain" class="form-select me-2" onchange="this.form.submit()">
                    @if(isset($domains))
                        @foreach($domains as $domain)
                            <option value="{{ $domain }}" @if(isset($selectedDomain) && $domain == $selectedDomain) selected @endif>
                                {{ $domain }}
                            </option>
                        @endforeach
                    @endif
                </select>
                <input type="search" name="search_query" class="form-control me-2" placeholder="Search users..." value="{{ $searchQuery ?? '' }}">
                <button class="btn btn-dark" type="submit">
                     <i class="bi bi-search"></i>
                </button>
            </form>

            <ul class="navbar-nav ms-2">
                 <li class="nav-item">
                     <a href="#" class="nav-link" title="Logout">
                        <i class="bi bi-box-arrow-right" style="font-size: 1.5rem;"></i>
                     </a>
                </li>
            </ul>
        </div>
    </div>
</nav>

<main class="container py-4">

    @if(session('success'))
        <div class="alert alert-success">{!! session('success') !!}</div>
    @endif
     @if(session('info'))
        <div class="alert alert-info">{{ session('info') }}</div>
    @endif

    <div class="d-flex justify-content-between align-items-center mb-3">
        <h1 class="h2">User Directory</h1>
        <button type="button" class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#userCreateModal">
            Create New User
        </button>
    </div>

    <div class="card">
        <div class="card-header">
             @if(isset($searchQuery) && $searchQuery)
                Showing results for "<strong>{{ $searchQuery }}</strong>" in {{ $selectedDomain ?? '' }}
            @else
                All users in {{ $selectedDomain ?? '' }}
            @endif
        </div>
        <div class="table-responsive">
            <table class="table table-hover align-middle mb-0">
                <thead>
                    <tr>
                        <th>Display Name</th>
                        <th>Username</th>
                        <th>Domain</th>
                        <th>Privileged</th>
                        <th>Expires</th>
                        <th>Status</th>
                        <th class="text-center">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    @forelse($users ?? [] as $user)
                        <tr>
                            <td>{{ $user->getFirstAttribute('displayname') }}</td>
                            <td>{{ $user->getFirstAttribute('samaccountname') }}</td>
                            <td>{{ $selectedDomain ?? 'N/A' }}</td>
                            <td>
                                @if (substr($user->getFirstAttribute('samaccountname'), -2) === '-a')
                                    <span class="badge bg-dark">Yes</span>
                                @else
                                    <span class="text-muted">No</span>
                                @endif
                            </td>
                            <td>
                                @if($user->accountexpires instanceof \Carbon\Carbon)
                                    {{ $user->accountexpires->format('Y-m-d') }}
                                @else
                                    Never
                                @endif
                            </td>
                            <td>
                                @if ($user->isDisabled())
                                    <span class="badge bg-danger">Disabled</span>
                                @else
                                    <span class="badge bg-success">Enabled</span>
                                @endif
                                @if ($user->getFirstAttribute('lockouttime') > 0)
                                    <span class="badge bg-warning text-dark">Locked</span>
                                @endif
                            </td>
                            <td class="text-center table-actions">
                                <div class="d-flex justify-content-center align-items-center">
                                    <button type="button" class="btn btn-link p-2" title="Edit User" data-bs-toggle="modal" data-bs-target="#editUserModal-{{ $user->getConvertedGuid() }}">
                                         <i class="bi bi-pencil-fill"></i>
                                    </button>
                                    <button type="button" class="btn btn-link p-2 reset-password-btn" title="Reset Password" data-guid="{{ $user->getConvertedGuid() }}" data-username="{{ $user->getFirstAttribute('samaccountname') }}">
                                        <i class="bi bi-key-fill text-secondary"></i>
                                    </button>
                                    @if ($user->getFirstAttribute('lockouttime') > 0)
                                        <form action="{{ route('users.unlock', ['guid' => $user->getConvertedGuid()]) }}" method="POST" class="d-inline">
                                            @csrf
                                            <input type="hidden" name="domain" value="{{ $selectedDomain }}">
                                            <button type="submit" class="btn btn-link" title="Unlock Account">
                                                <i class="bi bi-unlock-fill text-warning"></i>
                                            </button>
                                        </form>
                                    @else
                                         <a href="#" class="p-2 text-black-50" title="Account OK" style="cursor: not-allowed;">
                                            <i class="bi bi-shield-check text-success"></i>
                                        </a>
                                    @endif
                                    <form action="{{ route('users.toggle-status', ['guid' => $user->getConvertedGuid()]) }}" method="POST" class="d-inline">
                                        @csrf
                                        <input type="hidden" name="domain" value="{{ $selectedDomain }}">
                                        @if ($user->isDisabled())
                                            <button type="submit" class="btn btn-link" title="Enable Account">
                                                <i class="bi bi-check-circle-fill text-success"></i>
                                            </button>
                                        @else
                                            <button type="submit" class="btn btn-link" title="Disable Account">
                                               <i class="bi bi-x-circle-fill text-danger"></i>
                                            </button>
                                        @endif
                                    </form>
                                </div>
                            </td>
                        </tr>
                    @empty
                        <tr>
                            <td colspan="7" class="text-center p-5">
                                No users found.
                            </td>
                        </tr>
                    @endforelse
                </tbody>
            </table>
        </div>
    </div>
</main>

@include('users.create')

@if(isset($users))
    @foreach($users as $user)
        @include('users.edit', ['user' => $user, 'domain' => $selectedDomain, 'optionalGroups' => $optionalGroups])
    @endforeach
@endif

<!-- MODIFIED START - Add new global Reset Password confirmation modal [2025-10-11 16:25] -->
<div class="modal fade" id="confirmGlobalResetModal" tabindex="-1" aria-labelledby="confirmGlobalResetModalLabel" aria-hidden="true">
  <div class="modal-dialog modal-dialog-centered">
    <div class="modal-content">
      <div class="modal-header bg-warning">
        <h5 class="modal-title" id="confirmGlobalResetModalLabel">Confirm Password Reset</h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>
      <div class="modal-body">
        Are you sure you want to reset this user's password? This will also unlock their account if it is locked.
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
        <button type="button" id="confirmGlobalResetBtn" class="btn btn-danger">Yes, Reset</button>
      </div>
    </div>
  </div>
</div>
<!-- MODIFIED END -->

<!-- MODIFIED START - Add success modal showing new password and copy button [2025-10-11 16:25] -->
<div class="modal fade" id="resetResultModal" tabindex="-1" aria-labelledby="resetResultModalLabel" aria-hidden="true">
  <div class="modal-dialog modal-dialog-centered">
    <div class="modal-content">
      <div class="modal-header bg-success text-white">
        <h5 class="modal-title" id="resetResultModalLabel">Password Reset Successful</h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>
      <div class="modal-body">
        <p><strong>Username:</strong> <span id="resetUsername"></span></p>
        <p><strong>New Password:</strong>
          <span id="resetPasswordText" class="text-monospace"></span>
          <button class="btn btn-outline-secondary btn-sm" id="copyPasswordBtn">
            <i class="bi bi-clipboard"></i> Copy
          </button>
        </p>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-success" data-bs-dismiss="modal">Close</button>
      </div>
    </div>
  </div>
</div>
<!-- MODIFIED END -->

<script src="{{ asset('js/bootstrap.min.js') }}"></script>
<script>
    document.addEventListener('DOMContentLoaded', function() {
        const errorModalId = @json(session('open_modal'));
        if (errorModalId) {
            const errorModalElement = document.querySelector(errorModalId);
            if (errorModalElement) {
                const errorModal = new bootstrap.Modal(errorModalElement);
                errorModal.show();
            }
        }

        const successModalElement = document.getElementById('passwordResetSuccessModal');
        if (successModalElement && successModalElement.dataset.showModal === 'true') {
            document.getElementById('resetUsername').textContent = successModalElement.dataset.username;
            document.getElementById('resetPassword').value = successModalElement.dataset.password;
            const successModal = new bootstrap.Modal(successModalElement);
            successModal.show();
        }

        const copyBtn = document.getElementById('copyPasswordBtn');
        if (copyBtn) {
            copyBtn.addEventListener('click', function() {
                const passwordText = document.getElementById('resetPasswordText').textContent;
                navigator.clipboard.writeText(passwordText).then(() => {
                    this.innerHTML = '<i class="bi bi-check-lg"></i> Copied';
                    setTimeout(() => this.innerHTML = '<i class="bi bi-clipboard"></i> Copy', 2000);
                });
            });
        }

        // MODIFIED START - Add Reset Password handling JS [2025-10-11 16:25]
        let selectedUserGuid = null;
        let selectedUsername = null;

        document.querySelectorAll('.reset-password-btn').forEach(btn => {
            btn.addEventListener('click', function () {
                selectedUserGuid = this.dataset.guid;
                selectedUsername = this.dataset.username;
                const modal = new bootstrap.Modal(document.getElementById('confirmGlobalResetModal'));
                modal.show();
            });
        });

        document.getElementById('confirmGlobalResetBtn').addEventListener('click', function () {
            if (!selectedUserGuid) return;

            // MODIFIED START - 2025-10-11 09:03 - Corrected fetch URL structure to match Laravel route: /users/{guid}/reset-password.
            const domain = document.querySelector('select[name="domain"]').value;

            fetch(`/users/${selectedUserGuid}/reset-password`, {
            // MODIFIED END
                method: 'POST',
                headers: {
                    'X-CSRF-TOKEN': document.querySelector('meta[name="csrf-token"]') ? document.querySelector('meta[name="csrf-token"]').getAttribute('content') : '',
                    'Accept': 'application/json',
                    // MODIFIED START - 2025-10-11 08:59 - Explicitly set Content-Type for passing domain in body.
                    'Content-Type': 'application/json'
                    // MODIFIED END
                },
                // MODIFIED START - 2025-10-11 08:59 - Include domain in the request body.
                body: JSON.stringify({ domain: domain, _token: document.querySelector('meta[name="csrf-token"]') ? document.querySelector('meta[name="csrf-token"]').getAttribute('content') : '' })
                // MODIFIED END
            })
            .then(response => {
                 // MODIFIED START - 2025-10-11 08:59 - Handle non-200 responses to show better error messages.
                 if (!response.ok) {
                    throw new Error('Server returned an error: ' + response.status);
                 }
                 // MODIFIED END
                 return response.json();
            })
            .then(data => {
                const confirmModal = bootstrap.Modal.getInstance(document.getElementById('confirmGlobalResetModal'));
                confirmModal.hide();

                if (data.success) {
                    document.getElementById('resetUsername').textContent = data.username;
                    document.getElementById('resetPasswordText').textContent = data.new_password;

                    const resultModal = new bootstrap.Modal(document.getElementById('resetResultModal'));
                    resultModal.show();
                } else {
                    alert('Password reset failed: ' + (data.message || 'Unknown error.'));
                }
            })
            .catch(err => {
                const confirmModal = bootstrap.Modal.getInstance(document.getElementById('confirmGlobalResetModal'));
                confirmModal.hide();
                alert('An error occurred during password reset: ' + err.message);
                console.error(err);
            });
        });
        // MODIFIED END

        const firstNameInput = document.getElementById('first_name');
        const lastNameInput = document.getElementById('last_name');
        const displayNameInput = document.getElementById('display_name');

        function updateDisplayName() {
            if (!firstNameInput || !lastNameInput || !displayNameInput) {
                return;
            }

            const firstName = firstNameInput.value.trim();
            const lastName = lastNameInput.value.trim();

            const toSentenceCase = (str) => {
                if (!str) return '';
                return str.charAt(0).toUpperCase() + str.slice(1).toLowerCase();
            };

            displayNameInput.value = `${toSentenceCase(firstName)} ${toSentenceCase(lastName)}`.trim();
        }

        if (firstNameInput && lastNameInput) {
            firstNameInput.addEventListener('input', updateDisplayName);
            lastNameInput.addEventListener('input', updateDisplayName);
        }
    });
</script>

</body>
</html>
