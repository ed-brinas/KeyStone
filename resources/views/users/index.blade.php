<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>KeyStone - AD User Management</title>

    <!-- MODIFIED START - 2025-10-10 19:55 - Replaced Vite with local Bootstrap CSS and added Bootstrap Icons CDN. -->
    <link href="{{ asset('css/bootstrap.min.css') }}" rel="stylesheet">
    <link href="{{ asset('css/bootstrap-icons/bootstrap-icons.min.css') }}" rel="stylesheet">
    <!-- MODIFIED END - 2025-10-10 19:55 -->

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
            display: none; /* Hide default dropdown arrow */
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

    <!-- Flash Messages -->
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
                                @if (str_ends_with($user->getFirstAttribute('samaccountname'), '-a'))
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


                                    <button type="button" class="btn btn-link p-2" title="Reset Password" data-bs-toggle="modal" data-bs-target="#resetPasswordConfirmModal-{{ $user->getConvertedGuid() }}">
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

        <!-- Reset Password Confirmation Modal -->
        <div class="modal fade" id="resetPasswordConfirmModal-{{ $user->getConvertedGuid() }}" tabindex="-1" aria-labelledby="resetPasswordConfirmModalLabel-{{ $user->getConvertedGuid() }}" aria-hidden="true">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title" id="resetPasswordConfirmModalLabel-{{ $user->getConvertedGuid() }}">Confirm Password Reset</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        Are you sure you want to reset the password for <strong>{{ $user->getFirstAttribute('displayname') }}</strong>?
                        <br><br>
                        This will also unlock the account if it is currently locked.
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <form action="{{ route('users.resetPassword', ['guid' => $user->getConvertedGuid()]) }}" method="POST">
                            @csrf
                            <input type="hidden" name="domain" value="{{ $selectedDomain }}">
                            <button type="submit" class="btn btn-danger">Reset Password</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>

    @endforeach
@endif


{{-- MODIFIED START - 2025-10-10 23:08 - Updated timestamp to finalize session data handling for password reset success modal. --}}
<div class="modal fade" id="passwordResetSuccessModal" tabindex="-1" aria-labelledby="passwordResetSuccessModalLabel" aria-hidden="true"
    @if(session('reset_success'))
        data-show-modal="true"
        data-username="{{ session('reset_username') }}"
        data-password="{{ session('reset_password') }}"
    @endif
>
{{-- MODIFIED END - 2025-10-10 23:08 --}}
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="passwordResetSuccessModalLabel">Password Reset Successfully</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body">
                <p>The password for user <strong id="resetUsername"></strong> has been reset.</p>
                <div class="mb-3">
                    <label for="resetPassword" class="form-label">New Temporary Password:</label>
                    <div class="input-group">
                        <input type="text" id="resetPassword" class="form-control-plaintext" readonly>
                        <button class="btn btn-outline-secondary" type="button" id="copyPasswordBtn">
                            <i class="bi bi-clipboard"></i> Copy
                        </button>
                    </div>
                </div>
                <p class="text-muted small">The user will be required to change this password at next logon.</p>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-primary" data-bs-dismiss="modal">Close</button>
            </div>
        </div>
    </div>
</div>


<script src="{{ asset('js/bootstrap.min.js') }}"></script>


{{-- MODIFIED START - 2025-10-10 23:08 - Updated timestamp to finalize JavaScript logic for password reset and copy button. --}}
<script>
    document.addEventListener('DOMContentLoaded', function() {
        // --- Logic for re-opening modals on validation failure ---
        const errorModalId = @json(session('open_modal'));
        if (errorModalId) {
            const errorModalElement = document.querySelector(errorModalId);
            if (errorModalElement) {
                const errorModal = new bootstrap.Modal(errorModalElement);
                errorModal.show();
            }
        }

        // --- Logic for showing the password reset success modal ---
        const successModalElement = document.getElementById('passwordResetSuccessModal');
        if (successModalElement && successModalElement.dataset.showModal === 'true') {
            document.getElementById('resetUsername').textContent = successModalElement.dataset.username;
            document.getElementById('resetPassword').value = successModalElement.dataset.password;

            const successModal = new bootstrap.Modal(successModalElement);
            successModal.show();
        }

        // --- Logic for the 'Copy Password' button ---
        const copyBtn = document.getElementById('copyPasswordBtn');
        if (copyBtn) {
            copyBtn.addEventListener('click', function() {
                const passwordInput = document.getElementById('resetPassword');
                // Use document.execCommand('copy') for better compatibility in iframe environments
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(passwordInput.value).then(() => {
                        console.log('Password copied to clipboard (modern API)');
                    }).catch(err => {
                        console.error('Could not copy text (modern API fallback): ', err);
                        // Fallback using execCommand (deprecated but often necessary in iframes)
                        passwordInput.select();
                        document.execCommand('copy');
                    });
                } else {
                    passwordInput.select();
                    document.execCommand('copy');
                }


                const originalText = this.innerHTML;
                this.innerHTML = '<i class="bi bi-check-lg"></i> Copied!';

                setTimeout(() => {
                    this.innerHTML = originalText;
                }, 2000);
            });
        }

        // --- Logic for auto-generating display name in create form ---
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
{{-- MODIFIED END - 2025-10-10 23:08 --}}


</body>
</html>
