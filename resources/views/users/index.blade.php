<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>KeyStone - AD User Management</title>

    <!-- Use Vite to include compiled CSS and JS -->
    @vite(['resources/css/app.css', 'resources/js/app.js'])

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
    </style>
</head>
<body>

<nav class="navbar navbar-expand-md navbar-dark bg-dark">
    <div class="container-fluid">
        <a class="navbar-brand" href="{{ route('users.index') }}">KeyStone</a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarContent" aria-controls="navbarContent" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarContent">
            <!-- Left aligned items -->
            <ul class="navbar-nav me-auto mb-2 mb-md-0">
                <li class="nav-item">
                    <button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#createUserModal">
                        <i class="bi bi-plus-circle-fill me-1"></i> Create User
                    </button>
                </li>
            </ul>

            <!-- Right aligned search form -->
            <form action="{{ route('users.index') }}" method="GET" class="d-flex navbar-search-form">
                <select class="form-select me-2" name="domain" onchange="this.form.submit()">
                    @foreach($domains as $domain)
                        <option value="{{ $domain }}" {{ $selectedDomain == $domain ? 'selected' : '' }}>
                            {{ $domain }}
                        </option>
                    @endforeach
                </select>
                <input class="form-control me-2" type="search" name="search_query" placeholder="Search..." aria-label="Search" value="{{ $searchQuery }}">
                <button class="btn btn-outline-success" type="submit">Search</button>
            </form>
        </div>
    </div>
</nav>

<div class="container-fluid mt-4">
    @if(session('success'))
        <div class="alert alert-success alert-dismissible fade show" role="alert">
            {{ session('success') }}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
    @endif
    @if(session('error'))
        <div class="alert alert-danger alert-dismissible fade show" role="alert">
            {{ session('error') ?: $error }}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
    @endif
    @if($error)
        <div class="alert alert-danger">{{ $error }}</div>
    @endif


    <div class="card">
        <div class="card-body">
            <table class="table table-hover">
                <thead class="table-light">
                    <tr>
                        <th scope="col">Display Name</th>
                        <th scope="col">Username</th>
                        <th scope="col">Email</th>
                        <th scope="col">Status</th>
                        <th scope="col" class="text-center">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    @forelse ($users as $user)
                        <tr>
                            <td>{{ $user->getFirstAttribute('displayname') ?? 'N/A' }}</td>
                            <td>{{ $user->getFirstAttribute('samaccountname') ?? 'N/A' }}</td>
                            <td>{{ $user->getFirstAttribute('mail') ?? 'N/A' }}</td>
                            <td>
                                @if ($user->isDisabled())
                                    <span class="badge bg-secondary">Disabled</span>
                                @else
                                    <span class="badge bg-success">Enabled</span>
                                @endif
                            </td>
                            <td class="text-center table-actions">
                                <div class="dropdown">
                                    <button class="btn btn-link" type="button" id="dropdownMenuButton_{{ $user->getConvertedGuid() }}" data-bs-toggle="dropdown" aria-expanded="false">
                                        <i class="bi bi-three-dots-vertical"></i>
                                    </button>
                                    <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="dropdownMenuButton_{{ $user->getConvertedGuid() }}">
                                        <li>
                                            <a class="dropdown-item" href="{{ route('users.edit', ['guid' => $user->getConvertedGuid(), 'domain' => $selectedDomain]) }}">
                                                <i class="bi bi-pencil-square me-2"></i>Edit
                                            </a>
                                        </li>
                                        <li><hr class="dropdown-divider"></li>

                                        <!-- MODIFIED START - 2025-10-10 19:36 - Added isset() to prevent "Trying to access array offset on null" error. -->
                                        @if(isset($user->lockouttime[0]) && $user->lockouttime[0] > 0)
                                            <li>
                                                <form action="{{ route('users.unlock', ['guid' => $user->getConvertedGuid()]) }}" method="POST" class="d-inline">
                                                    @csrf
                                                    <input type="hidden" name="domain" value="{{ $selectedDomain }}">
                                                    <button type="submit" class="dropdown-item">
                                                        <i class="bi bi-unlock-fill me-2"></i>Unlock Account
                                                    </button>
                                                </form>
                                            </li>
                                        @endif
                                        <!-- MODIFIED END - 2025-10-10 19:36 -->

                                        <li>
                                            <form action="{{ route('users.toggleStatus', ['guid' => $user->getConvertedGuid()]) }}" method="POST" class="d-inline">
                                                @csrf
                                                <input type="hidden" name="domain" value="{{ $selectedDomain }}">
                                                <button type="submit" class="dropdown-item">
                                                    @if ($user->isDisabled())
                                                        <i class="bi bi-check-circle-fill me-2"></i>Enable Account
                                                    @else
                                                        <i class="bi bi-dash-circle-fill me-2"></i>Disable Account
                                                    @endif
                                                </button>
                                            </form>
                                        </li>
                                    </ul>
                                </div>
                            </td>
                        </tr>
                    @empty
                        <tr>
                            <td colspan="5" class="text-center">No users found.</td>
                        </tr>
                    @endforelse
                </tbody>
            </table>
        </div>
    </div>
</div>

<!-- MODIFIED START - 2025-10-10 19:09 - Added a modal for user creation (Phase 3 Stub). -->
<!-- Create User Modal -->
<div class="modal fade" id="createUserModal" tabindex="-1" aria-labelledby="createUserModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="createUserModalLabel">Create New User</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body">
                <!-- User creation form will go here -->
                <p>User creation form fields will be added in Phase 3.</p>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                <button type="button" class="btn btn-primary" disabled>Save User</button>
            </div>
        </div>
    </div>
</div>
<!-- MODIFIED END - 2025-10-10 19:09 -->


{{-- MODIFIED START - 2025-10-10 19:09 - Added JS to dynamically generate display name --}}
<script>
    // This script ensures that modals and other JS-dependent Bootstrap components will work.
    // It is triggered after the DOM is fully loaded.
    document.addEventListener('DOMContentLoaded', function () {
        // Auto-generate display name in the create user form.
        const firstNameInput = document.getElementById('first_name');
        const lastNameInput = document.getElementById('last_name');
        const displayNameInput = document.getElementById('display_name');

        function updateDisplayName() {
            // Guard against the elements not being present on the page.
            if (!firstNameInput || !lastNameInput || !displayNameInput) {
                return;
            }

            const firstName = firstNameInput.value.trim();
            const lastName = lastNameInput.value.trim();

            // Helper function to convert a string to "Sentence case"
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
{{-- MODIFIED END - 2025-10-10 19:09 --}}

</body>
</html>

