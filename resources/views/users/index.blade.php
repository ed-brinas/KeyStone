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
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarCollapse" aria-controls="navbarCollapse" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarCollapse">
            <ul class="navbar-nav me-auto mb-2 mb-md-0"></ul>

            <form class="d-flex navbar-search-form" action="{{ route('users.index') }}" method="GET">
                <select name="domain" class="form-select me-2">
                    @foreach($domains as $domain)
                        <option value="{{ $domain }}" @if($domain == $selectedDomain) selected @endif>
                            {{ $domain }}
                        </option>
                    @endforeach
                </select>
                <input type="search" name="search_query" class="form-control me-2" placeholder="Search users..." value="{{ $searchQuery ?? '' }}">
                <button class="btn btn-primary" type="submit">Search</button>
            </form>

            <div class="dropdown ms-2">
                <button class="btn btn-dark dropdown-toggle" type="button" id="navMenu" data-bs-toggle="dropdown" aria-expanded="false">
                    <i class="bi bi-list" style="font-size: 1.5rem;"></i>
                </button>
                <ul class="dropdown-menu dropdown-menu-dark dropdown-menu-end" aria-labelledby="navMenu">
                    <li><a class="dropdown-item active" href="{{ route('users.index') }}">Users</a></li>
                    <li><a class="dropdown-item" href="#">Audit Log</a></li>
                </ul>
            </div>

            <div class="d-flex ms-2">
                 <a href="#" class="btn btn-outline-light">Logout</a>
            </div>
        </div>
    </div>
</nav>

<main class="container py-4">
    <!-- Flash Messages -->
    @if(session('success'))
        <div class="alert alert-success">{{ session('success') }}</div>
    @endif
    @if(session('error'))
        <div class="alert alert-danger">{{ session('error') }}</div>
    @endif
     @if(session('info'))
        <div class="alert alert-info">{{ session('info') }}</div>
    @endif
    @if(isset($error))
         <div class="alert alert-danger">{{ $error }}</div>
    @endif


    <div class="d-flex justify-content-between align-items-center mb-3">
        <h1 class="h2">User Directory</h1>
        <a href="#" class="btn btn-primary">Create New User</a>
    </div>

    <div class="card">
        <div class="card-header">
             @if(isset($searchQuery) && $searchQuery)
                Showing results for "<strong>{{ $searchQuery }}</strong>" in {{ $selectedDomain }}
            @else
                All users in {{ $selectedDomain }}
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
                    @forelse($users as $user)
                        <tr>
                            <td>{{ $user->getFirstAttribute('cn') }}</td>
                            <td>{{ $user->getFirstAttribute('samaccountname') }}</td>
                            <td>{{ $selectedDomain }}</td>
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
                                    <a href="{{ route('users.edit', ['guid' => $user->getObjectGuid(), 'domain' => $selectedDomain]) }}" class="p-2" title="Edit User">
                                        <i class="bi bi-pencil-square"></i>
                                    </a>

                                    @if ($user->getFirstAttribute('lockouttime') > 0)
                                        <form action="{{ route('users.unlock', ['guid' => $user->getObjectGuid()]) }}" method="POST" class="d-inline">
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

                                    <form action="{{ route('users.toggle-status', ['guid' => $user->getObjectGuid()]) }}" method="POST" class="d-inline">
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
<!-- The old script tag is no longer needed; Vite handles JS as well -->
</body>
</html>

