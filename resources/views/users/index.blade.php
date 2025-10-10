<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>KeyStone - AD User Management</title>
    <!-- Local Bootstrap CSS -->
    <link href="{{ asset('css/bootstrap.min.css') }}" rel="stylesheet">
    <style>
        body {
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            background-color: #f8f9fa;
        }
        main {
            flex-grow: 1;
        }
        .table-actions a {
            color: var(--bs-secondary);
            text-decoration: none;
        }
        .table-actions a:hover {
            color: var(--bs-dark);
        }
    </style>
</head>
<body>

<nav class="navbar navbar-expand-md navbar-dark bg-dark mb-4">
    <div class="container-fluid">
        <a class="navbar-brand" href="{{ route('users.index') }}">KeyStone</a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarCollapse" aria-controls="navbarCollapse" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarCollapse">
            <ul class="navbar-nav me-auto mb-2 mb-md-0">
                <li class="nav-item">
                    <a class="nav-link active" aria-current="page" href="{{ route('users.index') }}">Users</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="#">Audit Log</a>
                </li>
            </ul>
        </div>
    </div>
</nav>

<main class="container">
    <div class="bg-light p-4 p-md-5 rounded">
        <h1 class="display-6">User Search</h1>
        <p class="lead text-muted">Find and manage Active Directory users across your domains.</p>

        <!-- Search Form -->
        <div class="mt-4">
            <form action="{{ route('users.index') }}" method="GET">
                <div class="input-group">
                    <select name="domain" class="form-select" style="max-width: 150px;">
                        @foreach($domains as $domain)
                            <option value="{{ $domain }}" @if($domain == $selectedDomain) selected @endif>
                                {{ $domain }}
                            </option>
                        @endforeach
                    </select>
                    <input type="text" name="search_query" class="form-control form-control-lg" placeholder="Enter username, name, or email..." value="{{ $searchQuery ?? '' }}" autofocus>
                    <button class="btn btn-primary" type="submit">Search</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Results Section -->
    @if(isset($searchQuery) && $searchQuery)
        <div class="card mt-4">
            <div class="card-header">
                Search Results for "{{ $searchQuery }}" in {{ $selectedDomain }}
            </div>
            <div class="table-responsive">
                <table class="table table-hover align-middle mb-0">
                    <thead>
                        <tr>
                            <th scope="col">Display Name</th>
                            <th scope="col">Username</th>
                            <th scope="col">Domain</th>
                            <th scope="col">Privileged</th>
                            <th scope="col">Expires</th>
                            <th scope="col">Status</th>
                            <th scope="col" class="text-center">Actions</th>
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
                                        <span class="badge bg-purple-lt">Yes</span>
                                    @else
                                        <span class="text-muted">No</span>
                                    @endif
                                </td>
                                <td>{{ $user->getAccountExpiry() ? $user->getAccountExpiry()->format('Y-m-d') : 'Never' }}</td>
                                <td>
                                    @if ($user->isDisabled())
                                        <span class="badge bg-danger">Disabled</span>
                                    @else
                                        <span class="badge bg-success">Enabled</span>
                                    @endif
                                </td>
                                <td class="text-center table-actions">
                                    <div class="d-flex justify-content-center align-items-center">
                                        <a href="#" class="p-2" title="Edit User">
                                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"></path></svg>
                                        </a>
                                        @if ($user->isLocked())
                                            <a href="#" class="p-2" title="Unlock Account">
                                                <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M7 7H6a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2v-2"></path><path d="M9 9V7a3 3 0 0 1 3-3v0a3 3 0 0 1 3 3v2"></path><rect x="13" y="13" width="8" height="5" rx="1"></rect><path d="M17 13v-2"></path></svg>
                                            </a>
                                        @else
                                             <a href="#" class="p-2 text-black-50" title="Account OK">
                                                <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
                                            </a>
                                        @endif
                                        @if ($user->isDisabled())
                                            <a href="#" class="p-2" title="Enable Account">
                                                <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path><path d="M13.73 21a2 2 0 0 1-3.46 0"></path><path d="M2 8c0-2.2.7-4.3 2-6"></path><path d="M22 8a10 10 0 0 0-2-6"></path></svg>
                                            </a>
                                        @else
                                            <a href="#" class="p-2" title="Disable Account">
                                               <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22c5.523 0 10-4.477 10-10S17.523 2 12 2 2 6.477 2 12s4.477 10 10 10z"></path><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>
                                            </a>
                                        @endif
                                    </div>
                                </td>
                            </tr>
                        @empty
                            <tr>
                                <td colspan="7" class="text-center p-5">
                                    No users found matching your query.
                                </td>
                            </tr>
                        @endforelse
                    </tbody>
                </table>
            </div>
        </div>
    @else
        <div class="text-center text-muted py-5 mt-4">
             <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" class="d-block mx-auto mb-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
            <h3 class="h4">Ready to Search</h3>
            <p>Enter a search term above to find an Active Directory user.</p>
        </div>
    @endif
</main>

<!-- Local Bootstrap JS -->
<script src="{{ asset('js/bootstrap.min.js') }}"></script>

</body>
</html>

