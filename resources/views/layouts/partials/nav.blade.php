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
