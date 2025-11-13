{{-- resources/views/users/partials/nav.blade.php --}}
<nav class="navbar navbar-expand-md navbar-dark bg-dark">
    <div class="container-fluid">
        <a class="navbar-brand" href="/">KeyStone</a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarCollapse">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarCollapse">
            <ul class="navbar-nav me-auto mb-2 mb-md-0">
                 <li class="nav-item"><a class="nav-link" href="/" title="Users"><i class="bi bi-people-fill" style="font-size: 1.5rem;"></i></a></li>
                 <li class="nav-item"><a class="nav-link" href="#" title="Audit Log"><i class="bi bi-journal-text" style="font-size: 1.5rem;"></i></a></li>
            </ul>

            {{-- This form's events will be captured by app.js --}}
            <form class="d-flex" id="user-search-form">
                <select id="domain-select" name="domain" class="form-select me-2">
                    {{-- Options will be populated by app.js, but you can pass initial ones from controller --}}
                    @if(isset($domains))
                        @foreach($domains as $domain)
                            <option value="{{ $domain }}" @if(isset($selectedDomain) && $domain == $selectedDomain) selected @endif>{{ $domain }}</option>
                        @endforeach
                    @endif
                </select>
                <input type="search" id="name-filter" name="search_query" class="form-control me-2" placeholder="Search users...">
                <button class="btn btn-outline-light" type="submit"><i class="bi bi-search"></i></button>
            </form>

            <ul class="navbar-nav ms-2">
                 <li class="nav-item"><a href="#" class="nav-link" title="Logout" id="logout-btn"><i class="bi bi-box-arrow-right" style="font-size: 1.5rem;"></i></a></li>
            </ul>
        </div>
    </div>
</nav>
