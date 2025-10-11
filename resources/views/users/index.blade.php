@extends('layouts.app')

@section('title', 'KeyStone - Manage Users')

@section('content')

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

                                    <button type="button" class="btn btn-link p-2 reset-password-btn" title="Reset Password" data-username="{{ $user->username }}" data-id="{{ $user->id }}">
                                        <i class="bi bi-key-fill text-secondary"></i>
                                    </button>


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

    @include('users.create')
    @include('users.reset.password')

    @if(isset($users))
        @foreach($users as $user)
            @include('users.edit', ['user' => $user, 'domain' => $selectedDomain, 'optionalGroups' => $optionalGroups])
        @endforeach
    @endif

@endsection
