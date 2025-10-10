@php
    $userGroups = $user->groups ? $user->groups->pluck('cn')->flatten()->toArray() : [];
@endphp
<div class="modal fade" id="editUserModal-{{ $user->getConvertedGuid() }}" tabindex="-1" aria-labelledby="editUserModalLabel-{{ $user->getConvertedGuid() }}" aria-hidden="true">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <form action="{{ route('users.update', ['guid' => $user->getConvertedGuid()]) }}" method="POST">
                @csrf
                @method('PUT')
                <input type="hidden" name="domain" value="{{ $domain }}">
                <div class="modal-header">
                    <h5 class="modal-title" id="editUserModalLabel-{{ $user->getConvertedGuid() }}">Edit User: {{ $user->getFirstAttribute('cn') }}</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    {{-- MODIFIED START - 2025-10-10 21:36 - Added a section to display general errors inside the modal. --}}
                    @if(session('open_modal') == '#editUserModal-'.$user->getConvertedGuid() && (session('error') || $errors->any()))
                        <div class="alert alert-danger">
                            <ul class="mb-0">
                                @if(session('error'))
                                    <li>{{ session('error') }}</li>
                                @endif
                                @foreach ($errors->all() as $error)
                                    <li>{{ $error }}</li>
                                @endforeach
                            </ul>
                        </div>
                    @endif
                    {{-- MODIFIED END - 2025-10-10 21:36 --}}

                    <div class="row">
                        <div class="col-md-6 mb-3">
                            <label for="first_name_{{ $user->getConvertedGuid() }}" class="form-label">First Name</label>
                            <input type="text" class="form-control @error('first_name') is-invalid @enderror" id="first_name_{{ $user->getConvertedGuid() }}" name="first_name" value="{{ old('first_name', $user->getFirstAttribute('givenname')) }}" required>
                             {{-- MODIFIED START - 2025-10-10 21:36 - Added field-specific validation message. --}}
                            @error('first_name')
                                <div class="invalid-feedback">{{ $message }}</div>
                            @enderror
                            {{-- MODIFIED END - 2025-10-10 21:36 --}}
                        </div>
                        <div class="col-md-6 mb-3">
                            <label for="last_name_{{ $user->getConvertedGuid() }}" class="form-label">Last Name</label>
                            <input type="text" class="form-control @error('last_name') is-invalid @enderror" id="last_name_{{ $user->getConvertedGuid() }}" name="last_name" value="{{ old('last_name', $user->getFirstAttribute('sn')) }}" required>
                             {{-- MODIFIED START - 2025-10-10 21:36 - Added field-specific validation message. --}}
                            @error('last_name')
                                <div class="invalid-feedback">{{ $message }}</div>
                            @enderror
                            {{-- MODIFIED END - 2025-10-10 21:36 --}}
                        </div>
                    </div>

                    <div class="mb-3">
                        <label for="samaccountname_{{ $user->getConvertedGuid() }}" class="form-label">Username</label>
                        <input type="text" class="form-control" id="samaccountname_{{ $user->getConvertedGuid() }}" name="samaccountname" value="{{ $user->getFirstAttribute('samaccountname') }}" readonly disabled>
                        <div class="form-text">The username (sAMAccountName) cannot be changed.</div>
                    </div>

                    <div class="row">
                        <div class="col-md-6 mb-3">
                            <label for="date_of_birth_{{ $user->getConvertedGuid() }}" class="form-label">Date of Birth</label>
                            <input type="date" class="form-control @error('date_of_birth') is-invalid @enderror" id="date_of_birth_{{ $user->getConvertedGuid() }}" name="date_of_birth" value="{{ old('date_of_birth', $user->getFirstAttribute('extensionattribute1')) }}" required>
                             {{-- MODIFIED START - 2025-10-10 21:36 - Added field-specific validation message. --}}
                            @error('date_of_birth')
                                <div class="invalid-feedback">{{ $message }}</div>
                            @enderror
                            {{-- MODIFIED END - 2025-10-10 21:36 --}}
                        </div>
                        <div class="col-md-6 mb-3">
                            <label for="mobile_number_{{ $user->getConvertedGuid() }}" class="form-label">Mobile Number</label>
                            <input type="text" class="form-control @error('mobile_number') is-invalid @enderror" id="mobile_number_{{ $user->getConvertedGuid() }}" name="mobile_number" value="{{ old('mobile_number', $user->getFirstAttribute('mobile')) }}" required>
                             {{-- MODIFIED START - 2025-10-10 21:36 - Added field-specific validation message. --}}
                            @error('mobile_number')
                                <div class="invalid-feedback">{{ $message }}</div>
                            @enderror
                            {{-- MODIFIED END - 2025-10-10 21:36 --}}
                        </div>
                    </div>

                    <div class="row">
                         <div class="col-md-6 mb-3">
                            <label for="account_expires_{{ $user->getConvertedGuid() }}" class="form-label">Account Expiry (Optional)</label>
                            <input type="date" class="form-control @error('account_expires') is-invalid @enderror" id="account_expires_{{ $user->getConvertedGuid() }}" name="account_expires" value="{{ old('account_expires', $user->accountexpires instanceof \Carbon\Carbon ? $user->accountexpires->format('Y-m-d') : '') }}">
                             {{-- MODIFIED START - 2025-10-10 21:36 - Added field-specific validation message. --}}
                            @error('account_expires')
                                <div class="invalid-feedback">{{ $message }}</div>
                            @enderror
                            {{-- MODIFIED END - 2025-10-10 21:36 --}}
                        </div>
                    </div>

                    <div class="mb-3">
                        <label class="form-label">Optional Groups</label>
                        <div class="border rounded p-2" style="max-height: 150px; overflow-y: auto;">
                            @foreach($optionalGroups as $group)
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" name="groups[]" value="{{ $group }}" id="edit_group_{{ $group }}_{{ $user->getConvertedGuid() }}"
                                    {{ in_array($group, old('groups', $userGroups)) ? 'checked' : '' }}>
                                <label class="form-check-label" for="edit_group_{{ $group }}_{{ $user->getConvertedGuid() }}">
                                    {{ $group }}
                                </label>
                            </div>
                            @endforeach
                        </div>
                    </div>

                    <hr class="my-4">
                    <h5 class="mb-3">Reset Password (Optional)</h5>

                    <div class="row">
                        <div class="col-md-6 mb-3">
                            <label for="password_{{ $user->getConvertedGuid() }}" class="form-label">New Password</label>
                            <input type="password" class="form-control @error('password') is-invalid @enderror" id="password_{{ $user->getConvertedGuid() }}" name="password">
                             {{-- MODIFIED START - 2025-10-10 21:36 - Added field-specific validation message. --}}
                            @error('password')
                                <div class="invalid-feedback">{{ $message }}</div>
                            @enderror
                            {{-- MODIFIED END - 2025-10-10 21:36 --}}
                        </div>
                        <div class="col-md-6 mb-3">
                            <label for="password_confirmation_{{ $user->getConvertedGuid() }}" class="form-label">Confirm New Password</label>
                            <input type="password" class="form-control" id="password_confirmation_{{ $user->getConvertedGuid() }}" name="password_confirmation">
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-primary">Save Changes</button>
                </div>
            </form>
        </div>
    </div>
</div>

