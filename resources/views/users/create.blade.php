<div class="modal fade" id="userCreateModal" tabindex="-1" aria-labelledby="userCreateModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <form action="{{ route('users.store') }}" method="POST">
                @csrf
                <div class="modal-header">
                    <h5 class="modal-title" id="userCreateModalLabel">Create New User</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">

                    @if(session('open_modal') == '#userCreateModal' && (session('error') || $errors->any()))
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


                    <div class="row">
                        <div class="col-md-6 mb-3">
                            <label for="first_name" class="form-label">First Name</label>
                            <input type="text" class="form-control @error('first_name') is-invalid @enderror" id="first_name" name="first_name" value="{{ old('first_name') }}" required>

                            @error('first_name')
                                <div class="invalid-feedback">{{ $message }}</div>
                            @enderror

                        </div>
                        <div class="col-md-6 mb-3">
                            <label for="last_name" class="form-label">Last Name</label>
                            <input type="text" class="form-control @error('last_name') is-invalid @enderror" id="last_name" name="last_name" value="{{ old('last_name') }}" required>

                            @error('last_name')
                                <div class="invalid-feedback">{{ $message }}</div>
                            @enderror

                        </div>
                    </div>

                    {{-- MODIFIED START - 2025-10-10 21:42 - Added the Display Name field back to the create user modal. --}}
                    <div class="mb-3">
                        <label for="display_name" class="form-label">Display Name</label>
                        <input type="text" class="form-control" id="display_name" name="display_name" value="{{ old('display_name') }}" readonly>
                        <div class="form-text">This is automatically generated from the first and last name.</div>
                    </div>
                    {{-- MODIFIED END - 2025-10-10 21:42 --}}

                    <div class="row">
                        <div class="col-md-6 mb-3">
                            <label for="date_of_birth" class="form-label">Date of Birth</label>
                            <input type="date" class="form-control @error('date_of_birth') is-invalid @enderror" id="date_of_birth" name="date_of_birth" value="{{ old('date_of_birth') }}" required>

                            @error('date_of_birth')
                                <div class="invalid-feedback">{{ $message }}</div>
                            @enderror

                        </div>
                        <div class="col-md-6 mb-3">
                            <label for="mobile_number" class="form-label">Mobile Number</label>
                            <input type="text" class="form-control @error('mobile_number') is-invalid @enderror" id="mobile_number" name="mobile_number" value="{{ old('mobile_number') }}" required>

                            @error('mobile_number')
                                <div class="invalid-feedback">{{ $message }}</div>
                            @enderror

                        </div>
                    </div>
                     <div class="row">
                         <div class="col-md-6 mb-3">
                            <label for="account_expires" class="form-label">Account Expiry (Optional)</label>
                            <input type="date" class="form-control @error('account_expires') is-invalid @enderror" id="account_expires" name="account_expires" value="{{ old('account_expires') }}">

                            @error('account_expires')
                                <div class="invalid-feedback">{{ $message }}</div>
                            @enderror

                        </div>
                         <div class="col-md-6 mb-3">
                            <label for="domain" class="form-label">Domain</label>
                            <select class="form-select @error('domain') is-invalid @enderror" id="domain" name="domain" required>
                                @foreach($domains as $domain)
                                    <option value="{{ $domain }}" {{ old('domain', $selectedDomain) == $domain ? 'selected' : '' }}>
                                        {{ $domain }}
                                    </option>
                                @endforeach
                            </select>

                            @error('domain')
                                <div class="invalid-feedback">{{ $message }}</div>
                            @enderror

                        </div>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Optional Groups</label>
                        <div class="border rounded p-2" style="max-height: 150px; overflow-y: auto;">
                            @foreach($optionalGroups as $group)
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" name="groups[]" value="{{ $group }}" id="group_{{ $group }}"
                                    {{ is_array(old('groups')) && in_array($group, old('groups')) ? 'checked' : '' }}>
                                <label class="form-check-label" for="group_{{ $group }}">
                                    {{ $group }}
                                </label>
                            </div>
                            @endforeach
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-primary">Create User</button>
                </div>
            </form>
        </div>
    </div>
</div>

