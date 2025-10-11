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
                        {{-- The 'display_name' field is hidden but its value is determined by JavaScript for display in the input,
                             then manually generated and validated on the server side using first_name and last_name. --}}
                        <input type="text" class="form-control" id="display_name" name="display_name_display" value="{{ old('display_name_display') }}" readonly>
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
{{-- MODIFIED START - Add the script for autofilling display name and modal reset logic --}}
<script>
    /**
     * Attaches event listeners to the user creation form fields
     * to handle real-time UI logic for Display Name autofill.
     */
    function initCreateUserFormLogic() {
        // Note: The input is named 'display_name_display' here since the actual
        // 'displayname' LDAP attribute is constructed on the server-side.
        const firstNameInput = document.getElementById('first_name');
        const lastNameInput = document.getElementById('last_name');
        const displayNameInput = document.getElementById('display_name');

        if (!firstNameInput || !lastNameInput || !displayNameInput) {
            return; // Exit if elements aren't found
        }

        const updateDisplayName = () => {
            const firstName = firstNameInput.value.trim();
            const lastName = lastNameInput.value.trim();
            // Update the display input (which is readonly)
            displayNameInput.value = `${firstName} ${lastName}`.trim();
        };

        firstNameInput.addEventListener('input', updateDisplayName);
        lastNameInput.addEventListener('input', updateDisplayName);

        // Run on modal open to catch `old()` values if validation failed
        updateDisplayName();
    }

    // Get the modal and its form
    const userCreateModal = document.getElementById('userCreateModal');
    const userCreateForm = userCreateModal ? userCreateModal.querySelector('form') : null;

    if (userCreateModal) {
        // 1. Attach the autofill logic when the modal is shown
        userCreateModal.addEventListener('shown.bs.modal', initCreateUserFormLogic);

        // 2. MODIFIED: Attach the reset logic when the modal is hidden
        userCreateModal.addEventListener('hidden.bs.modal', function () {
            // Reset the form to clear all values (except the domain selector's default)
            if (userCreateForm) {
                userCreateForm.reset();
            }

            // Remove Laravel validation error classes and messages manually
            userCreateForm.querySelectorAll('.is-invalid').forEach(el => {
                el.classList.remove('is-invalid');
            });
            userCreateForm.querySelectorAll('.invalid-feedback').forEach(el => {
                el.remove();
            });
            // Also, manually reset the Display Name field since `form.reset()` might not clear its readonly value
            document.getElementById('display_name').value = '';
        });
    }
</script>
{{-- MODIFIED END --}}
