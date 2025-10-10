{{--
    File Path: resources/views/users/create.blade.php
    Creation Date: 2025-10-10 19:13
    Purpose: This Blade partial contains the HTML for the "Create New User" modal.
             It is included by the main index view (index.blade.php).
--}}
<div class="modal fade" id="userCreateModal" tabindex="-1" aria-labelledby="userCreateModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="userCreateModalLabel">Create New User</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <form action="{{ route('users.store') }}" method="POST">
                @csrf
                <div class="modal-body">
                    <div class="row">
                        <div class="col-md-6 mb-3">
                            <label for="first_name" class="form-label">First Name</label>
                            <input type="text" class="form-control" id="first_name" name="first_name" required value="{{ old('first_name') }}">
                        </div>
                        <div class="col-md-6 mb-3">
                            <label for="last_name" class="form-label">Last Name</label>
                            <input type="text" class="form-control" id="last_name" name="last_name" required value="{{ old('last_name') }}">
                        </div>
                    </div>
                    <div class="mb-3">
                        <label for="display_name" class="form-label">Display Name</label>
                        <input type="text" class="form-control" id="display_name" name="display_name" readonly>
                    </div>
                    <div class="mb-3">
                         <label for="domain" class="form-label">Domain</label>
                         <select class="form-select" id="domain" name="domain">
                            @if(isset($domains))
                                @foreach($domains as $domain)
                                    <option value="{{ $domain }}" @if(isset($selectedDomain) && $domain == $selectedDomain) selected @endif>{{ $domain }}</option>
                                @endforeach
                            @endif
                        </select>
                    </div>
                     <div class="mb-3">
                        <label class="form-label">Optional Groups</label>
                        @foreach(config('keystone.provisioning.optionalGroupsForStandardUser', []) as $group)
                        <div class="form-check">
                            <input class="form-check-input" type="checkbox" name="optional_groups[]" value="{{ $group }}" id="group_{{ Str::slug($group) }}">
                            <label class="form-check-label" for="group_{{ Str::slug($group) }}">
                                {{ $group }}
                            </label>
                        </div>
                        @endforeach
                    </div>
                    <hr>
                    <div class="form-check form-switch">
                      <input class="form-check-input" type="checkbox" role="switch" id="create_admin_account" name="create_admin_account">
                      <label class="form-check-label" for="create_admin_account">Create & Manage Admin Account for this User</label>
                    </div>

                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                    <button type="submit" class="btn btn-primary">Create User</button>
                </div>
            </form>
        </div>
    </div>
</div>

