{{-- resources/views/users/index.blade.php --}}
@extends('layouts.app')

@section('title', 'KeyStone - User Management')

@section('content')
    {{-- This is the main container for the app, visible after successful initialization. --}}
    <div id="main-app" style="display: none;">

        {{-- Include your navigation bar partial --}}
        @include('layouts.partials.nav')

        <main class="container mt-4 mb-4">
            {{-- Alert placeholder for dynamic messages from app.js --}}
            <div id="alert-placeholder"></div>

            {{-- User Management Card --}}
            <div class="card">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <h4>User Management</h4>
                    <button id="create-user-show-modal-btn" class="btn btn-primary" disabled>Create New User</button>
                </div>
                <div class="card-body">

                    <div class="table-responsive mt-3">
                        <table class="table table-hover">
                            <thead>
                                <tr>
                                    <th>Display Name</th>
                                    <th>Username</th>
                                    <th>Domain</th>
                                    <th>Status</th>
                                    <th>Expires</th>
                                    <th>Has Admin?</th>                                    
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody id="user-table-body">
                                {{-- This table body will be populated by app.js --}}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </main>

        <footer class="footer mt-auto py-3 bg-light border-top">
            <div class="container text-center">
                <span class="text-muted">&copy; {{ date('Y') }} KeyStone. All rights reserved.</span>
            </div>
        </footer>
    </div>

    {{-- ------------------------------------------------------------------- --}}
    {{--                         SECTION: Modals                               --}}
    {{-- ------------------------------------------------------------------- --}}

    {{-- MODAL: Create New User --}}
    <div class="modal fade" id="create-user-modal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Create New User</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <!-- Alert Placeholder for Create User Modal -->
                    <div id="create-user-alert-placeholder"></div>

                    <form id="create-user-form" novalidate>
                        <div class="alert alert-info small mx-auto">A secure, random password will be generated for the new user account(s).</div>
                        <div class="row">
                            <div class="col-md-6 mb-3">
                                <label for="create-domain" class="form-label">Target Domain</label>
                                <select class="form-select" id="create-domain" required></select>
                            </div>
                            <div class="col-md-6 mb-3">
                                <label for="create-doe" class="form-label">Id Expiration</label>
                                <input type="date" class="form-control" id="create-doe">
                            </div>
                        </div>

                        <div class="row">
                            <div class="col-md-6 mb-3">
                                <label for="create-firstname" class="form-label">First Name</label>
                                <input type="text" class="form-control" id="create-firstname" required>
                            </div>
                            <div class="col-md-6 mb-3">
                                <label for="create-lastname" class="form-label">Last Name</label>
                                <input type="text" class="form-control" id="create-lastname" required>
                            </div>
                        </div>
                        <div class="mb-3">
                            <label for="create-samaccountname" class="form-label">Username (Badge #)</label>
                            <input type="text" class="form-control" id="create-samaccountname" required>
                        </div>
                        <div class="row">
                            <div class="col-md-6 mb-3">
                                <label for="create-dob" class="form-label">Date of Birth</label>
                                <input type="date" class="form-control" id="create-dob" required>
                            </div>
                            <div class="col-md-6 mb-3">
                                <label for="create-mobile" class="form-label">Mobile Number</label>
                                <input type="text" class="form-control" id="create-mobile" placeholder="05XXXXXXXX" required>
                            </div>
                        </div>

                        <div id="create-standard-groups-container" class="mb-3" style="display: none;">
                            <label class="form-label">Member Of</label>
                            <div id="create-standard-groups-list"></div>
                        </div>
                        <div id="create-admin-container" class="form-check form-switch mb-3" style="display: none;">
                            <input class="form-check-input" type="checkbox" role="switch" id="create-admin-account">
                            <label class="form-check-label" for="create-admin-account">Create associated admin account</label>
                        </div>
                        <div id="create-privilege-groups-container" class="mb-3" style="display: none;">
                            <label class="form-label">Member Of</label>
                            <div id="create-privilege-groups-list"></div>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                    <button type="submit" form="create-user-form" class="btn btn-primary">Create User</button>
                </div>
            </div>
        </div>
    </div>

    {{-- MODAL: Edit User --}}
    <div class="modal fade" id="edit-user-modal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header"><h5 class="modal-title">Edit User</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
                <div class="modal-body">
                    <!-- Alert Placeholder for Edit User Modal -->
                    <div id="edit-user-alert-placeholder"></div>

                    <form id="edit-user-form" novalidate>

                        <div class="row">
                            <div class="col-md-6 mb-3">
                                <label for="edit-domain" class="form-label">Target Domain</label>
                                <input type="text" class="form-control" id="edit-domain" readonly>
                            </div>
                            <div class="col-md-6 mb-3">
                                <label for="edit-doe" class="form-label">Id Expiration</label>
                                <input type="date" class="form-control" id="edit-doe">
                            </div>
                        </div>

                        <div class="row">
                            <div class="col-md-6 mb-3">
                                <label for="edit-firstname" class="form-label">First Name</label>
                                <input type="text" class="form-control" id="edit-firstname" required>
                            </div>
                            <div class="col-md-6 mb-3">
                                <label for="edit-lastname" class="form-label">Last Name</label>
                                <input type="text" class="form-control" id="edit-lastname" required>
                            </div>
                        </div>
                        <div class="mb-3">
                            <label for="edit-samaccountname" class="form-label">Badge or Iqama Number</label>
                            <input type="text" class="form-control" id="edit-samaccountname" readonly>
                        </div>
                        <div class="row">
                            <div class="col-md-6 mb-3">
                                <label for="edit-dob" class="form-label">Date of Birth</label>
                                <input type="date" class="form-control" id="edit-dob" required>
                            </div>
                            <div class="col-md-6 mb-3">
                                <label for="edit-mobile" class="form-label">Mobile Number</label>
                                <input type="text" class="form-control" id="edit-mobile" placeholder="05XXXXXXXX" required>
                            </div>
                        </div>
                        <div id="edit-standard-groups-container" class="mb-3" style="display: none;"><label class="form-label">Member Of</label><div id="edit-standard-groups-list"></div></div>
                        <div id="edit-admin-container" class="form-check form-switch mb-3" style="display: none;"><input class="form-check-input" type="checkbox" role="switch" id="edit-admin-account"><label class="form-check-label" for="edit-admin-account">Enable Administrator Access</label></div>
                        <div id="edit-privilege-groups-container" class="mb-3" style="display: none;">
                            <div class="mb-3">
                                <label for="edit-admin-samaccountname" class="form-label">Admin Account</label>
                                <input type="text" class="form-control" id="edit-admin-samaccountname" readonly>
                            </div>                                
                            <label class="form-label">Member Of</label>
                            <div id="edit-privilege-groups-list"></div>
                        </div>
                    </form>
                </div>
                <div class="modal-footer"><button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button><button type="submit" form="edit-user-form" class="btn btn-primary">Save Changes</button></div>
            </div>
        </div>
    </div>

    {{-- MODAL: Create User Result --}}
    <div class="modal fade" id="create-user-result-modal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header"><h5 class="modal-title">User Creation Successful</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
                <div class="modal-body" id="create-user-result-body">
                    <!-- Alert Placeholder for Create User Result Modal -->
                    <div id="create-result-alert-placeholder"></div>
                    {{-- Content will be injected here by app.js --}}
                </div>
                <div class="modal-footer"><button type="button" class="btn btn-primary" data-bs-dismiss="modal">Close</button></div>
            </div>
        </div>
    </div>

    {{-- MODAL: Reset Password Result --}}
    <div class="modal fade" id="reset-password-result-modal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header"><h5 class="modal-title">Password Reset Successful</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
                <div class="modal-body">
                    <!-- Alert Placeholder for Reset Password Modal -->
                    <div id="reset-pw-alert-placeholder"></div>

                    <p>Password for user <strong id="reset-pw-result-username"></strong> has been reset.</p>
                    <div class="mb-3">
                        <label for="reset-pw-result-new" class="form-label">New Temporary Password:</label>
                        <div class="input-group">
                            <input type="text" class="form-control" id="reset-pw-result-new" readonly>
                            <button class="btn btn-outline-secondary" type="button" id="copy-password-btn" title="Copy to clipboard"><i class="bi bi-clipboard"></i></button>
                        </div>
                    </div>
                    <p class="form-text">Please provide this password to the user. They will be required to change it on their next login.</p>
                </div>
                <div class="modal-footer"><button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button></div>
            </div>
        </div>
    </div>

@endsection