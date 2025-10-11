<div class="modal fade" id="resetPasswordConfirmModal" tabindex="-1" aria-labelledby="resetPasswordConfirmModalLabel" aria-hidden="true">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="resetPasswordConfirmModalLabel">Confirm Password Reset</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body">
                <p>Are you sure you want to reset the password for user: **<span id="confirm-username-placeholder"></span>**?</p>
                <p class="text-danger">This action will generate a new random password and unlock the account.</p>
                <div id="reset-password-loading" class="text-center" style="display: none;">
                    <div class="spinner-border text-primary" role="status">
                        <span class="visually-hidden">Loading...</span>
                    </div>
                    <p class="mt-2">Resetting password...</p>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                <button type="button" class="btn btn-danger" id="confirmResetPasswordBtn">Reset Password</button>
            </div>
        </div>
    </div>
</div>
