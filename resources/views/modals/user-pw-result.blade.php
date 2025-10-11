<div class="modal fade" id="resetPasswordSuccessModal" tabindex="-1" aria-labelledby="resetPasswordSuccessModalLabel" aria-hidden="true">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header bg-success text-white">
                <h5 class="modal-title" id="resetPasswordSuccessModalLabel">Password Reset Successful!</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body">
                <p class="mb-1">New temporary password for user: **<span id="success-username-placeholder"></span>**</p>
                <div class="input-group">
                    <input type="text" class="form-control" id="new-password-display" readonly value="">
                    <button class="btn btn-outline-secondary" type="button" id="copyPasswordBtn" title="Copy to clipboard">
                        <i class="bi bi-clipboard"></i> Copy
                    </button>
                </div>
                <div id="copy-feedback" class="form-text text-success" style="display: none;">Copied!</div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-primary" data-bs-dismiss="modal">Close</button>
            </div>
        </div>
    </div>
</div>
