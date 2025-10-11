<!-- Confirmation Modal -->
<div class="modal fade" id="confirmResetModal" tabindex="-1" role="dialog">
  <div class="modal-dialog modal-dialog-centered">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title">Confirm Password Reset</h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
      </div>
      <div class="modal-body">
        Are you sure you want to reset this user's password?
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
        <button type="button" class="btn btn-primary" id="confirmResetBtn">Yes, Reset</button>
      </div>
    </div>
  </div>
</div>

<!-- Result Modal -->
<div class="modal fade" id="resultModal" tabindex="-1" role="dialog">
  <div class="modal-dialog modal-dialog-centered">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title">Password Reset Successful</h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
      </div>
      <div class="modal-body">
        <p><strong>Username:</strong> <span id="resultUsername"></span></p>
        <p>
          <strong>New Password:</strong>
          <span id="resultPassword" class="text-monospace"></span>
          <button class="btn btn-light btn-sm" id="copyPasswordBtn" title="Copy to Clipboard">
            📋
          </button>
        </p>
      </div>
    </div>
  </div>
</div>
