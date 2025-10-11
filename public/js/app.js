// MODIFIED START - 2025-10-10 19:09 - Import Bootstrap to enable JS components like modals.
import 'bootstrap';
// MODIFIED END - 2025-10-10 19:09
import './bootstrap';

// ADDED: Logic for handling the password reset confirmation and AJAX request.
document.addEventListener('DOMContentLoaded', function () {
    // Check if Bootstrap is available (should be, due to the import)
    if (typeof bootstrap === 'undefined') {
        console.error("Bootstrap JS not loaded. Modals and other components will not function.");
        return;
    }

    const confirmModal = document.getElementById('resetPasswordConfirmModal');
    const successModal = document.getElementById('resetPasswordSuccessModal');
    const confirmButton = document.getElementById('confirmResetPasswordBtn');
    const copyButton = document.getElementById('copyPasswordBtn');

    let currentUserId = null;
    let currentUsername = null;

    // Get the current domain from the hidden input placed in index.blade.php
    const domainInput = document.getElementById('current-domain');
    let currentDomain = domainInput ? domainInput.value : null;

    // --- 1. Handle Confirmation Modal Display ---
    if (confirmModal) {
        // Event fires immediately when the modal is about to be shown
        confirmModal.addEventListener('show.bs.modal', function (event) {
            const button = event.relatedTarget; // Button that triggered the modal
            currentUserId = button.getAttribute('data-user-id');
            currentUsername = button.getAttribute('data-username');

            const usernamePlaceholder = confirmModal.querySelector('#confirm-username-placeholder');
            if (usernamePlaceholder) {
                usernamePlaceholder.textContent = currentUsername;
            }

            // Ensure the loading spinner is hidden and buttons are shown when the modal opens
            const loadingSpinner = document.getElementById('reset-password-loading');
            const footerButtons = confirmModal.querySelector('.modal-footer');
            if (loadingSpinner && footerButtons) {
                loadingSpinner.style.display = 'none';
                footerButtons.style.display = 'flex';
            }
        });
    }

    // --- 2. Handle the "Reset Password" confirmation button click (AJAX) ---
    if (confirmButton) {
        confirmButton.addEventListener('click', function () {
            if (!currentUserId || !currentDomain) {
                // Should not happen if data-user-id is set on the table button and domain input is present
                console.error("User ID or Domain missing for password reset.");
                return;
            }

            // Show loading spinner and hide footer buttons to prevent double-click
            const loadingSpinner = document.getElementById('reset-password-loading');
            const footerButtons = confirmModal.querySelector('.modal-footer');
            if (loadingSpinner && footerButtons) {
                loadingSpinner.style.display = 'block';
                footerButtons.style.display = 'none';
            }

            // Perform the AJAX request to the Laravel endpoint
            fetch(`/users/${currentUserId}/reset-password`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': document.querySelector('meta[name="csrf-token"]').getAttribute('content'),
                },
                // Pass the domain context in the request body, which the backend (UserController) expects
                body: JSON.stringify({
                    domain: currentDomain
                })
            })
            .then(response => {
                if (!response.ok) {
                    // Check for a JSON error response before throwing
                    return response.json().then(err => { throw new Error(err.error || 'Server error occurred.'); });
                }
                return response.json();
            })
            .then(data => {
                if (data.new_password) {
                    // Success: Hide confirm modal, show result modal
                    const modalInstance = bootstrap.Modal.getInstance(confirmModal);
                    if (modalInstance) modalInstance.hide();

                    const usernameSuccessPlaceholder = successModal.querySelector('#success-username-placeholder');
                    const passwordDisplay = successModal.querySelector('#new-password-display');
                    const copyFeedback = successModal.querySelector('#copy-feedback');

                    if (usernameSuccessPlaceholder && passwordDisplay) {
                        usernameSuccessPlaceholder.textContent = currentUsername;
                        passwordDisplay.value = data.new_password;
                    }

                    // Reset copy feedback display
                    if (copyFeedback) copyFeedback.style.display = 'none';

                    const successModalInstance = new bootstrap.Modal(successModal);
                    successModalInstance.show();

                } else {
                    // This block should ideally not be reached if the backend returns the expected structure
                    alert('Password reset failed: Unknown response format.');
                }
            })
            .catch(error => {
                console.error('Error during password reset:', error.message);
                // Use a custom modal or alert to inform the user about the error
                alert('Password reset failed. Details: ' + error.message);
            })
            .finally(() => {
                // Always reset UI elements and temporary variables
                if (loadingSpinner && footerButtons) {
                    loadingSpinner.style.display = 'none';
                    footerButtons.style.display = 'flex'; // Restore button visibility
                }
                currentUserId = null;
                currentUsername = null;
            });
        });
    }

    // --- 3. Handle copy to clipboard logic for the result modal ---
    if (copyButton) {
        copyButton.addEventListener('click', function() {
            const passwordDisplay = document.getElementById('new-password-display');
            const feedback = document.getElementById('copy-feedback');

            // Check if execCommand is available (clipboard API might be restricted in iframes/certain contexts)
            if (passwordDisplay && document.execCommand) {
                passwordDisplay.select();
                document.execCommand('copy');

                // Show 'Copied!' feedback
                if (feedback) {
                    feedback.style.display = 'block';
                    setTimeout(() => {
                        feedback.style.display = 'none';
                    }, 2000);
                }
            } else {
                alert('Copying to clipboard failed or is not supported in this context.');
            }
        });
    }
});
