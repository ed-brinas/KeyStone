/**
 * Consolidated Application Logic (app.js)
 * * This file contains two main modules:
 * 1. Initial Load Handler: For showing session-based modals and auto-generating display names.
 * 2. User Password Reset: A module for handling the reset password flow (confirmation, API call, success).
 */

document.addEventListener('DOMContentLoaded', () => {
    // --- 1. Initial Load Handler (Modal & Display Name) ---

    // Automatically open a modal if its ID is present in the session (Laravel/Blade integration)
    const sessionModalId = '@json(session("open_modal"))';
    if (sessionModalId) {
        const modalElement = document.querySelector(sessionModalId);
        // Assumes Bootstrap is loaded globally
        if (modalElement && typeof bootstrap !== 'undefined' && bootstrap.Modal) {
            new bootstrap.Modal(modalElement).show();
        }
    }

    // Auto-generate display name from first and last names
    const firstNameInput = document.getElementById('first_name');
    const lastNameInput = document.getElementById('last_name');
    const displayNameInput = document.getElementById('display_name');

    /** Converts a string to Sentence Case. */
    const toSentenceCase = str => str ? str.charAt(0).toUpperCase() + str.slice(1).toLowerCase() : '';

    /** Updates the display name field based on current first/last name inputs. */
    const updateDisplayName = () => {
        if (firstNameInput && lastNameInput && displayNameInput) {
            const firstName = firstNameInput.value.trim();
            const lastName = lastNameInput.value.trim();
            // Concatenate, convert to Sentence Case, and trim any excess whitespace
            displayNameInput.value = `${toSentenceCase(firstName)} ${toSentenceCase(lastName)}`.trim();
        }
    };

    if (firstNameInput && lastNameInput) {
        firstNameInput.addEventListener('input', updateDisplayName);
        lastNameInput.addEventListener('input', updateDisplayName);
    }


    // --- 2. User Password Reset Module ---

    const confirmModalEl = document.getElementById('resetPasswordConfirmModal');
    const successModalEl = document.getElementById('resetPasswordSuccessModal');
    const confirmResetBtn = document.getElementById('confirmResetPasswordBtn');
    const copyPasswordBtn = document.getElementById('copyPasswordBtn');
    const loadingDiv = document.getElementById('reset-password-loading');

    // Global state to store the user info captured from the trigger button
    let userContext = {
        id: null,
        username: null
    };

    /**
     * Toggles the loading state for the confirmation button/loading indicator.
     * @param {boolean} isLoading - True to show loading, false to hide.
     */
    const toggleLoadingState = (isLoading) => {
        if (loadingDiv) loadingDiv.style.display = isLoading ? 'block' : 'none';
        if (confirmResetBtn) confirmResetBtn.disabled = isLoading;
    };


    // Event 1: Capture user context when the confirmation modal is about to show
    if (confirmModalEl) {
        confirmModalEl.addEventListener('show.bs.modal', (event) => {
            const button = event.relatedTarget;
            userContext.id = button.getAttribute('data-user-id');
            userContext.username = button.getAttribute('data-username');

            const usernamePlaceholder = confirmModalEl.querySelector('#confirm-username-placeholder');
            if (usernamePlaceholder) {
                usernamePlaceholder.textContent = userContext.username;
            }
        });
    }

    // Event 2: Handle the actual password reset API call
    if (confirmResetBtn) {
        confirmResetBtn.addEventListener('click', async () => {
            toggleLoadingState(true);

            try {
                // Use the globally available userContext.id
                const response = await fetch(`/users/${userContext.id}/reset-password`, {
                    method: 'POST',
                    headers: {
                        // Assuming this is running in a Laravel/Blade environment
                        'X-CSRF-TOKEN': '{{ csrf_token() }}',
                        'Content-Type': 'application/json'
                    }
                });

                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }

                const data = await response.json();

                // 1. Hide confirmation modal
                const confirmModalInstance = bootstrap.Modal.getInstance(confirmModalEl);
                if (confirmModalInstance) confirmModalInstance.hide();

                // 2. Populate and show success modal
                if (successModalEl) {
                    successModalEl.querySelector('#success-username-placeholder').textContent = userContext.username;
                    successModalEl.querySelector('#new-password-display').value = data.new_password;
                    new bootstrap.Modal(successModalEl).show();
                }

            } catch (error) {
                console.error('Password Reset Failed:', error);
                // Use a custom modal/message box instead of alert()
                // For this simplification, we'll log, but in a real app, use a proper UI notification
                console.warn('Failed to reset password. Please check the console for details.');
            } finally {
                toggleLoadingState(false);
            }
        });
    }

    // Event 3: Handle Copy to Clipboard Functionality (using modern Clipboard API if available)
    if (copyPasswordBtn) {
        copyPasswordBtn.addEventListener('click', async () => {
            const passwordField = document.getElementById('new-password-display');
            const feedback = document.getElementById('copy-feedback');

            if (!passwordField) return;

            try {
                // Modern API (preferred but might be restricted in iframes/certain environments)
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    await navigator.clipboard.writeText(passwordField.value);
                } else {
                    // Fallback to legacy document.execCommand('copy')
                    passwordField.select();
                    document.execCommand('copy');
                }

                if (feedback) {
                    feedback.style.display = 'block';
                    setTimeout(() => {
                        feedback.style.display = 'none';
                    }, 2000);
                }
            } catch (err) {
                console.error('Failed to copy password: ', err);
            }
        });
    }

});
