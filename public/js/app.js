// MODIFIED START - 2025-10-10 19:09 - Import Bootstrap to enable JS components like modals.
import 'bootstrap';
// MODIFIED END - 2025-10-10 19:09
import './bootstrap';

/**
 * Attaches event listeners to the user creation form fields
 * to handle real-time UI logic.
 */
function initCreateUserFormLogic() {
    const firstNameInput = document.getElementById('first_name');
    const lastNameInput = document.getElementById('last_name');
    const displayNameInput = document.getElementById('display_name');
    const mobileNumberInput = document.getElementById('mobile_number');

    if (!firstNameInput || !lastNameInput || !displayNameInput) {
        console.warn('One or more user creation form elements not found.');
        return;
    }

    /**
     * Updates the Display Name field based on First and Last Name input.
     */
    const updateDisplayName = () => {
        const firstName = firstNameInput.value.trim();
        const lastName = lastNameInput.value.trim();
        displayNameInput.value = `${firstName} ${lastName}`.trim();
    };

    firstNameInput.addEventListener('input', updateDisplayName);
    lastNameInput.addEventListener('input', updateDisplayName);

    // Initial update in case the form was reloaded with old values
    updateDisplayName();
}

// Since the form is in a modal, we only initialize the logic when the modal is shown.
document.addEventListener('DOMContentLoaded', () => {
    const userCreateModal = document.getElementById('userCreateModal');
    if (userCreateModal) {
        // Use Bootstrap's native event to run the logic when the modal opens
        userCreateModal.addEventListener('shown.bs.modal', initCreateUserFormLogic);
    } else {
        // Fallback for non-modal usage (though unlikely here)
        initCreateUserFormLogic();
    }
});



/**
    * Password Reset Logic
 */
document.addEventListener("DOMContentLoaded", () => {
    // Modal & button references
    const confirmModalEl = document.getElementById("resetPasswordConfirmModal");
    const successModalEl = document.getElementById("resetPasswordSuccessModal");
    const confirmResetBtn = document.getElementById("confirmResetPasswordBtn");
    const copyPasswordBtn = document.getElementById("copyPasswordBtn");
    const loadingDiv = document.getElementById("reset-password-loading");

    let confirmModalInstance = null;
    let successModalInstance = null;

    if (typeof bootstrap !== "undefined" && bootstrap.Modal) {
        if (confirmModalEl)
            confirmModalInstance = new bootstrap.Modal(confirmModalEl, {
                backdrop: "static",
                keyboard: false,
            });
        if (successModalEl)
            successModalInstance = new bootstrap.Modal(successModalEl);
    }

    const userContext = { id: null, username: null, domain: null, dn: null };

    // 🔄 Toggle loading spinner
    const toggleLoading = (isLoading) => {
        if (loadingDiv) loadingDiv.style.display = isLoading ? "block" : "none";
        if (confirmResetBtn) {
            confirmResetBtn.disabled = isLoading;
            confirmResetBtn.textContent = isLoading ? "Processing..." : "Reset Password";
        }
    };

    // When confirm modal opens, capture user info
    if (confirmModalEl) {
        confirmModalEl.addEventListener("show.bs.modal", (event) => {
            const trigger = event.relatedTarget;
            userContext.id = trigger?.getAttribute("data-user-id") || null;
            userContext.username = trigger?.getAttribute("data-username") || "Unknown";
            userContext.domain = trigger?.getAttribute("data-domain") || null;
            userContext.dn = trigger?.getAttribute("data-dn") || null;

            const placeholder = confirmModalEl.querySelector("#confirm-username-placeholder");
            if (placeholder) placeholder.textContent = userContext.username;
            toggleLoading(false);
        });
    }

    // 🔒 Fetch or refresh CSRF token
    async function getCsrfToken() {
        try {
            let token =
                document.querySelector('meta[name="csrf-token"]')?.getAttribute("content") || "";
            if (!token) {
                const cookieMatch = document.cookie.match(/XSRF-TOKEN=([^;]+)/);
                token = cookieMatch ? decodeURIComponent(cookieMatch[1]) : "";
            }
            if (!token) {
                console.warn("[CSRF] Missing token. Refreshing via /sanctum/csrf-cookie...");
                await fetch("/sanctum/csrf-cookie", { credentials: "same-origin" });
                const retryMatch = document.cookie.match(/XSRF-TOKEN=([^;]+)/);
                token = retryMatch ? decodeURIComponent(retryMatch[1]) : "";
            }
            return token;
        } catch (err) {
            console.error("[CSRF] Failed to fetch token:", err);
            return "";
        }
    }

    // 🧩 Handle password reset request
    async function performPasswordReset() {
        toggleLoading(true);
        try {
            const csrfToken = await getCsrfToken();
            if (!csrfToken) throw new Error("CSRF token unavailable. Please refresh and try again.");

            // Validate that we have the domain context
            if (!userContext.domain) {
                 throw new Error("Domain context is missing for the selected user.");
            }

            const apiUrl = `/users/${userContext.id}/reset-password`;
            console.log(`[RESET] Requesting password reset for user ID ${userContext.id} in domain ${userContext.domain}...`);

            // Construct the payload with the domain context
            const payload = {
                domain: userContext.domain,
                dn: userContext.dn
            };

            const response = await fetch(apiUrl, {
                method: "POST",
                headers: {
                    "X-CSRF-TOKEN": csrfToken,
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    // Removed 'X-Domain' header as the controller expects it in the body
                },
                credentials: "same-origin",
                // PASS THE DOMAIN CONTEXT IN THE REQUEST BODY
                body: JSON.stringify(payload)
            });

            // Handle session expiration (419)
            if (response.status === 419) {
                console.warn("[RESET] Session expired. Refreshing CSRF cookie and retrying...");
                await fetch("/sanctum/csrf-cookie", { credentials: "same-origin" });
                return performPasswordReset(); // retry once
            }

            // Generic HTTP error
            if (!response.ok) {
                // MODIFICATION START: Read the response body ONCE as text
                const responseBody = await response.text();

                let errorMessage = `Server returned ${response.status}: ${responseBody}`;

                // Try to parse the text body as JSON to get a structured error message
                try {
                    const errorJson = JSON.parse(responseBody);
                    // Update error message if a specific 'error' field is present
                    errorMessage = `Server returned ${response.status}: ${errorJson.error || 'Unknown error'}`;
                } catch (e) {
                    // If JSON parsing fails, the errorMessage remains the status code and raw text.
                    console.warn("[RESET] Failed to parse error response as JSON:", e);
                }

                throw new Error(errorMessage);
                // MODIFICATION END
            }

            const data = await response.json();
            console.log("[RESET] Success:", data);

            if (confirmModalInstance) confirmModalInstance.hide();

            // Show success modal or fallback alert
            if (successModalInstance) {
                const successUsername = successModalEl.querySelector("#success-username-placeholder");
                const passwordField = successModalEl.querySelector("#new-password-display");
                if (successUsername) successUsername.textContent = userContext.username;
                if (passwordField)
                    passwordField.value = data.new_password || data.password || "(unknown)";
                const feedback = document.getElementById("copy-feedback");
                if (feedback) feedback.style.display = "none";
                successModalInstance.show();
            } else {
                alert(`Password reset successful!\nNew password: ${data.new_password}`);
            }
        } catch (err) {
            console.error("[RESET] Failed:", err);
            alert(`Password reset failed: ${err.message}`);
        } finally {
            toggleLoading(false);
        }
    }

    // ✅ Click handler for reset button
    if (confirmResetBtn) {
        confirmResetBtn.addEventListener("click", () => {
            if (!userContext.id) {
                alert("No user selected. Please choose a user first.");
                return;
            }
            performPasswordReset();
        });
    }

    // 📋 Copy password to clipboard
    if (copyPasswordBtn) {
        copyPasswordBtn.addEventListener("click", async () => {
            const passwordField = document.getElementById("new-password-display");
            const feedback = document.getElementById("copy-feedback");
            if (!passwordField) return;
            try {
                const password = passwordField.value;
                if (!password) throw new Error("No password to copy.");
                if (navigator.clipboard?.writeText) {
                    await navigator.clipboard.writeText(password);
                } else {
                    passwordField.select();
                    document.execCommand("copy");
                }
                if (feedback) {
                    feedback.style.display = "block";
                    setTimeout(() => (feedback.style.display = "none"), 2000);
                }
            } catch (err) {
                console.error("[COPY] Failed to copy password:", err);
            }
        });
    }
});
