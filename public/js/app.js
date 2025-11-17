document.addEventListener('DOMContentLoaded', () => {
    // --- Configuration and State ---
    const API_BASE_URL = '/api';
    let currentUser = null;
    let config = null;
    let createUserModal, editUserModal, resetPasswordResultModal, createUserResultModal;

    // --- UI Element Cache ---
    const screens = {
        login: document.getElementById('login-page'),
        error: document.getElementById('error-screen'),
        main: document.getElementById('main-app'),
        loading: document.getElementById('loading-spinner')
    };
    const alertPlaceholder = document.getElementById('alert-placeholder');
    const loginError = document.getElementById('login-error');
    // Cache modal alert placeholders
    const createUserAlert = document.getElementById('create-user-alert-placeholder');
    const editUserAlert = document.getElementById('edit-user-alert-placeholder');
    const createResultAlert = document.getElementById('create-result-alert-placeholder');
    const resetPwAlert = document.getElementById('reset-pw-alert-placeholder');


    // --- UI Functions ---
    const showScreen = (screenName) => {
        Object.values(screens).forEach(s => { if (s) s.style.display = 'none'; });
        if (screenName === 'main' && screens.main) {
            screens.main.style.display = 'block';
        } else if (screens[screenName]) {
            screens[screenName].style.display = 'flex';
        }
    };

    const showLoading = (show) => {
        if (screens.loading) {
            screens.loading.style.display = show ? 'flex' : 'none';
        }
    };

    /**
     * Shows an alert message.
     * @param {string} message The message to display.
     * @param {string} type The Bootstrap alert type (e.g., 'danger', 'success').
     * @param {HTMLElement|string} targetElement The element or ID string of the placeholder to append the alert to. Defaults to the main page alert.
     */
    const showAlert = (message, type = 'danger', targetElement = alertPlaceholder) => {
        // Allow passing either the element itself or its ID
        let target = targetElement;
        if (typeof target === 'string') {
            target = document.getElementById(targetElement);
        }

        if (!target) {
            // Fallback to main alert if target is invalid, but log an error
            console.error(`Alert target '${targetElement}' not found. Falling back to main alert.`);
            target = alertPlaceholder;
        }
        
        if (!target) return; // If even fallback fails, give up.

        const wrapper = document.createElement('div');
        wrapper.innerHTML = [
            `<div class="alert alert-${type} alert-dismissible fade show" role="alert">`,
            `   <div>${message}</div>`,
            '   <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>',
            '</div>'
        ].join('');
        
        target.innerHTML = ''; // Clear previous alerts in this target
        target.append(wrapper);
    };

    /**
     * Clears alerts from a specific placeholder.
     * @param {HTMLElement|string} targetElement The element or ID string of the placeholder to clear. Defaults to the main page alert.
     */
    const clearAlert = (targetElement = alertPlaceholder) => {
        let target = targetElement;
        if (typeof target === 'string') {
            target = document.getElementById(targetElement);
        }
        if (target) {
            target.innerHTML = '';
        }
    };

    /**
     * Correctly formats a date string for an <input type="date"> field.
     * Uses getLocalISODate to avoid timezone conversion issues inherent in .toISOString().
     * @param {string} dateString The date string from the server.
     * @returns {string} The date in 'YYYY-MM-DD' format.
     */
    const formatDateForInput = (dateString) => {
        if (!dateString) return '';
        const date = new Date(dateString);
        // Check for invalid date (e.g., from an empty string or bad data)
        if (isNaN(date.getTime())) return '';
        // Use getLocalISODate to avoid timezone shifts
        return getLocalISODate(date);
    };

    /**
     * Converts a local Date object to a 'YYYY-MM-DD' string.
     * This avoids timezone shifts caused by using .toISOString().
     * @param {Date} date The local date object.
     * @returns {string} The date in 'YYYY-MM-DD' format.
     */
    const getLocalISODate = (date) => {
        if (!date) return '';
        const year = date.getFullYear();
        const month = String(date.getMonth() + 1).padStart(2, '0');
        const day = String(date.getDate()).padStart(2, '0');
        return `${year}-${month}-${day}`;
    };

    const apiFetch = (url, options = {}, isPublic = false) => {
        showLoading(true);
        const csrfToken = document.querySelector('meta[name="csrf-token"]');
        const apiToken = localStorage.getItem('api_token');

        const ajaxSettings = {
            url: url,
            type: options.method || 'GET',
            contentType: 'application/json',
            dataType: 'json',
            headers: {
                'Accept': 'application/json',
                ...(csrfToken && {'X-CSRF-TOKEN': csrfToken.getAttribute('content')}),
                ...(!isPublic && apiToken && {'Authorization': 'Bearer ' + apiToken}),
                ...options.headers
            },
            xhrFields: {
                withCredentials: true
            },
            data: options.body ? JSON.stringify(options.body) : undefined,
        };

        return new Promise((resolve, reject) => {
            $.ajax(ajaxSettings)
                .done((data, textStatus, jqXHR) => {
                    if (jqXHR.status === 204 || jqXHR.responseText === "") {
                        resolve(null);
                    } else {
                        resolve(data);
                    }
                })
                .fail((jqXHR, textStatus, errorThrown) => {
                    console.error('API Ajax Error:', textStatus, errorThrown, jqXHR);
                    
                    if (jqXHR.status === 401) {
                        localStorage.removeItem('api_token');
                        
                        if (!document.getElementById('login-form')) {
                            // We assume the login page is at /login
                            window.location.href = '/login'; 
                        }
                        
                        reject(new Error('Unauthorized'));
                        return;
                    }

                    let errorMessage = errorThrown; // Default
                    
                    if (jqXHR.responseJSON) {
                        const json = jqXHR.responseJSON;
                        
                        // Check for Laravel-style validation errors (HTTP 422)
                        if (jqXHR.status === 422 && json.errors) {
                            // We have a validation error object. Let's format it.
                            let errorHtml = json.message ? `<p class="mb-1">${json.message}</p>` : '<p class="mb-1">Validation failed:</p>';
                            errorHtml += '<ul class="mb-0">';
                            for (const field in json.errors) {
                                json.errors[field].forEach(error => {
                                    errorHtml += `<li>${error}</li>`;
                                });
                            }
                            errorHtml += '</ul>';
                            errorMessage = errorHtml; // The showAlert function will render this HTML

                        } else if (json.message) {
                            // Standard JSON error message (e.g., { "message": "..." })
                            errorMessage = json.message;
                        } else if (json.error) {
                            // Alternative JSON error message (e.g., { "error": "..." })
                            errorMessage = json.error;
                        }
                    } else if (jqXHR.responseText) {
                        // Fallback for non-JSON or malformed JSON
                        try {
                            const errorData = JSON.parse(jqXHR.responseText);
                            errorMessage = errorData.message || errorData.error || errorThrown;
                        } catch (e) {
                            errorMessage = jqXHR.statusText || errorThrown || 'An unknown error occurred.';
                        }
                    } else {
                        errorMessage = jqXHR.statusText || errorThrown || 'An unknown error occurred.';
                    }
                    
                    reject(new Error(errorMessage));
                })
                .always(() => {
                    showLoading(false);
                });
        });
    };

    // --- Core Application Logic ---

    // This function is called after a SUCCESSFUL LOGIN on the login page
    const redirectToMainApp = () => {
        // The user has successfully logged in. Redirect them to the main app page.
        // We assume the main app is at the root '/'
        window.location.href = '/';
    };

    const getGroupName = (dn) => {
        // Matches "CN=GroupName," at the start of the string
        const match = dn.match(/^CN=([^,]+),/i);
        return match ? match[1] : dn; // Return CN if found, otherwise return full DN
    };

    const handleLogin = async (e) => {
        e.preventDefault();
        const form = e.target;
        if (loginError) loginError.classList.add('d-none');

        const data = {
            domain: form.querySelector('#login-domain').value,
            username: form.querySelector('#login-username').value,
            password: form.querySelector('#login-password').value,
        };

        try {
            const loginResponse = await apiFetch(`${API_BASE_URL}/auth/login`, { method: 'POST', body: data });

            if (loginResponse && loginResponse.token) {
                localStorage.setItem('api_token', loginResponse.token);
            } else {
                throw new Error("Login successful, but no token was provided by the server.");
            }

            redirectToMainApp();

        } catch (error) {
            if(loginError) {
                localStorage.removeItem('api_token');
                loginError.textContent = error.message || 'Login failed. Please check your credentials.';
                loginError.classList.remove('d-none');
            }
        }
    };

    const handleLogout = async () => {
        try {
            await apiFetch(`${API_BASE_URL}/v1/logout`, { method: 'POST' });
        } catch (error) {
            console.error("Logout failed:", error.message);
        } finally {
            localStorage.removeItem('api_token');
            window.location.href = '/login'; 
        }
    };

    const handleSearch = async () => {
        
        const domain = document.getElementById('domain-select').value;
        const nameFilter = document.getElementById('name-filter').value;       
        const tableBody = document.getElementById('user-table-body');
        
        if (!tableBody) {
             console.error("Critical error: User table body element ('user-table-body') not found.");
             return;
        }

        tableBody.innerHTML = '<tr><td colspan="6" class="text-center">Searching...</td></tr>';

        const params = new URLSearchParams({ domain });
        if(nameFilter) params.append('nameFilter', nameFilter);
        const requestUrl = `${API_BASE_URL}/v1/users?${params.toString()}`;
console.log(requestUrl);
        try {
            
            const users = await apiFetch(requestUrl);
            if (!users || users.length === 0) {
                tableBody.innerHTML = '<tr><td colspan="6" class="text-center">No users found.</td></tr>';
                return;
            }

            const tableHtml = users.map(user => `
                <tr>
                    <td>${user.displayName || ''}</td>
                    <td>${user.samAccountName || ''}</td>
                    <td>${user.domain || ''}</td>
                    <td>${user.isEnabled ? '<span class="badge text-success-emphasis bg-success-subtle border border-success-subtle rounded-pill">Enabled</span>' : '<span class="badge text-danger-emphasis bg-danger-subtle border border-danger-subtle rounded-pill">Disabled</span>'}</td>
                    <td>${user.dateOfExpiration}</td>
                    <td>${user.hasAdminAccount ? '✔️' : ''}</td>                    
                    <td class="action-btn-group">
                        <button class="btn btn-sm btn-secondary" title="Edit User" data-action="edit" data-sam="${user.badgeNumber}"><i class="bi bi-pencil-square"></i></button>
                        <button class="btn btn-sm btn-warning" title="Reset Password" data-action="reset-pw" data-sam="${user.badgeNumber}"><i class="bi bi-person-lock"></i></button>
                        <button class="btn btn-sm btn-info" title="Unlock Account" data-action="unlock" data-sam="${user.badgeNumber}"><i class="bi bi-unlock"></i></button>                    
                        ${user.isEnabled
                            ? `<button class="btn btn-sm btn-danger" title="Disable Account" data-action="disable" data-sam="${user.badgeNumber}"><i class="bi bi-ban"></i></button>`
                            : `<button class="btn btn-sm btn-success" title="Enable Account" data-action="enable" data-sam="${user.badgeNumber}"><i class="bi bi-check2-square"></i></button>`
                        }
                        ${user.isEnabled && currentUser.isHighPrivilege && user.hasAdminAccount
                            ? ` | 
                                <button class="btn btn-sm btn-dark" title="Reset Admin Password" data-action="reset-pw-admin" data-sam="${user.badgeNumber}-a"><i class="bi bi-person-lock"></i></button>
                                <button class="btn btn-sm btn-dark" title="Unlock Admin Account" data-action="unlock-admin" data-sam="${user.badgeNumber}-a"><i class="bi bi-unlock"></i></button>
                                `
                            : ''
                        } 
                        ${user.isEnabled && currentUser.isHighPrivilege && user.hasAdminAccount && user.isEnabledAdmin
                            ? `<button class="btn btn-sm btn-dark" title="Disable Admin Account" data-action="disable-admin" data-sam="${user.badgeNumber}-a"><i class="bi bi-ban"></i></button>`
                            : ``
                        }
                        ${user.isEnabled && currentUser.isHighPrivilege && user.hasAdminAccount && !user.isEnabledAdmin
                            ? `<button class="btn btn-sm btn-dark" title="Enable Admin Account" data-action="enable-admin" data-sam="${user.badgeNumber}-a"><i class="bi bi-check2-square"></i></button>`
                            : ``
                        }                        
                         
                    </td>
                </tr>
            `).join('');

            tableBody.innerHTML = tableHtml;
        } catch (error) {
            tableBody.innerHTML = `<tr><td colspan="6" class="text-center text-danger">Failed to load users: ${error.message}</td></tr>`;
        }
    };

    const handleShowCreateModal = () => {
        clearAlert(createUserAlert); // Clear old errors
        const form = document.getElementById('create-user-form');
        if (form) form.reset();

        // --- NEW: Set Date Defaults and Constraints ---
        const today = new Date();
        const todayISO = getLocalISODate(today); 

        // --- DOB Logic (Create Modal) ---
        const dobDefault = new Date();
        dobDefault.setFullYear(dobDefault.getFullYear() - 18);
        const dobDefaultISO = getLocalISODate(dobDefault); 
        
        const createDob = document.getElementById('create-dob');
        if (createDob) {
            createDob.value = dobDefaultISO;
            createDob.max = todayISO;
        }

        // --- DOE Logic (Create Modal) ---
        const doeDefault = new Date();
        doeDefault.setMonth(doeDefault.getMonth() + 3);
        const doeDefaultISO = getLocalISODate(doeDefault); 

        const createDoe = document.getElementById('create-doe');
        if (createDoe) {
            createDoe.value = doeDefaultISO;
            createDoe.min = todayISO;
        }
        // --- END: Set Date Defaults ---
        
        const standardGroupsContainer = document.getElementById('create-standard-groups-container');
        const standardGroupsList = document.getElementById('create-standard-groups-list');
        const adminContainer = document.getElementById('create-admin-container');
        const adminCheckbox = document.getElementById('create-admin-account');
        const privilegeGroupsContainer = document.getElementById('create-privilege-groups-container');

        if (standardGroupsContainer) standardGroupsContainer.style.display = 'none';
        if (adminContainer) adminContainer.style.display = 'none';
        if (privilegeGroupsContainer) privilegeGroupsContainer.style.display = 'none';


        if (config.optionalGroupsForStandard && config.optionalGroupsForStandard.length > 0 && standardGroupsContainer && standardGroupsList) {
            standardGroupsContainer.style.display = 'block';
            standardGroupsList.innerHTML = config.optionalGroupsForStandard.map(g => {
                    const gn = getGroupName(g); // Extract Group Name
                    return `<div class="form-check">
                                <input class="form-check-input" type="checkbox" value="${g}" id="create-standard-group-${gn}">
                                <label class="form-check-label" for="create-standard-group-${gn}">${gn}</label>
                            </div>`;
                }).join('');
        }

        if (currentUser.isHighPrivilege && adminContainer) {
            adminContainer.style.display = 'block';
            
            const privilegeGroupsList = document.getElementById('create-privilege-groups-list');
            
            if (config.optionalGroupsForHighPrivilege && config.optionalGroupsForHighPrivilege.length > 0 && privilegeGroupsList) {
                privilegeGroupsList.innerHTML = config.optionalGroupsForHighPrivilege.map(g => {
                    const gn = getGroupName(g); // Extract Group Name
                    return `<div class="form-check">
                                <input class="form-check-input" type="checkbox" value="${g}" id="create-privilege-group-${gn}">
                                <label class="form-check-label" for="create-privilege-group-${gn}">${gn}</label>
                            </div>`;
                }).join('');
            }
            if (privilegeGroupsContainer && adminCheckbox) {
                 privilegeGroupsContainer.style.display = adminCheckbox.checked ? 'block' : 'none';
            }
        }
    };

    const handleShowEditModal = async (sam, domain) => {
        
        clearAlert(editUserAlert); 
        const form = document.getElementById('edit-user-form');
        if (form) form.reset();

        // --- NEW: Set Date Constraints ---
        const today = new Date();
        const todayISO = getLocalISODate(today); 

        const editDob = document.getElementById('edit-dob');
        if (editDob) {
            editDob.max = todayISO; // Can't set DOB to a future date
        }

        const editDoe = document.getElementById('edit-doe');
        if (editDoe) {
            editDoe.min = todayISO; // Can't set expiration to a past date
        }
        // --- END: Set Date Constraints ---
        
        try {
            
            const params = new URLSearchParams({ domain });
            const safeSam = sam.split('@')[0];
            
            if (form) {
                form.dataset.originalSam = safeSam;
            }
            console.log(`${API_BASE_URL}/v1/users/${safeSam}?${params.toString()}`);

            const userDetails = await apiFetch(`${API_BASE_URL}/v1/users/${safeSam}?${params.toString()}`);
            
            
            if (!userDetails) {
                showAlert(`Could not find details for user '${sam}'.`, 'warning');
                return;
            }

            const editUsernameDisplay = document.getElementById('edit-username-display');
            const editSamAccountName = document.getElementById('edit-samaccountname');
            const editAdminSamAccountName = document.getElementById('edit-admin-samaccountname');
            const editFirstName = document.getElementById('edit-firstname');
            const editLastName = document.getElementById('edit-lastname');
            const editMobile = document.getElementById('edit-mobile');
            const editDomain = document.getElementById('edit-domain');
            
            
            if (editUsernameDisplay) editUsernameDisplay.value = userDetails.badgeNumber;
            if (editAdminSamAccountName) editAdminSamAccountName.value = userDetails.badgeNumber + '-a';
            if (editSamAccountName) editSamAccountName.value = userDetails.badgeNumber;
            if (editFirstName) editFirstName.value = userDetails.firstName;
            if (editLastName) editLastName.value = userDetails.lastName;
            if (editDob) editDob.value = formatDateForInput(userDetails.dateOfBirth);
            if (editMobile) editMobile.value = userDetails.mobileNumber;
            if (editDomain) editDomain.value = domain;
            if (editDoe) editDoe.value = formatDateForInput(userDetails.dateOfExpiration);
            
            const standardGroupsContainer = document.getElementById('edit-standard-groups-container');
            const standardGroupsList = document.getElementById('edit-standard-groups-list');
            
            // --- Containers for Admin/Privilege ---
            const adminContainer = document.getElementById('edit-admin-container');
            const adminCheckbox = document.getElementById('edit-admin-account');
            const privilegeGroupsContainer = document.getElementById('edit-privilege-groups-container');
            const privilegeGroupsList = document.getElementById('edit-privilege-groups-list');

            // --- Reset Containers ---
            if (standardGroupsContainer) standardGroupsContainer.style.display = 'none';
            if (adminContainer) adminContainer.style.display = 'none';
            if (privilegeGroupsContainer) privilegeGroupsContainer.style.display = 'none';
            if (adminCheckbox) adminCheckbox.disabled = true; // Default to disabled

            const userGroupsLower = userDetails.memberOf.map(dn => getGroupName(dn).toLowerCase());

            // --- Standard Groups ---
            if (config.optionalGroupsForStandard && config.optionalGroupsForStandard.length > 0 && standardGroupsContainer && standardGroupsList) {
                standardGroupsContainer.style.display = 'block';
                standardGroupsList.innerHTML = config.optionalGroupsForStandard.map(g => {
                    const gn = getGroupName(g); // Extracts "RDP-EMS" from "CN=RDP-EMS,..."
                    const isChecked = userGroupsLower.includes(gn.toLowerCase()) ? 'checked' : '';
                    return `<div class="form-check">
                                <input class="form-check-input" type="checkbox" value="${g}" id="edit-standard-group-${gn}" ${isChecked}>
                                <label class="form-check-label" for="edit-standard-group-${gn}">${gn}</label>
                            </div>`;
                }).join('');
            }

            // --- Admin and Privilege Groups ---
            if (adminContainer && adminCheckbox) {
                adminCheckbox.checked = userDetails.hasAdminAccount;
    
                if (currentUser.isHighPrivilege || userDetails.hasAdminAccount) {
                    adminContainer.style.display = 'block';
                } else {
                    adminContainer.style.display = 'none';
                }
    
                adminCheckbox.disabled = !currentUser.isHighPrivilege;
            }
            
            const privilegeGroupsLower = userDetails.memberOfAdmin.map(dn => getGroupName(dn).toLowerCase());
            // Populate and manage the *privilege group* checkboxes
            if (privilegeGroupsList) {
                // First, clear the list
                privilegeGroupsList.innerHTML = '';
                
                // We only populate/show the privilege groups if the user has high privilege
                if (currentUser.isHighPrivilege && config.optionalGroupsForHighPrivilege && config.optionalGroupsForHighPrivilege.length > 0) {
                    
                    privilegeGroupsList.innerHTML = config.optionalGroupsForHighPrivilege.map(g => {
                        const gn = getGroupName(g);
                        const isChecked = privilegeGroupsLower.includes(gn.toLowerCase()) ? 'checked' : '';
                        return `<div class="form-check">
                                    <input class="form-check-input" type="checkbox" value="${g}" id="edit-privilege-group-${gn}" ${isChecked}>
                                    <label class="form-check-label" for="edit-privilege-group-${gn}">${gn}</label>
                                </div>`;
                    }).join('');
                }
            }
            
            // Show the privilege group *container* only if the admin checkbox is checked.
            if (privilegeGroupsContainer) {
                privilegeGroupsContainer.style.display = adminCheckbox.checked ? 'block' : 'none';
            }

            if (editUserModal) editUserModal.show();
        } catch (error) {
            showAlert(`Failed to load user details: ${error.message}`);
        }
    };

    const handleUserAction = async (action, sam, domain, confirmMessage) => {
        // Using a custom modal for confirm is better, but this will work
        if (confirmMessage && !confirm(confirmMessage)) return;
        try {
            const body = { domain, samAccountName: sam };

            let result;
            
            switch(action) {
                case 'reset-pw': case 'reset-pw-admin':
                    result = await apiFetch(`${API_BASE_URL}/v1/passwords/reset-standard`, { method: 'POST', body });
                    clearAlert(resetPwAlert);
                    const resetPwResultUsername = document.getElementById('reset-pw-result-username');
                    const resetPwResultNew = document.getElementById('reset-pw-result-new');
                    if (resetPwResultUsername) resetPwResultUsername.textContent = sam;
                    if (resetPwResultNew) resetPwResultNew.value = result.newPassword;
                    if (resetPasswordResultModal) resetPasswordResultModal.show();
                    break;
                case 'unlock': case 'unlock-admin':
                    await apiFetch(`${API_BASE_URL}/v1/users/${sam}/unlock`, { method: 'POST', body });
                    showAlert(`Successfully unlocked account: ${sam}`, 'success');
                    break;
                case 'disable': case 'disable-admin':
                    await apiFetch(`${API_BASE_URL}/v1/users/${sam}/disable`, { method: 'POST', body });
                    showAlert(`Successfully disabled account: ${sam}`, 'success');
                    break;
                case 'enable': case 'enable-admin':
                    await apiFetch(`${API_BASE_URL}/v1/users/${sam}/enable`, { method: 'POST', body });
                    showAlert(`Successfully enabled account: ${sam}`, 'success');
                    break;
            }
            if (action !== 'reset-pw' && action !== 'reset-pw-admin') {
                await handleSearch();
            }
        } catch(error) {
             showAlert(`Failed to ${action.replace('-', ' ')} account: ${error.message}`);
        }
    };

    const handleCreateSubmit = async (e) => {
        e.preventDefault();
        const form = e.target;
        clearAlert(createUserAlert); // Clear previous errors
        if (!form.checkValidity()) {
            form.classList.add('was-validated');
            return;
        }

        const standardGroups = Array.from(form.querySelectorAll('#create-standard-groups-list input:checked')).map(cb => cb.value);
        const privilegeGroups = Array.from(form.querySelectorAll('#create-privilege-groups-list input:checked')).map(cb => cb.value);
        
        const data = {
            domain: form.querySelector('#create-domain').value,
            first_name: form.querySelector('#create-firstname').value,
            last_name: form.querySelector('#create-lastname').value,
            badge_number: form.querySelector('#create-samaccountname').value,
            date_of_birth: form.querySelector('#create-dob').value,
            date_of_expiry: form.querySelector('#create-doe').value,
            mobile_number: form.querySelector('#create-mobile').value,
            has_admin: form.querySelector('#create-admin-account').checked,
            groups_standard_user: standardGroups,
            groups_privilege_user: privilegeGroups,

        };
 
        try {
            const result = await apiFetch(`${API_BASE_URL}/v1/users`, { method: 'POST', body: data });
            if (createUserModal) createUserModal.hide();

            // --- Aligned with new JSON response ---
            let resultHtml = `<h6>User account for <strong>${result.standard_information.username}</strong> created successfully.</h6>`;
            resultHtml += `<p class="mt-3"><strong>Temporary Password:</strong></p><div class="input-group"><input type="text" class="form-control" value="${result.standard_information.password}" readonly><button class="btn btn-outline-secondary copy-btn" data-copy-text="${result.standard_information.password}">Copy</button></div>`;

            // Check if the admin_information object exists
            if (result.admin_information && result.admin_information.username) {
                resultHtml += `<h6 class="mt-4">Admin account <strong>${result.admin_information.username}</strong> also created.</h6>`;
                resultHtml += `<p class="mt-3"><strong>Admin Temporary Password:</strong></p><div class="input-group"><input type="text" class="form-control" value="${result.admin_information.password}" readonly><button class="btn btn-outline-secondary copy-btn" data-copy-text="${result.admin_information.password}">Copy</button></div>`;
            }
            // --- End of alignment ---

            const createUserResultBody = document.getElementById('create-user-result-body');
            if (createUserResultBody) {
                clearAlert(createResultAlert);
                Array.from(createUserResultBody.children).forEach(child => {
                    if (child.id !== 'create-result-alert-placeholder') {
                        child.remove();
                    }
                });
                const contentWrapper = document.createElement('div');
                contentWrapper.innerHTML = resultHtml;
                createUserResultBody.appendChild(contentWrapper);
            }
            
            if (createUserResultModal) createUserResultModal.show();
            await handleSearch();
        } catch (error) {
            showAlert(`Failed to create user: ${error.message}`, 'danger', createUserAlert);
        }
    };

    const handleEditSubmit = async (e) => {
        e.preventDefault();
        const form = e.target;
        clearAlert(editUserAlert);
         if (!form.checkValidity()) {
            form.classList.add('was-validated');
            return;
        }

        const originalSam = form.dataset.originalSam;
        const standardGroups = Array.from(form.querySelectorAll('#edit-standard-groups-list input:checked')).map(cb => cb.value);
        const privilegeGroups = Array.from(form.querySelectorAll('#edit-privilege-groups-list input:checked')).map(cb => cb.value);

        const data = {
            domain: form.querySelector('#edit-domain').value,
            badge_number: form.querySelector('#edit-samaccountname').value,
            first_name: form.querySelector('#edit-firstname').value,
            last_name: form.querySelector('#edit-lastname').value,            
            date_of_birth: form.querySelector('#edit-dob').value,
            date_of_expiry: form.querySelector('#edit-doe').value,
            mobile_number: form.querySelector('#edit-mobile').value,
            has_admin: form.querySelector('#edit-admin-account').checked,
            groups_standard_user: standardGroups,
            groups_privilege_user: privilegeGroups,            
        };

        if (!originalSam) {
            showAlert('Critical error: Original SAM account name not found. Cannot update.', 'danger', editUserAlert);
            return;
        }

        try {
            await apiFetch(`${API_BASE_URL}/v1/users/${originalSam}`, { method: 'PUT', body: data });
            if (editUserModal) editUserModal.hide();
            showAlert(`Successfully updated user: ${data.badge_number}`, 'success');
            await handleSearch();
        } catch (error) {
            // Show error inside the edit modal
            showAlert(`Failed to update user: ${error.message}`, 'danger', editUserAlert);
        }
    };

    // --- Event Listeners and Initialization ---
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
    }

    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', handleLogout);
    }

    const tryAgainBtn = document.getElementById('try-again-btn');
    if (tryAgainBtn) {
        tryAgainBtn.addEventListener('click', () => window.location.href = '/login');
    }

    const userSearchForm = document.getElementById('user-search-form');
    if (userSearchForm) {
        userSearchForm.addEventListener('submit', (e) => {
            e.preventDefault(); // Prevent page reload
            handleSearch();
        });
    }

    const showCreateModalBtn = document.getElementById('create-user-show-modal-btn');
    if (showCreateModalBtn) {
        showCreateModalBtn.addEventListener('click', () => {
            if(createUserModal) {
                handleShowCreateModal();
                createUserModal.show();
            }
        });
    }

    const createUserForm = document.getElementById('create-user-form');
    if (createUserForm) {
        createUserForm.addEventListener('submit', handleCreateSubmit);
    }

    const editUserForm = document.getElementById('edit-user-form');
    if (editUserForm) {
        editUserForm.addEventListener('submit', handleEditSubmit);
    }

    const createAdminAccountCheckbox = document.getElementById('create-admin-account');
    if (createAdminAccountCheckbox) {
        createAdminAccountCheckbox.addEventListener('change', (e) => {
            const privilegeGroupsContainer = document.getElementById('create-privilege-groups-container');
            if (privilegeGroupsContainer) {
                privilegeGroupsContainer.style.display = e.target.checked ? 'block' : 'none';
            }
        });
    }

    const editAdminAccountCheckbox = document.getElementById('edit-admin-account');
    if (editAdminAccountCheckbox) {
        editAdminAccountCheckbox.addEventListener('change', (e) => {
            const privilegeGroupsContainer = document.getElementById('edit-privilege-groups-container');
            if (privilegeGroupsContainer) {
                privilegeGroupsContainer.style.display = e.target.checked ? 'block' : 'none';
            }
        });
    }

    const userTableBody = document.getElementById('user-table-body');
    if (userTableBody) {
        userTableBody.addEventListener('click', (e) => {
            const button = e.target.closest('button[data-action]');
            if (!button) return;
            const sam = button.dataset.sam;
            const domain = document.getElementById('domain-select').value;
            const action = button.dataset.action;
            const messages = {
                'reset-pw': `Are you sure you want to reset the password for ${sam}?`,
                'reset-pw-admin': `Are you sure you want to reset the password for ${sam}?`,
                'unlock': `Are you sure you want to unlock the account for ${sam}?`,
                'unlock-admin': `Are you sure you want to unlock the account for ${sam}?`,
                'disable': `Are you sure you want to DISABLE the account for ${sam}?`,
                'disable-admin': `Are you sure you want to DISABLE the account for ${sam}?`,
                'enable': `Are you sure you want to ENABLE the account for ${sam}?`,
                'enable-admin': `Are you sure you want to ENABLE the account for ${sam}?`,
            };
            if(action === 'edit') {
                handleShowEditModal(sam, domain);
            } else {
                handleUserAction(action, sam, domain, messages[action]);
            }
        });
    }

    document.body.addEventListener('click', (e) => {
        const button = e.target.closest('.copy-btn, #copy-password-btn');
        if(!button) return;

        const textToCopy = button.dataset.copyText || document.getElementById('reset-pw-result-new').value;
        
        // Determine which modal is active to show the alert in the right place
        let targetAlert = null;
        if (button.closest('#reset-password-result-modal')) {
            targetAlert = resetPwAlert;
        } else if (button.closest('#create-user-result-modal')) {
            targetAlert = createResultAlert;
        } else {
            targetAlert = alertPlaceholder; // Fallback to main
        }

        navigator.clipboard.writeText(textToCopy).then(() => {
             showAlert('Password copied to clipboard!', 'success', targetAlert);
        }).catch(err => {
             console.error('Failed to copy text: ', err);
             showAlert('Failed to copy password. Please copy manually.', 'danger', targetAlert);
        });
    });

    try {
        const createUserModalEl = document.getElementById('create-user-modal');
        if (createUserModalEl) createUserModal = new bootstrap.Modal(createUserModalEl);

        const editUserModalEl = document.getElementById('edit-user-modal');
        if (editUserModalEl) editUserModal = new bootstrap.Modal(editUserModalEl);

        const resetPasswordResultModalEl = document.getElementById('reset-password-result-modal');
        if (resetPasswordResultModalEl) resetPasswordResultModal = new bootstrap.Modal(resetPasswordResultModalEl);

        const createUserResultModalEl = document.getElementById('create-user-result-modal');
        if (createUserResultModalEl) createUserResultModal = new bootstrap.Modal(createUserResultModalEl);
    } catch(e) {
        console.error("Error initializing Bootstrap modals:", e);
    }

    // --- NEW: Page-aware Initialization ---
    if (document.getElementById('login-form')) {
        // --- We are on the LOGIN page ---
        showScreen('login'); // Show login form
        
        // Fetch config *just* for the domain dropdown
        apiFetch(`${API_BASE_URL}/v1/config`, {}, true)
            .then(conf => {
                config = conf; // Save config
                const loginDomainSelect = document.getElementById('login-domain');
                if (loginDomainSelect) {
                    loginDomainSelect.innerHTML = '';
                    config.domains.forEach(d => {
                        loginDomainSelect.add(new Option(d, d));
                    });
                }
            })
            .catch(error => {
                console.error('Failed to load config for login page:', error);
                if (loginError) {
                    loginError.textContent = 'Failed to load domain configuration. Please refresh.';
                    loginError.classList.remove('d-none');
                }
            });
    
    } else if (document.getElementById('main-app')) {
        // --- We are on the MAIN APP page ---
        // We must be authenticated. Let's fetch user data and config.
        // If this fails, apiFetch's 401 handling will redirect to login.
        Promise.all([
            apiFetch(`${API_BASE_URL}/auth/me`),
            // This call is on the main app, so it should be authenticated (isPublic = false by default)
            apiFetch(`${API_BASE_URL}/v1/config`)
        ])
        .then(([user, conf]) => {
            // --- Authentication successful ---
            currentUser = user;
            config = conf;

            // --- Populate user and config data ---
            const userNameElement = document.getElementById('userName');
            if (userNameElement) {
                userNameElement.textContent = currentUser.displayName || 'User';
            }
            
            // Populate roles for logic
            currentUser.isHighPrivilege = !!currentUser.hasHighPrivilegeAccess;
            currentUser.isGeneralAccess = !!currentUser.hasGeneralAccess;


            const domainSelect = document.getElementById('domain-select');
            const createDomainSelect = document.getElementById('create-domain');
            if (domainSelect && createDomainSelect && config && config.domains) {
                domainSelect.innerHTML = createDomainSelect.innerHTML = '';
                config.domains.forEach(d => {
                    domainSelect.add(new Option(d, d));
                    createDomainSelect.add(new Option(d, d));
                });
            }

            const createUserButton = document.getElementById('create-user-show-modal-btn');
            if (createUserButton) {
                createUserButton.disabled = false;
            }
            
            // --- Show the app and load initial data ---
            showScreen('main');
            handleSearch(); // Run initial search
            
        })
        .catch(error => {
            // This catch is for any non-401 error
            // The 401 error is handled in apiFetch and redirects to login
            console.error("Failed to initialize main application:", error);
            showScreen('error'); 
        });
    }
});