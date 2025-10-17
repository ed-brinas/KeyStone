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

    // --- UI Functions ---
    const showScreen = (screenName) => {
        Object.values(screens).forEach(s => s.style.display = 'none');
        if (screenName === 'main') {
            screens.main.style.display = 'block';
        } else if (screens[screenName]) {
            screens[screenName].style.display = 'flex';
        }
    };

    const showLoading = (show) => { screens.loading.style.display = show ? 'flex' : 'none'; };

    const showAlert = (message, type = 'danger') => {
        const wrapper = document.createElement('div');
        wrapper.innerHTML = [
            `<div class="alert alert-${type} alert-dismissible fade show" role="alert">`,
            `   <div>${message}</div>`,
            '   <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>',
            '</div>'
        ].join('');
        alertPlaceholder.innerHTML = '';
        alertPlaceholder.append(wrapper);
    };

    const formatDateForInput = (dateString) => !dateString ? '' : new Date(dateString).toISOString().split('T')[0];

    // --- API Communication ---
    const apiFetch = async (url, options = {}) => {
        showLoading(true);
        try {
            const csrfToken = document.querySelector('meta[name="csrf-token"]');
            const mergedOptions = {
                ...options,
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    ...(csrfToken && {'X-CSRF-TOKEN': csrfToken.getAttribute('content')}),
                    ...options.headers
                },
                credentials: 'omit' // Use omit for APIs with tokens, 'include' for cookie-based auth
            };

            if (mergedOptions.body && typeof mergedOptions.body !== 'string') {
                mergedOptions.body = JSON.stringify(mergedOptions.body);
            }

            const response = await fetch(url, mergedOptions);

            if (response.status === 401) {
                // Handle unauthorized access by redirecting to login
                showScreen('login');
                throw new Error('Unauthorized');
            }

            if (!response.ok) {
                const errorData = await response.json();
                throw errorData;
            }
            if (response.status === 204 || response.headers.get("content-length") === "0") return null;
            return response.json();
        } catch (error) {
            console.error('API Fetch Error:', error);
            const errorMessage = error.message || 'An unknown error occurred.';
            throw new Error(errorMessage);
        } finally {
            showLoading(false);
        }
    };

    // --- Core Application Logic ---
    const setupMainApplication = async () => {
        document.getElementById('user-name').textContent = currentUser.name;
        const domainSelect = document.getElementById('domain-select');
        const createDomainSelect = document.getElementById('create-domain');
        domainSelect.innerHTML = createDomainSelect.innerHTML = '';
        config.domains.forEach(d => {
            domainSelect.add(new Option(d, d));
            createDomainSelect.add(new Option(d, d));
        });

        document.getElementById('create-user-show-modal-btn').disabled = false;

        showScreen('main');
        await handleSearch();
    };

    const tryAutoLogin = async () => {
        try {
             // First, get config, as it's not protected
            config = await apiFetch(`${API_BASE_URL}/config`);
            const loginDomainSelect = document.getElementById('login-domain');
            config.domains.forEach(d => {
                loginDomainSelect.add(new Option(d, d));
            });

            // Then, check if user is already authenticated
            currentUser = await apiFetch(`${API_BASE_URL}/auth/me`);
            await setupMainApplication();
        } catch (error) {
            // This is expected if not logged in
            showScreen('login');
        }
    };

    const handleLogin = async (e) => {
        e.preventDefault();
        const form = e.target;
        loginError.classList.add('d-none');

        const data = {
            domain: form.querySelector('#login-domain').value,
            username: form.querySelector('#login-username').value,
            password: form.querySelector('#login-password').value,
        };

        try {
            await apiFetch(`${API_BASE_URL}/auth/login`, { method: 'POST', body: data });
            // After successful login, try to get user data again
            currentUser = await apiFetch(`${API_BASE_URL}/auth/me`);
            await setupMainApplication();
        } catch (error) {
            loginError.textContent = error.message || 'Login failed. Please check your credentials.';
            loginError.classList.remove('d-none');
        }
    };

    const handleLogout = async () => {
        try {
            await apiFetch(`${API_BASE_URL}/auth/logout`, { method: 'POST' });
        } catch (error) {
            console.error("Logout failed:", error.message);
        } finally {
            currentUser = null;
            config = null;
            showScreen('login');
        }
    };


    const handleSearch = async () => {
        const domain = document.getElementById('domain-select').value;
        const nameFilter = document.getElementById('name-filter').value;
        const statusFilter = document.getElementById('status-filter').value;
        const adminFilter = document.getElementById('admin-filter').value;
        const tableBody = document.getElementById('user-table-body');
        tableBody.innerHTML = '<tr><td colspan="6" class="text-center">Searching...</td></tr>';

        const params = new URLSearchParams({ domain });
        if(nameFilter) params.append('nameFilter', nameFilter);
        if(statusFilter !== "") params.append('statusFilter', statusFilter);
        if(adminFilter !== "") params.append('hasAdminAccount', adminFilter);
        const requestUrl = `${API_BASE_URL}/users?${params.toString()}`;

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
                    <td>${domain}</td>
                    <td>${user.isEnabled ? '<span class="badge text-success-emphasis bg-success-subtle border border-success-subtle rounded-pill">Enabled</span>' : '<span class="badge text-danger-emphasis bg-danger-subtle border border-danger-subtle rounded-pill">Disabled</span>'}</td>
                    <td>${user.hasAdminAccount ? '✔️' : ''}</td>
                    <td class="action-btn-group">
                        <button class="btn btn-sm btn-secondary" title="Edit User" data-action="edit" data-sam="${user.samAccountName}"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-pencil-square" viewBox="0 0 16 16"><path d="M15.502 1.94a.5.5 0 0 1 0 .706L14.459 3.69l-2-2L13.502.646a.5.5 0 0 1 .707 0l1.293 1.293zm-1.75 2.456-2-2L4.939 9.21a.5.5 0 0 0-.121.196l-.805 2.414a.25.25 0 0 0 .316.316l2.414-.805a.5.5 0 0 0 .196-.12l6.813-6.814z"/><path fill-rule="evenodd" d="M1 13.5A1.5 1.5 0 0 0 2.5 15h11a1.5 1.5 0 0 0 1.5-1.5v-6a.5.5 0 0 0-1 0v6a.5.5 0 0 1-.5.5h-11a.5.5 0 0 1-.5-.5v-11a.5.5 0 0 1 .5-.5H9a.5.5 0 0 0 0-1H2.5A1.5 1.5 0 0 0 1 2.5z"/></svg></button>
                        <button class="btn btn-sm btn-warning" title="Reset Password" data-action="reset-pw" data-sam="${user.samAccountName}"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-key-fill" viewBox="0 0 16 16"><path d="M3.5 11.5a3.5 3.5 0 1 1 3.163-5H14L15.5 8 14 9.5l-1-1-1 1-1-1-1 1-1-1-1 1H6.663a3.5 3.5 0 0 1-3.163 2zM2.5 9a1 1 0 1 0 0-2 1 1 0 0 0 0 2"/></svg></button>
                        ${currentUser.isHighPrivilege && user.hasAdminAccount
                            ? `<button class="btn btn-sm btn-dark" title="Reset Admin Password" data-action="reset-admin-pw" data-sam="${user.samAccountName}"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-shield-lock-fill" viewBox="0 0 16 16"><path fill-rule="evenodd" d="M8 0c-.69 0-1.843.265-2.928.56-1.11.3-2.229.655-2.887.87a1.54 1.54 0 0 0-1.044 1.262c-.596 4.477.787 7.795 2.465 9.99a11.8 11.8 0 0 0 2.517 2.453c.386.273.744.482 1.048.625.28.132.581.19.829.19s.548-.058.829-.19c.304-.143.662-.352 1.048-.625a11.8 11.8 0 0 0 2.517-2.453c1.678-2.195 3.061-5.513 2.465-9.99a1.54 1.54 0 0 0-1.044-1.262c-.658-.215-1.777-.57-2.887-.87C9.843.265 8.69 0 8 0m2.028 6.472a.5.5 0 0 1 .472.472v3.056a.5.5 0 0 1-1 0V7.004a.5.5 0 0 1 .528-.472M8 4.5a1.5 1.5 0 1 1 0 3 1.5 1.5 0 0 1 0-3"/></svg></button>`
                            : ''
                        }
                        <button class="btn btn-sm btn-info" title="Unlock Account" data-action="unlock" data-sam="${user.samAccountName}"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-unlock-fill" viewBox="0 0 16 16"><path d="M11 1a2 2 0 0 0-2 2v4a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V9a2 2 0 0 1 2-2h5V3a3 3 0 0 1 6 0v4a.5.5 0 0 1-1 0V3a2 2 0 0 0-2-2"/></svg></button>
                        ${user.isEnabled
                            ? `<button class="btn btn-sm btn-danger" title="Disable Account" data-action="disable" data-sam="${user.samAccountName}"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-person-fill-slash" viewBox="0 0 16 16"><path d="M13.879 10.414a2.502 2.502 0 0 0-3.465-3.465l3.465 3.465Zm.707.707-3.465-3.465a2.502 2.502 0 0 0-3.465 3.465l3.465-3.465Zm-4.56-4.56a2.5 2.5 0 1 0 0-3.535 2.5 2.5 0 0 0 0 3.535M11 5a3 3 0 1 1-6 0 3 3 0 0 1 6 0m-2.293 7.293a1 1 0 0 1-1.414 0l-1.414-1.414a1 1 0 1 1 1.414-1.414l1.414 1.414a1 1 0 0 1 0 1.414m2.828-2.828a1 1 0 0 1-1.414-1.414l-1.414 1.414a1 1 0 1 1-1.414-1.414l1.414-1.414a1 1 0 1 1 1.414 1.414l-1.414 1.414a1 1 0 0 1 1.414 1.414l-3.535-3.535a1 1 0 0 1 1.414-1.414zM4.5 0A3.5 3.5 0 0 1 8 3.5v1.096a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V3.5A3.5 3.5 0 0 1 4.5 0"/></svg></button>`
                            : `<button class="btn btn-sm btn-success" title="Enable Account" data-action="enable" data-sam="${user.samAccountName}"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-person-fill-check" viewBox="0 0 16 16"><path d="M12.5 16a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7m-.646-4.854.646.647.646-.647a.5.5 0 0 1 .708.708l-1 1a.5.5 0 0 1-.708 0l-.5-.5a.5.5 0 0 1 .708-.708z"/><path d="M5.5 2.5a2.5 2.5 0 1 1-5 0 2.5 2.5 0 0 1 5 0m.5 8.5a.5.5 0 0 1 .5.5v1.5a.5.5 0 0 1-1 0V12a.5.5 0 0 1 .5-.5m-2-1a.5.5 0 0 1 .5-.5h4a.5.5 0 0 1 0 1h-4a.5.5 0 0 1-.5-.5m1.5 2a.5.5 0 0 1 .5-.5h2a.5.5 0 0 1 0 1h-2a.5.5 0 0 1-.5-.5"/></svg></button>`
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
        document.getElementById('create-user-form').reset();

        const standardGroupsContainer = document.getElementById('create-standard-groups-container');
        const standardGroupsList = document.getElementById('create-standard-groups-list');
        const adminContainer = document.getElementById('create-admin-container');
        const adminCheckbox = document.getElementById('create-admin-account');
        const privilegeGroupsContainer = document.getElementById('create-privilege-groups-container');

        standardGroupsContainer.style.display = 'none';
        adminContainer.style.display = 'none';
        privilegeGroupsContainer.style.display = 'none';

        if (config.optionalGroupsForStandard && config.optionalGroupsForStandard.length > 0) {
            standardGroupsContainer.style.display = 'block';
            standardGroupsList.innerHTML = config.optionalGroupsForStandard.map(g => `<div class="form-check"><input class="form-check-input" type="checkbox" value="${g}" id="create-standard-group-${g}"><label class="form-check-label" for="create-standard-group-${g}">${g}</label></div>`).join('');
        }

        if (currentUser.isHighPrivilege) {
            adminContainer.style.display = 'block';
            if (config.optionalGroupsForHighPrivilege && config.optionalGroupsForHighPrivilege.length > 0) {
                 privilegeGroupsList.innerHTML = config.optionalGroupsForHighPrivilege.map(g => `<div class="form-check"><input class="form-check-input" type="checkbox" value="${g}" id="create-privilege-group-${g}"><label class="form-check-label" for="create-privilege-group-${g}">${g}</label></div>`).join('');
            }
             privilegeGroupsContainer.style.display = adminCheckbox.checked ? 'block' : 'none';
        }
    };

    const handleShowEditModal = async (sam, domain) => {
        document.getElementById('edit-user-form').reset();
        try {
            const params = new URLSearchParams({ domain, samAccountName: sam });
            const userDetails = await apiFetch(`${API_BASE_URL}/users/show?${params.toString()}`);
            if (!userDetails) {
                showAlert(`Could not find details for user '${sam}'.`, 'warning');
                return;
            }

            document.getElementById('edit-username-display').value = userDetails.samAccountName;
            document.getElementById('edit-samaccountname').value = userDetails.samAccountName;
            document.getElementById('edit-firstname').value = userDetails.firstName || '';
            document.getElementById('edit-lastname').value = userDetails.lastName || '';
            document.getElementById('edit-dob').value = formatDateForInput(userDetails.dateOfBirth);
            document.getElementById('edit-mobile').value = userDetails.mobileNumber || '';
            document.getElementById('edit-domain').value = domain;

            const standardGroupsContainer = document.getElementById('edit-standard-groups-container');
            const standardGroupsList = document.getElementById('edit-standard-groups-list');
            const adminContainer = document.getElementById('edit-admin-container');
            const adminCheckbox = document.getElementById('edit-admin-account');
            const privilegeGroupsContainer = document.getElementById('edit-privilege-groups-container');

            standardGroupsContainer.style.display = 'none';
            adminContainer.style.display = 'none';
            privilegeGroupsContainer.style.display = 'none';

            if (config.optionalGroupsForStandard && config.optionalGroupsForStandard.length > 0) {
                standardGroupsContainer.style.display = 'block';
                standardGroupsList.innerHTML = config.optionalGroupsForStandard.map(g => `<div class="form-check"><input class="form-check-input" type="checkbox" value="${g}" id="edit-standard-group-${g}" ${userDetails.memberOf.includes(g) ? 'checked' : ''}><label class="form-check-label" for="edit-standard-group-${g}">${g}</label></div>`).join('');
            }

            if (currentUser.isHighPrivilege) {
                adminContainer.style.display = 'block';
                adminCheckbox.checked = userDetails.hasAdminAccount;

                const privilegeGroupsList = document.getElementById('edit-privilege-groups-list');
                if (config.optionalGroupsForHighPrivilege && config.optionalGroupsForHighPrivilege.length > 0) {
                     privilegeGroupsList.innerHTML = config.optionalGroupsForHighPrivilege.map(g => `<div class="form-check"><input class="form-check-input" type="checkbox" value="${g}" id="edit-privilege-group-${g}" ${userDetails.memberOf.includes(g) ? 'checked' : ''}><label class="form-check-label" for="edit-privilege-group-${g}">${g}</label></div>`).join('');
                }

                privilegeGroupsContainer.style.display = adminCheckbox.checked ? 'block' : 'none';
            }

            editUserModal.show();
        } catch (error) {
            showAlert(`Failed to load user details: ${error.message}`);
        }
    };

    const handleUserAction = async (action, sam, domain, confirmMessage) => {
        if (confirmMessage && !confirm(confirmMessage)) return;
        try {
            const body = { domain, samAccountName: sam };
            let result;
            let actionPath = action.replace(/([A-Z])/g, '-$1').toLowerCase();

            switch(action) {
                case 'reset-pw':
                    result = await apiFetch(`${API_BASE_URL}/users/reset-password`, { method: 'POST', body });
                    document.getElementById('reset-pw-result-username').textContent = sam;
                    document.getElementById('reset-pw-result-new').value = result.newPassword;
                    resetPasswordResultModal.show();
                    break;
                case 'reset-admin-pw':
                    result = await apiFetch(`${API_BASE_URL}/users/reset-admin-password`, { method: 'POST', body });
                    document.getElementById('reset-pw-result-username').textContent = `${sam}-a`;
                    document.getElementById('reset-pw-result-new').value = result.newPassword;
                    resetPasswordResultModal.show();
                    break;
                case 'unlock':
                    await apiFetch(`${API_BASE_URL}/users/unlock-account`, { method: 'POST', body });
                    showAlert(`Successfully unlocked account: ${sam}`, 'success');
                    break;
                case 'disable':
                    await apiFetch(`${API_BASE_URL}/users/disable-account`, { method: 'POST', body });
                    showAlert(`Successfully disabled account: ${sam}`, 'success');
                    break;
                case 'enable':
                    await apiFetch(`${API_BASE_URL}/users/enable-account`, { method: 'POST', body });
                    showAlert(`Successfully enabled account: ${sam}`, 'success');
                    break;
            }
            if (action !== 'reset-pw' && action !== 'reset-admin-pw') {
                await handleSearch();
            }
        } catch(error) {
             showAlert(`Failed to ${action.replace('-', ' ')} account: ${error.message}`);
        }
    };

    const handleCreateSubmit = async (e) => {
        e.preventDefault();
        const form = e.target;
        if (!form.checkValidity()) {
            form.classList.add('was-validated');
            return;
        }

        const standardGroups = Array.from(form.querySelectorAll('#create-standard-groups-list input:checked')).map(cb => cb.value);
        const privilegeGroups = Array.from(form.querySelectorAll('#create-privilege-groups-list input:checked')).map(cb => cb.value);

        const data = {
            domain: form.querySelector('#create-domain').value,
            firstName: form.querySelector('#create-firstname').value,
            lastName: form.querySelector('#create-lastname').value,
            samAccountName: form.querySelector('#create-samaccountname').value,
            dateOfBirth: form.querySelector('#create-dob').value,
            mobileNumber: form.querySelector('#create-mobile').value,
            optionalGroups: [...new Set([...standardGroups, ...privilegeGroups])],
            privilegeGroups: privilegeGroups,
            createAdminAccount: form.querySelector('#create-admin-account').checked,
        };
        try {
            const result = await apiFetch(`${API_BASE_URL}/users`, { method: 'POST', body: data });
            createUserModal.hide();

            let resultHtml = `<h6>User account for <strong>${result.samAccountName}</strong> created successfully.</h6>`;
            resultHtml += `<p class="mt-3"><strong>Temporary Password:</strong></p><div class="input-group"><input type="text" class="form-control" value="${result.initialPassword}" readonly><button class="btn btn-outline-secondary copy-btn" data-copy-text="${result.initialPassword}">Copy</button></div>`;

            if (result.adminAccountName) {
                resultHtml += `<h6 class="mt-4">Admin account <strong>${result.adminAccountName}</strong> also created.</h6>`;
                resultHtml += `<p class="mt-3"><strong>Admin Temporary Password:</strong></p><div class="input-group"><input type="text" class="form-control" value="${result.adminInitialPassword}" readonly><button class="btn btn-outline-secondary copy-btn" data-copy-text="${result.adminInitialPassword}">Copy</button></div>`;
            }

            document.getElementById('create-user-result-body').innerHTML = resultHtml;
            createUserResultModal.show();
            await handleSearch();
        } catch (error) {
            showAlert(`Failed to create user: ${error.message}`);
        }
    };

    const handleEditSubmit = async (e) => {
        e.preventDefault();
        const form = e.target;
         if (!form.checkValidity()) {
            form.classList.add('was-validated');
            return;
        }

        const standardGroups = Array.from(form.querySelectorAll('#edit-standard-groups-list input:checked')).map(cb => cb.value);
        const privilegeGroups = Array.from(form.querySelectorAll('#edit-privilege-groups-list input:checked')).map(cb => cb.value);

        const data = {
            domain: form.querySelector('#edit-domain').value,
            samAccountName: form.querySelector('#edit-samaccountname').value,
            dateOfBirth: form.querySelector('#edit-dob').value,
            mobileNumber: form.querySelector('#edit-mobile').value,
            optionalGroups: [...new Set([...standardGroups, ...privilegeGroups])],
            hasAdminAccount: form.querySelector('#edit-admin-account').checked,
        };
        try {
            await apiFetch(`${API_BASE_URL}/users`, { method: 'PUT', body: data });
            editUserModal.hide();
            showAlert(`Successfully updated user: ${data.samAccountName}`, 'success');
            await handleSearch();
        } catch (error) {
            showAlert(`Failed to update user: ${error.message}`);
        }
    };

    // --- Event Listeners and Initialization ---
    document.getElementById('login-form').addEventListener('submit', handleLogin);
    document.getElementById('logout-btn').addEventListener('click', handleLogout);
    document.getElementById('try-again-btn').addEventListener('click', () => showScreen('login'));
    document.getElementById('search-users-btn').addEventListener('click', handleSearch);
    document.getElementById('create-user-show-modal-btn').addEventListener('click', () => { handleShowCreateModal(); createUserModal.show(); });
    document.getElementById('create-user-form').addEventListener('submit', handleCreateSubmit);
    document.getElementById('edit-user-form').addEventListener('submit', handleEditSubmit);

    document.getElementById('create-admin-account').addEventListener('change', (e) => {
        document.getElementById('create-privilege-groups-container').style.display = e.target.checked ? 'block' : 'none';
    });
    document.getElementById('edit-admin-account').addEventListener('change', (e) => {
        document.getElementById('edit-privilege-groups-container').style.display = e.target.checked ? 'block' : 'none';
    });

    document.getElementById('user-table-body').addEventListener('click', (e) => {
        const button = e.target.closest('button[data-action]');
        if (!button) return;
        const sam = button.dataset.sam;
        const domain = document.getElementById('domain-select').value;
        const action = button.dataset.action;
        const messages = {
            'reset-pw': `Are you sure you want to reset the password for ${sam}?`,
            'reset-admin-pw': `Are you sure you want to reset the ADMIN password for the account associated with ${sam}?`,
            'unlock': `Are you sure you want to unlock the account for ${sam}?`,
            'disable': `Are you sure you want to DISABLE the account for ${sam}?`,
            'enable': `Are you sure you want to ENABLE the account for ${sam}?`,
        };
        if(action === 'edit') {
            handleShowEditModal(sam, domain);
        } else {
            handleUserAction(action, sam, domain, messages[action]);
        }
    });

    document.body.addEventListener('click', (e) => {
        const button = e.target.closest('.copy-btn, #copy-password-btn');
        if(!button) return;

        const textToCopy = button.dataset.copyText || document.getElementById('reset-pw-result-new').value;
        navigator.clipboard.writeText(textToCopy).then(() => {
             showAlert('Password copied to clipboard!', 'success');
        });
    });

    createUserModal = new bootstrap.Modal(document.getElementById('create-user-modal'));
    editUserModal = new bootstrap.Modal(document.getElementById('edit-user-modal'));
    resetPasswordResultModal = new bootstrap.Modal(document.getElementById('reset-password-result-modal'));
    createUserResultModal = new bootstrap.Modal(document.getElementById('create-user-result-modal'));

    tryAutoLogin();
});
