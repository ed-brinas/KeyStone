# README.md

## Overview
**ADWebManager** is a web-based application for managing Active Directory (AD) accounts and providing self-service password reset for end-users.  

It is designed to run entirely on-premises (no Internet dependencies) and is deployed on Microsoft IIS.

---

## Features

### Admin Portal
- **AD User Management**
  - Create, update, enable/disable, unlock, and reset user accounts.
  - Auto-create privileged `-a` admin accounts (with separate password policy).
  - Mobile number support in account creation and updates.
  - Force regular users to change password at next logon (excludes `-a` accounts).
- **Password Reset**
  - Reset and unlock user accounts with one click.
  - Reset privileged `-a` admin accounts separately.
- **User Lifecycle**
  - Auto-disable on expiration date.
  - Orphaned admin detector (flags `-a` accounts without base user).
- **Governance & Reporting**
  - Full audit log of all actions.
  - Export user creation summaries to PDF (excludes admin credentials).
- **Health Dashboard**
  - Domain Controller connectivity.
  - LDAP latency monitoring.
  - Service account lockout warnings.
  - Disk space checks for logs.
- **Group Drift Guard**
  - Nightly reconciliation of group memberships against templates.

### Self-Service Portal
- Minimal, focused interface for end-users.
- Reset password by verifying:
  - Domain
  - Username
  - Date of birth
  - Last 4 digits of registered mobile number
- Generates recovery codes on first password set.
- Blocks privileged `-a` accounts from using self-service.
- Enforces password policy, checks against breach/banned lists.

### Security
- **Session Security**
  - CSRF tokens for all `POST/PUT/PATCH/DELETE` requests.
  - SameSite cookies.
  - Device fingerprinting for sessions.
  - Idle/session timeouts.
- **Splash Gate**
  - Warning splash screen before accessing `/admin` or `/selfservice`.
  - User must explicitly accept terms before proceeding.
- **Offline Operation**
  - All dependencies are vendored locally (Bootstrap, jQuery, icons, etc.).

### Integrations
- SIEM integration via syslog/CEF stream of audit events.

---

## Password Policy
- **Regular Users:** 12 characters, letters + numbers + special characters.
- **Admin Accounts (`-a`):** 8 characters, letters + numbers only.

---

## Deployment

### Prerequisites
- Windows Server with IIS installed.
- .NET 6 (or later) runtime.
- Service account with delegated permissions to manage AD users.

### Steps
1. **Build and publish**
   ```bash
   dotnet publish -c Release -o ./publish
   ```
2. **Configure IIS**
   - Create a new site in IIS pointing to `./publish`.
   - Set app pool to use **No Managed Code** and run under the service account identity.
3. **Bind HTTPS**
   - Use a valid certificate.
   - Enforce TLS 1.2 or higher.
4. **Configure `appsettings.json`**
   - Domains, LDAP paths, and OUs.
   - Admin OU for privileged accounts.
   - Logging, SIEM, and breach-password list location.
5. **Verify**
   - Access `https://yourserver/admin` → Splash Gate → Admin Portal.
   - Access `https://yourserver/selfservice` → Splash Gate → Self-Service Reset.

---

## Roadmap
Planned enhancements:
- Multi-approval workflows for admin account creation (department manager → enterprise admin).
- Offline CAPTCHA for self-service rate-limit lockouts.
- Enhanced health dashboard (charts, thresholds, alerting).

---

⚠️ **Security Notice:**  
This application interacts directly with AD. Deploy only in secured environments, restrict IIS access, and monitor all actions through audit logs and SIEM.
