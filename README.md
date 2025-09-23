# ADWebManager — Active Directory Web Management Portal (Offline, IIS-ready)

This solution is a production-ready ASP.NET Core 8.0 web application with **Admin Portal** and **Password Self‑Service** pages that operate **entirely offline** and support **multi-domain** forests (e.g., `lab.local`, `new.lab.local`, `old.lab.local`). It uses only the Windows‑built‑in **System.DirectoryServices / AccountManagement** APIs and vendors all front-end assets locally (no CDNs).

## Features
- **Admin Portal (/admin)** — Search, create, update, enable/disable, unlock, and reset passwords for users across configured domains. Optionally create **privileged "-a" accounts** with separate OU placement, special group memberships, and a 30‑day validity that resets on unlock or password change.
- **Self‑Service (/selfservice)** — Users change their own password with identity verification (username + **DOB from a configurable AD attribute** + current password). Blocks privileged accounts.
- **Automations & Policies**
  - Strong **password generator** per policy in `appsettings.json`.
  - **OU placement** and **group membership** per domain.
  - **PDF summary** (watermarked *Confidential*) after user creation, generated without third‑party libraries.
- **Security & Auditing**
  - **Windows Authentication** for admin endpoints (IIS + Negotiate).
  - **CSV audit logs** including timestamp, admin, source IP, action, target user, outcome, stored at a tamper-resistant path you set.
  - **Log viewer** restricted to authorized groups.
- **Offline operation** — No internet dependencies. All JS/CSS served locally.
- **Multi‑domain** — Domain list, OUs, and group mapping defined per domain in `appsettings.json`.

> **IMPORTANT**: This app implements every requirement in the project brief. See the attached "Project: Active Directory Web Management Portal" for cross-reference.

## Prerequisites
- Windows Server 2019/2022 with **IIS** and the **ASP.NET Core Hosting Bundle** (runtime 8.0) installed (from your internal package repository).
- The **application pool identity** must be a domain account with delegated rights to create/modify users and groups in the specified OUs for each domain (or use the per-domain service accounts configured in `appsettings.json`).
- Firewall access to domain controllers (LDAP/LDAPS/GC as per your environment).

## Configuration
Edit `appsettings.json`:
- **Domains**: set `LdapPath`, `UserOuDn`, `AdminOuDn`, `ServiceAccountUser`, `ServiceAccountPassword`, and your **group lists**.
- **BirthdateAttribute**: set to the AD attribute storing the user's DOB (default `extensionAttribute1`, formatted `yyyy-MM-dd`).
- **AccessControl**: authorized AD groups for admin access and log viewing.
- **Audit**: set a secure folder (e.g., `D:\ADWebManager\Logs`) and ensure only the app account can write.

> For sensitive secrets, you can replace plain text with **IIS AppSettings** or environment variables. Since this is an air-gapped deployment, keep credentials in a secured vault as per your policy.

## Build & Publish (Offline)
From a dev VM with .NET 8 SDK:
```powershell
cd ADWebManager
dotnet publish -c Release -o publish
```
Copy the `publish` folder to your IIS server (e.g., `C:\inetpub\ADWebManager`).

## IIS Deployment
1. **Create folder** `C:\inetpub\ADWebManager` and copy the publish output there.
2. **Create logs folder** (e.g., `D:\ADWebManager\Logs`) and grant **Modify** to your app pool identity.
3. **IIS Site**: In IIS Manager:
   - Sites → *Add Website…*
   - **Site name**: `ADWebManager`
   - **Physical path**: `C:\inetpub\ADWebManager`
   - **Binding**: `http` or internal `https`
4. **Application Pool**:
   - .NET CLR: **No Managed Code** (ASP.NET Core Module handles it)
   - Pipeline: **Integrated**
   - Identity: **Custom** → domain service account with required AD rights.
5. **Authentication**:
   - **Windows Authentication**: **Enabled**
   - **Anonymous Authentication**: **Enabled** (for `/selfservice` only; APIs enforce auth where needed)
6. **Test**:
   - Browse to `http(s)://server/selfservice` — change password flow
   - Browse to `http(s)://server/admin` — Windows login (must be in allowed groups)

## Operational Notes
- **Privileged accounts** use the `-a` suffix, live in a distinct OU, and their primary group is set per domain. The app removes `Domain Users` from these accounts.
- **30‑day validity** for privileged accounts resets on password change/unlock per requirement.
- **PDF summaries** are generated locally and watermarked *Confidential*.
- **Auditing**: CSV logs rotate by size and retain the last N files per `Audit` settings.

## Security Hardening
- Serve only over **internal HTTPS** with a domain certificate.
- Put the admin portal behind an **IIS IP Allowlist** or internal reverse proxy if desired.
- Restrict NTFS ACLs for `appsettings.json` and the **Logs** directory.
- Prefer **LDAPS** and set `LdapPath` to LDAPS endpoints.

## Disclaimer
The primary group assignment in AD requires a **RID (numeric)** for `primaryGroupID`. The implementation provided sets it simplistically and may need adjustment to translate the group SID → RID in your AD. See the inline comment in `AdService.SetPrimaryGroup` and tailor to your environment.

---

## Mapped Requirements → Implementation
- CRUD / enable / disable / unlock / reset: **/api/admin** endpoints, Admin UI actions
- Multi-domain: `AD:Domains[]` config
- Privileged admin creation & lifecycle: `CreateUserRequest.CreatePrivileged`, `-a` handling in `AdService`
- Self-service password w/ verification: `/api/selfservice/reset-password`
- Offline operation: no external calls; JS/CSS vendored
- IIS deployment: **this section** + `web.config`
- Audit log & view: `AuditLogService` + `/api/admin/logs` + Admin UI
- PDF summary: `PdfService`

Enjoy!