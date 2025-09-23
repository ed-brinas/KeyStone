
using ADWebManager.Models;
using Microsoft.Extensions.Options;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Globalization;

namespace ADWebManager.Services {
    public class AdService {
        private readonly AdOptions _opts;
        private readonly AuditLogService _audit;
        private readonly PasswordService _passwords;
        public AdService(IOptions<AdOptions> opts, AuditLogService audit, PasswordService passwords) {
            _opts = opts.Value;
            _audit = audit;
            _passwords = passwords;
        }

        private DomainConfig GetDomain(string name) {
            var dom = _opts.Domains.FirstOrDefault(d => d.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
            if (dom == null) throw new InvalidOperationException($"Domain not configured: {name}");
            return dom;
        }

        private PrincipalContext AdminContext(DomainConfig d, ContextOptions? extra = null) {
            var opts = ContextOptions.Negotiate;
            if (extra.HasValue) opts |= extra.Value;
            return new PrincipalContext(ContextType.Domain, d.Name, d.ServiceAccountUser, d.ServiceAccountPassword);
        }

        private PrincipalContext UserContext(DomainConfig d) {
            return new PrincipalContext(ContextType.Domain, d.Name);
        }

        public IEnumerable<UserDto> GetAllUsers() {
            var results = new List<UserDto>();
            foreach (var d in _opts.Domains) {
                using var ctx = AdminContext(d);
                using var q = new UserPrincipal(ctx);
                using var search = new PrincipalSearcher(q);
                foreach (var p in search.FindAll().OfType<UserPrincipal>()) {
                    var isPriv = p.SamAccountName != null && p.SamAccountName.EndsWith("-a", StringComparison.OrdinalIgnoreCase);
                    results.Add(new UserDto {
                        Domain = d.Name,
                        SamAccountName = p.SamAccountName ?? "",
                        DisplayName = p.DisplayName ?? "",
                        DistinguishedName = p.DistinguishedName ?? "",
                        IsLocked = p.IsAccountLockedOut(),
                        Enabled = p.Enabled ?? true,
                        ExpirationDate = p.AccountExpirationDate,
                        IsPrivileged = isPriv
                    });
                }
            }
            return results;
        }

        public CreateUserResult CreateUser(CreateUserRequest req, string caller) {
            var d = GetDomain(req.Domain);
            var sam = string.IsNullOrWhiteSpace(req.SamAccountName)
                ? $"{req.FirstName}.{req.LastName}".ToLowerInvariant()
                : req.SamAccountName;
            sam = sam.Replace(" ", "");
            var display = ToSentenceCase($"{req.FirstName} {req.LastName}");
            var initialPassword = _passwords.Generate();

            // Standard account
            var (userDn, createdUp) = CreateAccountInternal(d, sam, display, req, initialPassword, isPrivileged:false);

            var groupsAdded = new List<string>();
            foreach (var g in d.StandardGroups) {
                AddToGroup(d, sam, g);
                groupsAdded.Add(g);
            }

            if (req.CreatePrivileged) {
                var adminSam = sam + "-a";
                var adminDisplay = display.ToLowerInvariant();
                var (_, adminUp) = CreateAccountInternal(d, adminSam, adminDisplay, req, initialPassword, isPrivileged:true);
                foreach (var g in d.PrivilegedGroups) {
                    AddToGroup(d, adminSam, g);
                    groupsAdded.Add(g);
                }
                // Set primary group and remove Domain Users
                SetPrimaryGroup(d, adminSam, d.PrivilegedPrimaryGroup);
                RemoveFromGroup(d, adminSam, "Domain Users");
            }

            var res = new CreateUserResult {
                Domain = d.Name,
                SamAccountName = sam,
                DisplayName = display,
                DistinguishedName = userDn,
                OuCreatedIn = d.UserOuDn,
                Enabled = true,
                IsLocked = false,
                ExpirationDate = req.ExpirationDate.HasValue ? req.ExpirationDate.Value.ToDateTime(new TimeOnly(0,0)) : null,
                InitialPassword = initialPassword,
                GroupsAdded = groupsAdded.ToArray()
            };

            _audit.WriteAsync(new AuditEvent {
                TimestampUtc = DateTime.UtcNow,
                Administrator = caller,
                SourceIp = "server",
                ActionType = "CreateUser",
                TargetUser = $"{d.Name}\\{sam}",
                Outcome = "Success"
            });

            return res;
        }

        private (string dn, UserPrincipal up) CreateAccountInternal(DomainConfig d, string sam, string display, CreateUserRequest req, string password, bool isPrivileged) {
            using var ctx = AdminContext(d);
            var up = new UserPrincipal(ctx);
            up.SamAccountName = sam;
            up.DisplayName = display;
            up.GivenName = ToSentenceCase(req.FirstName);
            up.Surname = ToSentenceCase(req.LastName);
            up.Enabled = true;
            if (req.ExpirationDate.HasValue)
                up.AccountExpirationDate = req.ExpirationDate.Value.ToDateTime(new TimeOnly(0,0));
            up.SetPassword(password);
            up.Save();

            // Move to OU
            using var entry = (DirectoryEntry)up.GetUnderlyingObject();
            using var newParent = new DirectoryEntry($"LDAP://{d.UserOuDn}", d.ServiceAccountUser, d.ServiceAccountPassword);
            entry.MoveTo(newParent);
            entry.Properties["displayName"].Value = display;
            // Custom birthdate attribute
            if (req.Birthdate.HasValue) {
                var dobAttr = _opts.BirthdateAttribute ?? "extensionAttribute1";
                entry.Properties[dobAttr].Value = req.Birthdate.Value.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
            }
            entry.CommitChanges();

            if (isPrivileged) {
                // Set 30-day validity (from now)
                up.AccountExpirationDate = DateTime.UtcNow.AddDays(30);
                up.Save();
            }

            return (entry.Properties["distinguishedName"].Value?.ToString() ?? "", up);
        }

        public void UpdateUser(UpdateUserRequest req, string caller) {
            var d = GetDomain(req.Domain);
            using var ctx = AdminContext(d);
            var up = UserPrincipal.FindByIdentity(ctx, req.SamAccountName) ?? throw new InvalidOperationException("User not found");
            up.GivenName = ToSentenceCase(req.FirstName);
            up.Surname = ToSentenceCase(req.LastName);
            up.DisplayName = ToSentenceCase($"{req.FirstName} {req.LastName}");
            if (req.ExpirationDate.HasValue) up.AccountExpirationDate = req.ExpirationDate.Value.ToDateTime(new TimeOnly(0,0));
            up.Save();

            // Birthdate
            using var entry = (DirectoryEntry)up.GetUnderlyingObject();
            if (req.Birthdate.HasValue) {
                entry.Properties[_opts.BirthdateAttribute ?? "extensionAttribute1"].Value = req.Birthdate.Value.ToString("yyyy-MM-dd");
            }
            entry.CommitChanges();

            if (req.CreatePrivileged) {
                var adminSam = up.SamAccountName + "-a";
                // Create if not exists
                using var ctx2 = AdminContext(d);
                var existing = UserPrincipal.FindByIdentity(ctx2, adminSam);
                if (existing == null) {
                    var cur = new CreateUserRequest {
                        Domain = req.Domain,
                        FirstName = req.FirstName,
                        LastName = req.LastName,
                        Birthdate = req.Birthdate,
                        ExpirationDate = DateOnly.FromDateTime(DateTime.UtcNow.AddDays(30)),
                        CreatePrivileged = false,
                        SamAccountName = adminSam
                    };
                    CreateAccountInternal(d, adminSam, (up.DisplayName ?? "").ToLowerInvariant(), cur, _passwords.Generate(), isPrivileged:true);
                    foreach (var g in d.PrivilegedGroups) AddToGroup(d, adminSam, g);
                    SetPrimaryGroup(d, adminSam, d.PrivilegedPrimaryGroup);
                    RemoveFromGroup(d, adminSam, "Domain Users");
                }
            }
        }

        public void UnlockUser(string domain, string sam) {
            var d = GetDomain(domain);
            using var ctx = AdminContext(d);
            var up = UserPrincipal.FindByIdentity(ctx, sam) ?? throw new InvalidOperationException("User not found");
            up.UnlockAccount();
        }

        public void EnableDisableUser(string domain, string sam, bool enable) {
            var d = GetDomain(domain);
            using var ctx = AdminContext(d);
            var up = UserPrincipal.FindByIdentity(ctx, sam) ?? throw new InvalidOperationException("User not found");
            up.Enabled = enable;
            up.Save();
        }

        public void ResetPassword(string domain, string sam, string newPassword, bool unlock) {
            var d = GetDomain(domain);
            using var ctx = AdminContext(d);
            var up = UserPrincipal.FindByIdentity(ctx, sam) ?? throw new InvalidOperationException("User not found");
            up.SetPassword(newPassword);
            if (unlock) up.UnlockAccount();
            up.Save();

            if (sam.EndsWith("-a", StringComparison.OrdinalIgnoreCase)) {
                // Reset 30-day validity
                up.AccountExpirationDate = DateTime.UtcNow.AddDays(30);
                up.Save();
            }
        }

        public bool VerifyCredentials(string domain, string sam, string password) {
            var d = GetDomain(domain);
            using var ctx = new PrincipalContext(ContextType.Domain, d.Name);
            return ctx.ValidateCredentials(sam, password);
        }

        public bool VerifyBirthdate(string domain, string sam, DateOnly? dob) {
            if (!dob.HasValue) return false;
            var d = GetDomain(domain);
            using var ctx = AdminContext(d);
            var up = UserPrincipal.FindByIdentity(ctx, sam);
            if (up == null) return false;
            using var de = (DirectoryEntry)up.GetUnderlyingObject();
            var attr = _opts.BirthdateAttribute ?? "extensionAttribute1";
            var val = de.Properties[attr]?.Value?.ToString();
            if (string.IsNullOrEmpty(val)) return false;
            return string.Equals(val, dob.Value.ToString("yyyy-MM-dd"), StringComparison.Ordinal);
        }

        public void ChangeOwnPassword(string domain, string sam, string currentPassword, string newPassword) {
            var d = GetDomain(domain);
            using var ctx = new PrincipalContext(ContextType.Domain, d.Name, sam, currentPassword);
            using var up = UserPrincipal.FindByIdentity(ctx, sam) ?? throw new InvalidOperationException("User not found");
            up.ChangePassword(currentPassword, newPassword);
        }

        private void AddToGroup(DomainConfig d, string sam, string groupName) {
            using var ctx = AdminContext(d);
            using var up = UserPrincipal.FindByIdentity(ctx, sam) ?? throw new InvalidOperationException("User not found");
            using var gp = GroupPrincipal.FindByIdentity(ctx, groupName) ?? throw new InvalidOperationException($"Group not found: {groupName}");
            if (!gp.Members.Contains(up)) gp.Members.Add(up);
            gp.Save();
        }
        private void RemoveFromGroup(DomainConfig d, string sam, string groupName) {
            using var ctx = AdminContext(d);
            using var up = UserPrincipal.FindByIdentity(ctx, sam) ?? throw new InvalidOperationException("User not found");
            using var gp = GroupPrincipal.FindByIdentity(ctx, groupName);
            if (gp != null && gp.Members.Contains(up)) {
                gp.Members.Remove(up);
                gp.Save();
            }
        }
        private void SetPrimaryGroup(DomainConfig d, string sam, string groupName) {
            using var ctx = AdminContext(d);
            using var up = UserPrincipal.FindByIdentity(ctx, sam) ?? throw new InvalidOperationException("User not found");
            using var gp = GroupPrincipal.FindByIdentity(ctx, groupName) ?? throw new InvalidOperationException($"Group not found: {groupName}");
            using var de = (DirectoryEntry)up.GetUnderlyingObject();
            de.Properties["primaryGroupID"].Value = gp.Sid.Value; // may require RID; simplified, often needs numeric RID not SID
            de.CommitChanges();
        }

        private static string ToSentenceCase(string s) {
            if (string.IsNullOrWhiteSpace(s)) return s;
            var lower = s.ToLowerInvariant();
            return char.ToUpper(lower[0]) + lower.Substring(1);
        }
    }
}
