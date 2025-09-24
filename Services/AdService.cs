using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Globalization;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using ADWebManager.Models;
using Microsoft.Extensions.Options;

namespace ADWebManager.Services
{
    public class AdOptions
    {
        public List<DomainConfig> Domains { get; set; } = new();
        public string BirthdateAttribute { get; set; } = "extensionAttribute1";
        public int PrivilegedAccountValidityDays { get; set; } = 30;
    }

    public interface IPasswordGenerator
    {
        string GenerateStandard(); // 12, letters+numbers+specials
        string GenerateAdmin();    // 8, letters+numbers only
    }

    public sealed class DefaultPasswordGenerator : IPasswordGenerator
    {
        private static readonly char[] StandardAlphabet =
            "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()-_=+[]{}".ToCharArray();
        private static readonly char[] AdminAlphabet =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".ToCharArray();

        private static string Generate(int length, char[] alphabet)
        {
            using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
            var buf = new byte[length];
            rng.GetBytes(buf);
            var sb = new StringBuilder(length);
            for (int i = 0; i < buf.Length; i++) sb.Append(alphabet[buf[i] % alphabet.Length]);
            return sb.ToString();
        }

        public string GenerateStandard() => Generate(12, StandardAlphabet);
        public string GenerateAdmin()    => Generate(8,  AdminAlphabet);
    }

    public class AdService
    {
        private readonly AdOptions _opts;
        private readonly IPasswordGenerator _passwords;

        public AdService(IOptions<AdOptions> options, IPasswordGenerator? passwords = null)
        {
            _opts = options.Value ?? new AdOptions();
            _passwords = passwords ?? new DefaultPasswordGenerator();
        }

        // ---------- Public ----------
        public CreateUserResult CreateUser(CreateUserRequest req, string caller)
        {
            var d = GetDomain(req.Domain);

            Require(!string.IsNullOrWhiteSpace(req.FirstName), "First name required.");
            Require(!string.IsNullOrWhiteSpace(req.LastName), "Last name required.");
            Require(req.Birthdate.HasValue, "Birthdate required.");
            Require(req.ExpirationDate.HasValue, "Expiration date required.");
            Require(!string.IsNullOrWhiteSpace(req.SamAccountName), "Username required.");

            var sam = req.SamAccountName!.Trim();
            var display = ToSentenceCase($"{req.FirstName} {req.LastName}");

            // Regular account
            var stdPass = _passwords.GenerateStandard();
            var (userDn, userOu, _) = CreateAccountInternal(
                d, sam, display, req, stdPass,
                isPrivileged: false,
                expireAtLogon: true);

            var groupsAdded = new List<string>();
            if (d.StandardGroups != null)
                foreach (var g in d.StandardGroups) TryAddToGroup(d, sam, g, groupsAdded);

            // Optional privileged (-a) account
            string? adminPass = null;
            if (req.CreatePrivileged)
            {
                adminPass = _passwords.GenerateAdmin();
                var adminSam = sam + "-a";

                CreateAccountInternal(
                    d, adminSam, display, req, adminPass,
                    isPrivileged: true,
                    expireAtLogon: false);

                // Add all configured privileged groups (if any)
                if (d.PrivilegedGroups != null)
                    foreach (var g in d.PrivilegedGroups) TryAddToGroup(d, adminSam, g, groupsAdded);

                // NEW: Add the selected privileged group (if provided and not already included)
                if (!string.IsNullOrWhiteSpace(req.SelectedPrivilegedGroupCn))
                    TryAddToGroup(d, adminSam, req.SelectedPrivilegedGroupCn, groupsAdded);

                // Decide primary group:
                // 1) If MakeSelectedPrimary==true and a SelectedPrivilegedGroupCn is provided → make it primary.
                // 2) Else if config has a fallback PrivilegedPrimaryGroup → use that.
                if (req.MakeSelectedPrimary && !string.IsNullOrWhiteSpace(req.SelectedPrivilegedGroupCn))
                {
                    TrySetPrimaryGroup(d, adminSam, req.SelectedPrivilegedGroupCn!);
                    // Optional: remove default "Domain Users"
                    TryRemoveFromGroup(d, adminSam, "Domain Users");
                }
                else if (!string.IsNullOrWhiteSpace(d.PrivilegedPrimaryGroup))
                {
                    TrySetPrimaryGroup(d, adminSam, d.PrivilegedPrimaryGroup!);
                    TryRemoveFromGroup(d, adminSam, "Domain Users");
                }
            }

            return new CreateUserResult
            {
                Domain = d.Name,
                SamAccountName = sam,
                DisplayName = display,
                DistinguishedName = userDn,
                OuCreatedIn = userOu,
                Enabled = true,
                IsLocked = false,
                ExpirationDate = req.ExpirationDate?.ToDateTime(new TimeOnly(0, 0)),
                MobileNumber = req.MobileNumber,
                InitialPassword = stdPass,
                AdminInitialPassword = adminPass,
                HasPrivileged = req.CreatePrivileged,
                GroupsAdded = groupsAdded.Distinct(StringComparer.OrdinalIgnoreCase).ToArray()
            };
        }


        public void UpdateUser(UpdateUserRequest req, string caller)
        {
            var d = GetDomain(req.Domain);
            Require(!string.IsNullOrWhiteSpace(req.SamAccountName), "Username required.");
            Require(!string.IsNullOrWhiteSpace(req.FirstName), "First name required.");
            Require(!string.IsNullOrWhiteSpace(req.LastName), "Last name required.");
            Require(req.Birthdate.HasValue, "Birthdate required.");
            Require(req.ExpirationDate.HasValue, "Expiration required.");

            using var ctx = AdminContext(d);
            var user = FindBySam(ctx, req.SamAccountName!) ?? throw new Exception("User not found.");

            user.GivenName = ToSentenceCase(req.FirstName);
            user.Surname = ToSentenceCase(req.LastName);
            user.DisplayName = $"{user.GivenName} {user.Surname}";
            user.AccountExpirationDate = req.ExpirationDate!.Value.ToDateTime(new TimeOnly(0, 0));
            user.Save();

            using var de = (DirectoryEntry)user.GetUnderlyingObject();

            var dobAttr = _opts.BirthdateAttribute ?? "extensionAttribute1";
            de.Properties[dobAttr].Value = req.Birthdate!.Value.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);

            if (!string.IsNullOrWhiteSpace(req.MobileNumber))
                de.Properties["mobile"].Value = req.MobileNumber;

            de.CommitChanges();
        }

        public void UnlockAccount(string domain, string samAccountName)
        {
            var d = GetDomain(domain);
            using var ctx = AdminContext(d);
            var user = FindBySam(ctx, samAccountName) ?? throw new Exception("User not found.");
            try { user.UnlockAccount(); } catch { }
            user.Save();
        }

        public void SetEnabled(string domain, string samAccountName, bool enable)
        {
            var d = GetDomain(domain);
            using var ctx = AdminContext(d);
            var user = FindBySam(ctx, samAccountName) ?? throw new Exception("User not found.");
            user.Enabled = enable;
            user.Save();
        }

        public string ResetPassword(string domain, string samAccountName, bool unlock)
        {
            var d = GetDomain(domain);
            using var ctx = AdminContext(d);
            var user = FindBySam(ctx, samAccountName) ?? throw new Exception("User not found.");

            var isAdmin = samAccountName.EndsWith("-a", StringComparison.OrdinalIgnoreCase);
            var newPass = isAdmin ? _passwords.GenerateAdmin() : _passwords.GenerateStandard();

            user.SetPassword(newPass);
            if (unlock) { try { user.UnlockAccount(); } catch { } user.Enabled = true; }
            user.Save();
            return newPass;
        }

        public async Task SelfServiceResetPasswordAsync(SelfServiceResetRequest req)
        {
            Require(!string.IsNullOrWhiteSpace(req.Domain), "Domain required.");
            Require(!string.IsNullOrWhiteSpace(req.SamAccountName), "Username required.");
            Require(!string.IsNullOrWhiteSpace(req.Birthdate), "Birthdate required.");
            Require(!string.IsNullOrWhiteSpace(req.NewPassword), "New password required.");

            if (req.SamAccountName.EndsWith("-a", StringComparison.OrdinalIgnoreCase))
                throw new Exception("Privileged (-a) accounts cannot use self-service.");

            var d = GetDomain(req.Domain);
            using var ctx = AdminContext(d);
            var user = FindBySam(ctx, req.SamAccountName!) ?? throw new Exception("Account not found.");

            using var de = (DirectoryEntry)user.GetUnderlyingObject();

            // Verify DOB
            var dobAttr = _opts.BirthdateAttribute ?? "extensionAttribute1";
            var storedDob = (de.Properties[dobAttr]?.Value as string)?.Trim();
            var expectedDob = req.Birthdate.Trim();
            if (string.IsNullOrWhiteSpace(storedDob) || !string.Equals(storedDob, expectedDob, StringComparison.Ordinal))
                throw new Exception("Identity verification failed (DOB).");

            // Verify last-4 of mobile
            if (!string.IsNullOrWhiteSpace(req.MobileLast4))
            {
                var storedMobile = (de.Properties["mobile"]?.Value as string) ?? "";
                var digits = new string(storedMobile.Where(char.IsDigit).ToArray());
                var last4 = digits.Length >= 4 ? digits[^4..] : digits;
                if (string.IsNullOrWhiteSpace(last4) || !string.Equals(last4, req.MobileLast4.Trim(), StringComparison.Ordinal))
                    throw new Exception("Identity verification failed (mobile).");
            }

            user.SetPassword(req.NewPassword);
            try { user.UnlockAccount(); } catch { }
            user.Enabled = true;
            user.Save();

            await Task.CompletedTask;
        }

        public IReadOnlyList<UserRow> ListUsers(string domain)
        {
            var d = GetDomain(domain);
            var rows = new List<UserRow>();

            using var de = new DirectoryEntry($"LDAP://{d.LdapBaseDn}", d.ServiceAccountUser, d.ServiceAccountPassword);
            using var ds = new DirectorySearcher(de)
            {
                Filter = "(&(objectCategory=person)(objectClass=user)(!(objectClass=computer)))",
                PageSize = 500,
                SearchScope = SearchScope.Subtree
            };
            ds.PropertiesToLoad.AddRange(new[] { "samAccountName", "displayName", "userAccountControl", "lockoutTime", "accountExpires" });

            foreach (SearchResult r in ds.FindAll())
            {
                var sam = r.Properties["samAccountName"]?.Count > 0 ? (string)r.Properties["samAccountName"][0] : null;
                if (string.IsNullOrWhiteSpace(sam)) continue;

                var display = r.Properties["displayName"]?.Count > 0 ? (string)r.Properties["displayName"][0] : sam;

                bool enabled = true;
                if (r.Properties["userAccountControl"]?.Count > 0)
                {
                    var uac = (int)r.Properties["userAccountControl"][0];
                    enabled = (uac & 0x2) == 0;
                }

                bool isLocked = false;
                if (r.Properties["lockoutTime"]?.Count > 0)
                {
                    var val = (long)r.Properties["lockoutTime"][0];
                    isLocked = val != 0;
                }

                DateTime? expiration = null;
                if (r.Properties["accountExpires"]?.Count > 0)
                {
                    var exp = (long)r.Properties["accountExpires"][0];
                    if (exp != 0 && exp != 0x7FFFFFFFFFFFFFFF) expiration = DateTime.FromFileTimeUtc(exp);
                }

                rows.Add(new UserRow
                {
                    Domain = d.Name,
                    SamAccountName = sam,
                    DisplayName = display,
                    Enabled = enabled,
                    IsLocked = isLocked,
                    ExpirationDate = expiration,
                    IsPrivileged = sam.EndsWith("-a", StringComparison.OrdinalIgnoreCase)
                });
            }
            return rows;
        }

        // ---------- Internals ----------
        private (string dn, string ouUsed, UserPrincipal up) CreateAccountInternal(
            DomainConfig d, string sam, string display, CreateUserRequest req,
            string password, bool isPrivileged, bool expireAtLogon)
        {
            using var ctx = AdminContext(d);
            if (FindBySam(ctx, sam) != null) throw new Exception($"Account '{sam}' already exists.");

            var up = new UserPrincipal(ctx)
            {
                SamAccountName = sam,
                DisplayName = display,
                GivenName = ToSentenceCase(req.FirstName),
                Surname = ToSentenceCase(req.LastName),
                Enabled = true
            };
            if (req.ExpirationDate.HasValue)
                up.AccountExpirationDate = req.ExpirationDate.Value.ToDateTime(new TimeOnly(0, 0));
            up.Save();

            using var entry = (DirectoryEntry)up.GetUnderlyingObject();

            // Move to OU
            var targetOu = (!string.IsNullOrWhiteSpace(d.AdminOuDn) && isPrivileged) ? d.AdminOuDn : d.UserOuDn;
            if (!string.IsNullOrWhiteSpace(targetOu))
            {
                using var newParent = new DirectoryEntry($"LDAP://{targetOu}", d.ServiceAccountUser, d.ServiceAccountPassword);
                entry.MoveTo(newParent);
            }

            // Password & flags
            up.SetPassword(password);
            up.PasswordNeverExpires = false;
            up.Save();

            // Attributes
            entry.Properties["displayName"].Value = display;

            if (req.Birthdate.HasValue)
            {
                var dobAttr = _opts.BirthdateAttribute ?? "extensionAttribute1";
                entry.Properties[dobAttr].Value = req.Birthdate.Value.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
            }

            if (!string.IsNullOrWhiteSpace(req.MobileNumber))
                entry.Properties["mobile"].Value = req.MobileNumber;

            entry.CommitChanges();

            if (isPrivileged)
            {
                var days = Math.Max(1, _opts.PrivilegedAccountValidityDays);
                up.AccountExpirationDate = DateTime.UtcNow.AddDays(days);
                up.Save();
            }
            else if (expireAtLogon)
            {
                up.ExpirePasswordNow();
                up.Save();
            }

            var dn = (string)entry.Properties["distinguishedName"].Value;
            return (dn, targetOu, up);
        }

        private DomainConfig GetDomain(string name)
        {
            var d = _opts.Domains.FirstOrDefault(x => x.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
            if (d == null) throw new Exception($"Domain '{name}' is not configured.");
            Require(!string.IsNullOrWhiteSpace(d.ServiceAccountUser), $"Service account user not set for domain {name}.");
            Require(!string.IsNullOrWhiteSpace(d.ServiceAccountPassword), $"Service account password not set for domain {name}.");
            Require(!string.IsNullOrWhiteSpace(d.LdapBaseDn), $"LDAP base DN not set for domain {name}.");
            Require(!string.IsNullOrWhiteSpace(d.UserOuDn), $"User OU DN not set for domain {name}.");
            return d;
        }

        private PrincipalContext AdminContext(DomainConfig d) =>
            new PrincipalContext(ContextType.Domain, d.Name, d.ServiceAccountUser, d.ServiceAccountPassword);

        private static UserPrincipal? FindBySam(PrincipalContext ctx, string sam)
        {
            using var qbe = new UserPrincipal(ctx) { SamAccountName = sam };
            using var searcher = new PrincipalSearcher(qbe);
            return searcher.FindOne() as UserPrincipal;
        }

        private static string ToSentenceCase(string? s)
        {
            if (string.IsNullOrWhiteSpace(s)) return string.Empty;
            s = s.Trim();
            return s.Length == 1 ? s.ToUpperInvariant() : char.ToUpperInvariant(s[0]) + s[1..].ToLowerInvariant();
        }
        private static void Require(bool predicate, string message) { if (!predicate) throw new Exception(message); }

        // Groups
        private void TryAddToGroup(DomainConfig d, string sam, string groupCn, List<string>? auditList = null)
        {
            try
            {
                using var ctx = AdminContext(d);
                var user = FindBySam(ctx, sam); if (user == null) return;
                using var deGroup = new DirectoryEntry($"LDAP://CN={groupCn},{d.GroupsBaseDn}", d.ServiceAccountUser, d.ServiceAccountPassword);
                using var deUser = (DirectoryEntry)user.GetUnderlyingObject();
                var members = deGroup.Properties["member"];
                var userDn = (string)deUser.Properties["distinguishedName"].Value;
                if (!ContainsDn(members, userDn)) { members.Add(userDn); deGroup.CommitChanges(); }
                auditList?.Add(groupCn);
            } catch { }
        }
        private void TryRemoveFromGroup(DomainConfig d, string sam, string groupCn)
        {
            try
            {
                using var ctx = AdminContext(d);
                var user = FindBySam(ctx, sam); if (user == null) return;
                using var deGroup = new DirectoryEntry($"LDAP://CN={groupCn},{d.GroupsBaseDn}", d.ServiceAccountUser, d.ServiceAccountPassword);
                using var deUser = (DirectoryEntry)user.GetUnderlyingObject();
                var members = deGroup.Properties["member"];
                var userDn = (string)deUser.Properties["distinguishedName"].Value;
                if (ContainsDn(members, userDn)) { members.Remove(userDn); deGroup.CommitChanges(); }
            } catch { }
        }
        private void TrySetPrimaryGroup(DomainConfig d, string sam, string primaryGroupCn)
        {
            try
            {
                using var ctx = AdminContext(d);
                var user = FindBySam(ctx, sam); if (user == null) return;
                using var deUser = (DirectoryEntry)user.GetUnderlyingObject();
                using var deGroup = new DirectoryEntry($"LDAP://CN={primaryGroupCn},{d.GroupsBaseDn}", d.ServiceAccountUser, d.ServiceAccountPassword);
                var groupSid = new SecurityIdentifier((byte[])deGroup.Properties["objectSid"].Value, 0);
                var primaryRid = int.Parse(groupSid.ToString().Split('-')[^1], CultureInfo.InvariantCulture);
                deUser.Properties["primaryGroupID"].Value = primaryRid;
                deUser.CommitChanges();
            } catch { }
        }
        private static bool ContainsDn(PropertyValueCollection members, string dn)
        {
            foreach (var m in members) if (string.Equals(m?.ToString(), dn, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }
    }
}
