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
    public interface IPasswordGenerator
    {
        string GenerateStandard();
        string GenerateAdmin();
    }

    public sealed class ConfigurablePasswordGenerator : IPasswordGenerator
    {
        private readonly PasswordPolicy _policy;
        public ConfigurablePasswordGenerator(PasswordPolicy policy) { _policy = policy; }

        private static string Alphabet(bool letters, bool digits, bool specials, string allowedSpecials)
        {
            var sb = new StringBuilder();
            if (letters) sb.Append("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
            if (digits) sb.Append("0123456789");
            if (specials && !string.IsNullOrEmpty(allowedSpecials)) sb.Append(allowedSpecials);
            return sb.ToString();
        }

        private static string Generate(int length, string alphabet)
        {
            if (string.IsNullOrEmpty(alphabet)) throw new Exception("Password alphabet is empty; check PasswordPolicy.");
            using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
            var bytes = new byte[length];
            rng.GetBytes(bytes);
            var chars = new char[length];
            for (int i = 0; i < length; i++) chars[i] = alphabet[bytes[i] % alphabet.Length];
            return new string(chars);
        }

        public string GenerateStandard()
        {
            var p = _policy.Standard;
            var alpha = Alphabet(p.IncludeLetters, p.IncludeDigits, p.IncludeSpecials, p.AllowedSpecials);
            return Generate(p.Length, alpha);
        }

        public string GenerateAdmin()
        {
            var p = _policy.Admin;
            var alpha = Alphabet(p.IncludeLetters, p.IncludeDigits, p.IncludeSpecials, p.AllowedSpecials);
            return Generate(p.Length, alpha);
        }
    }

    public class AdService
    {
        private readonly AdSettings _cfg;
        private readonly IPasswordGenerator _pw;

        public AdService(IOptions<AdSettings> cfg)
        {
            _cfg = cfg.Value;
            _pw = new ConfigurablePasswordGenerator(_cfg.PasswordPolicy ?? new PasswordPolicy());
        }

        public CreateUserResult CreateUser(CreateUserRequest req, string caller)
        {
            Require(!string.IsNullOrWhiteSpace(req.Domain), "Domain required.");
            Require(!string.IsNullOrWhiteSpace(req.SamAccountName), "Username required.");
            Require(!string.IsNullOrWhiteSpace(req.FirstName), "First name required.");
            Require(!string.IsNullOrWhiteSpace(req.LastName), "Last name required.");
            Require(req.Birthdate.HasValue, "Birthdate required.");
            Require(req.ExpirationDate.HasValue, "Expiration required.");
            Require(!string.IsNullOrWhiteSpace(req.MobileNumber), "Mobile number required.");

            var sam = req.SamAccountName.Trim();
            var display = ToSentenceCase($"{req.FirstName} {req.LastName}");

            var ctx = AdminContext(req.Domain);
            using var user = new UserPrincipal(ctx)
            {
                SamAccountName = sam,
                GivenName = ToSentenceCase(req.FirstName),
                Surname = ToSentenceCase(req.LastName),
                DisplayName = display,
                Enabled = true,
                AccountExpirationDate = req.ExpirationDate!.Value.ToDateTime(new TimeOnly(0, 0))
            };
            user.Save();
            using var deUser = (DirectoryEntry)user.GetUnderlyingObject();

            var userOu = ExpandOu(_cfg.Provisioning.DefaultUserOuFormat, req.Domain);
            MoveToOu(deUser, userOu);

            var stdPass = _pw.GenerateStandard();
            user.SetPassword(stdPass);
            user.PasswordNeverExpires = false;
            user.ExpirePasswordNow();
            user.Save();

            var dobAttr = string.IsNullOrWhiteSpace(_cfg.BirthdateAttribute) ? "extensionAttribute1" : _cfg.BirthdateAttribute;
            if (req.Birthdate.HasValue)
                deUser.Properties[dobAttr].Value = req.Birthdate.Value.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
            if (!string.IsNullOrWhiteSpace(req.MobileNumber))
                deUser.Properties["mobile"].Value = req.MobileNumber;
            deUser.CommitChanges();

            var groupsAdded = new List<string>();
            string? adminPass = null;

            if (req.CreatePrivileged)
            {
                var adminSam = sam + "-a";
                using var admin = new UserPrincipal(ctx)
                {
                    SamAccountName = adminSam,
                    GivenName = user.GivenName,
                    Surname = user.Surname,
                    DisplayName = display,
                    Enabled = true
                };
                admin.Save();
                using var deAdmin = (DirectoryEntry)admin.GetUnderlyingObject();

                var adminOu = ExpandOu(_cfg.Provisioning.AdminUserOuFormat, req.Domain);
                MoveToOu(deAdmin, adminOu);

                adminPass = _pw.GenerateAdmin();
                admin.SetPassword(adminPass);
                admin.PasswordNeverExpires = false;
                admin.Save();

                if (!string.IsNullOrWhiteSpace(req.SelectedPrivilegedGroupCn))
                    TryAddToGroup(req.Domain, adminSam, req.SelectedPrivilegedGroupCn, groupsAdded);

                if (req.MakeSelectedPrimary && !string.IsNullOrWhiteSpace(req.SelectedPrivilegedGroupCn))
                {
                    TrySetPrimaryGroup(req.Domain, adminSam, req.SelectedPrivilegedGroupCn);
                    TryRemoveFromGroup(req.Domain, adminSam, "Domain Users");
                }

                var days = Math.Max(1, _cfg.PrivilegedAccountValidityDays);
                admin.AccountExpirationDate = DateTime.UtcNow.AddDays(days);
                admin.Save();
            }

            var dn = (string)deUser.Properties["distinguishedName"].Value;
            return new CreateUserResult
            {
                Domain = req.Domain,
                SamAccountName = sam,
                DisplayName = display,
                DistinguishedName = dn,
                OuCreatedIn = userOu,
                Enabled = true,
                IsLocked = false,
                ExpirationDate = req.ExpirationDate!.Value.ToDateTime(new TimeOnly(0, 0)),
                MobileNumber = req.MobileNumber,
                InitialPassword = stdPass,
                AdminInitialPassword = adminPass,
                HasPrivileged = req.CreatePrivileged,
                GroupsAdded = groupsAdded.Distinct(StringComparer.OrdinalIgnoreCase).ToArray()
            };
        }

        public UserDetails GetUserDetails(string domain, string sam)
        {
            using var ctx = AdminContext(domain);
            var user = FindBySam(ctx, sam) ?? throw new Exception("User not found.");
            using var de = (DirectoryEntry)user.GetUnderlyingObject();

            var dobAttr = string.IsNullOrWhiteSpace(_cfg.BirthdateAttribute) ? "extensionAttribute1" : _cfg.BirthdateAttribute;
            var dobString = de.Properties[dobAttr]?.Value as string;
            DateOnly? birthdate = null;
            if (DateOnly.TryParse(dobString, out var dob))
            {
                birthdate = dob;
            }

            return new UserDetails
            {
                Domain = domain,
                SamAccountName = user.SamAccountName,
                DisplayName = user.DisplayName,
                FirstName = user.GivenName,
                LastName = user.Surname,
                Enabled = user.Enabled ?? false,
                IsLocked = user.IsAccountLockedOut(),
                ExpirationDate = user.AccountExpirationDate,
                Birthdate = birthdate,
                MobileNumber = de.Properties["mobile"]?.Value as string
            };
        }

        public void UpdateUser(UpdateUserRequest req, string caller)
        {
            Require(!string.IsNullOrWhiteSpace(req.Domain), "Domain required.");
            Require(!string.IsNullOrWhiteSpace(req.SamAccountName), "Username required.");
            Require(!string.IsNullOrWhiteSpace(req.FirstName), "First name required.");
            Require(!string.IsNullOrWhiteSpace(req.LastName), "Last name required.");
            Require(req.Birthdate.HasValue, "Birthdate required.");
            Require(req.ExpirationDate.HasValue, "Expiration required.");
            Require(!string.IsNullOrWhiteSpace(req.MobileNumber), "Mobile number required.");

            using var ctx = AdminContext(req.Domain);
            var user = FindBySam(ctx, req.SamAccountName) ?? throw new Exception("User not found.");

            user.GivenName = ToSentenceCase(req.FirstName);
            user.Surname = ToSentenceCase(req.LastName);
            user.DisplayName = $"{user.GivenName} {user.Surname}";
            user.AccountExpirationDate = req.ExpirationDate!.Value.ToDateTime(new TimeOnly(0, 0));
            user.Save();

            using var de = (DirectoryEntry)user.GetUnderlyingObject();
            var dobAttr = string.IsNullOrWhiteSpace(_cfg.BirthdateAttribute) ? "extensionAttribute1" : _cfg.BirthdateAttribute;
            de.Properties[dobAttr].Value = req.Birthdate!.Value.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
            de.Properties["mobile"].Value = req.MobileNumber;
            de.CommitChanges();
        }

        public string ResetPassword(string domain, string sam, bool unlock)
        {
            using var ctx = AdminContext(domain);
            var user = FindBySam(ctx, sam) ?? throw new Exception("User not found.");
            var isAdmin = sam.EndsWith("-a", StringComparison.OrdinalIgnoreCase);
            var newPass = isAdmin ? _pw.GenerateAdmin() : _pw.GenerateStandard();

            user.SetPassword(newPass);
            if (unlock) { try { user.UnlockAccount(); } catch { } user.Enabled = true; }
            user.Save();
            return newPass;
        }

        public void SetPassword(string domain, string sam, string newPassword, bool unlock)
        {
            using var ctx = AdminContext(domain);
            var user = FindBySam(ctx, sam) ?? throw new Exception("User not found.");

            user.SetPassword(newPassword);
            if (unlock) { try { user.UnlockAccount(); } catch { } user.Enabled = true; }
            user.Save();
        }

        public async Task SelfServiceResetPasswordAsync(SelfServiceResetRequest req)
        {
            if (req.SamAccountName.EndsWith("-a", StringComparison.OrdinalIgnoreCase))
                throw new Exception("Privileged (-a) accounts cannot use self-service.");

            using var ctx = AdminContext(req.Domain);
            var user = FindBySam(ctx, req.SamAccountName) ?? throw new Exception("Account not found.");
            using var de = (DirectoryEntry)user.GetUnderlyingObject();

            var dobAttr = string.IsNullOrWhiteSpace(_cfg.BirthdateAttribute) ? "extensionAttribute1" : _cfg.BirthdateAttribute;
            var storedDob = (de.Properties[dobAttr]?.Value as string)?.Trim();
            if (!string.Equals(storedDob, req.Birthdate.Trim(), StringComparison.Ordinal))
                throw new Exception("Identity verification failed (DOB).");

            var mobile = (de.Properties["mobile"]?.Value as string) ?? string.Empty;
            var digits = new string(mobile.Where(char.IsDigit).ToArray());
            var last4 = digits.Length >= 4 ? digits[^4..] : digits;
            if (!string.Equals(last4, req.MobileLast4?.Trim() ?? "", StringComparison.Ordinal))
                throw new Exception("Identity verification failed (mobile).");

            user.SetPassword(req.NewPassword);
            try { user.UnlockAccount(); } catch { }
            user.Enabled = true;
            user.Save();
            await Task.CompletedTask;
        }
        
        private PrincipalContext AdminContext(string domain) =>
            new PrincipalContext(ContextType.Domain, domain, _cfg.Provisioning.ServiceAccountUser, _cfg.Provisioning.ServiceAccountPassword);

        private static UserPrincipal? FindBySam(PrincipalContext ctx, string sam)
        {
            using var qbe = new UserPrincipal(ctx) { SamAccountName = sam };
            using var s = new PrincipalSearcher(qbe);
            return s.FindOne() as UserPrincipal;
        }

        private string ExpandOu(string format, string domain)
        {
            var comps = string.Join(",", domain.Split('.').Select(x => $"DC={x}"));
            return format.Replace("{domain-components}", comps, StringComparison.OrdinalIgnoreCase);
        }

        private void MoveToOu(DirectoryEntry de, string ouDn)
        {
            using var parent = new DirectoryEntry($"LDAP://{ouDn}", _cfg.Provisioning.ServiceAccountUser, _cfg.Provisioning.ServiceAccountPassword);
            de.MoveTo(parent);
            de.CommitChanges();
        }

        private static void Require(bool ok, string msg) { if (!ok) throw new Exception(msg); }

        private void TryAddToGroup(string domain, string sam, string groupCn, List<string>? audit = null)
        {
            if (string.IsNullOrWhiteSpace(groupCn)) return;
            try
            {
                using var ctx = AdminContext(domain);
                var user = FindBySam(ctx, sam); if (user == null) return;
                using var deGroup = new DirectoryEntry($"LDAP://CN={groupCn},{ExpandOu("CN=Users,{domain-components}", domain)}",
                    _cfg.Provisioning.ServiceAccountUser, _cfg.Provisioning.ServiceAccountPassword);
                using var deUser = (DirectoryEntry)user.GetUnderlyingObject();
                var userDn = (string)deUser.Properties["distinguishedName"].Value;
                var members = deGroup.Properties["member"];
                if (!ContainsDn(members, userDn)) { members.Add(userDn); deGroup.CommitChanges(); }
                audit?.Add(groupCn);
            } catch { }
        }

        private void TryRemoveFromGroup(string domain, string sam, string groupCn)
        {
            try
            {
                using var ctx = AdminContext(domain);
                var user = FindBySam(ctx, sam); if (user == null) return;
                using var deGroup = new DirectoryEntry($"LDAP://CN={groupCn},{ExpandOu("CN=Users,{domain-components}", domain)}",
                    _cfg.Provisioning.ServiceAccountUser, _cfg.Provisioning.ServiceAccountPassword);
                using var deUser = (DirectoryEntry)user.GetUnderlyingObject();
                var userDn = (string)deUser.Properties["distinguishedName"].Value;
                var members = deGroup.Properties["member"];
                if (ContainsDn(members, userDn)) { members.Remove(userDn); deGroup.CommitChanges(); }
            } catch { }
        }

        private void TrySetPrimaryGroup(string domain, string sam, string primaryGroupCn)
        {
            try
            {
                using var ctx = AdminContext(domain);
                var user = FindBySam(ctx, sam); if (user == null) return;
                using var deUser = (DirectoryEntry)user.GetUnderlyingObject();
                using var deGroup = new DirectoryEntry($"LDAP://CN={primaryGroupCn},{ExpandOu("CN=Users,{domain-components}", domain)}",
                    _cfg.Provisioning.ServiceAccountUser, _cfg.Provisioning.ServiceAccountPassword);
                var sid = new SecurityIdentifier((byte[])deGroup.Properties["objectSid"].Value, 0);
                var ridStr = sid.ToString().Split('-').Last();
                if (int.TryParse(ridStr, out int rid))
                {
                    deUser.Properties["primaryGroupID"].Value = rid;
                    deUser.CommitChanges();
                }
            } catch { }
        }

        private static bool ContainsDn(PropertyValueCollection members, string dn)
        {
            foreach (var m in members) if (string.Equals(m?.ToString(), dn, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        private static string ToSentenceCase(string? s)
        {
            if (string.IsNullOrWhiteSpace(s)) return string.Empty;
            s = s.Trim();
            return s.Length == 1 ? s.ToUpperInvariant() : char.ToUpperInvariant(s[0]) + s[1..].ToLowerInvariant();
        }
    }
}

