using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;
using ADWebManager.Models;
using Microsoft.Extensions.Options;

namespace ADWebManager.Services
{
    public class AdService
    {
        private readonly AdSettings _cfg;
        private readonly PasswordService _pwSvc;
        
        public AdService(IOptions<AdSettings> cfg, PasswordService pwSvc)
        {
            _cfg = cfg.Value;
            _pwSvc = pwSvc;
        }

        private PrincipalContext GetPrincipalContext(string domain)
        {
            var d = _cfg.Domains.FirstOrDefault(d => d.Name.Equals(domain, StringComparison.OrdinalIgnoreCase));
            if (d == null) throw new Exception($"Domain '{domain}' not found in configuration.");
            
            return new PrincipalContext(ContextType.Domain, d.Name, d.ServiceAccountUser, d.ServiceAccountPassword);
        }

        public List<UserRow> ListUsers(string domain)
        {
            using var ctx = GetPrincipalContext(domain);
            using var searcher = new PrincipalSearcher(new UserPrincipal(ctx));
            var results = new List<UserRow>();

            foreach (var result in searcher.FindAll())
            {
                if (result is UserPrincipal user)
                {
                    results.Add(new UserRow
                    {
                        Domain = domain,
                        SamAccountName = user.SamAccountName,
                        DisplayName = user.DisplayName,
                        Enabled = user.Enabled ?? false,
                        IsLocked = user.IsAccountLockedOut(),
                        ExpirationDate = user.AccountExpirationDate,
                        IsPrivileged = IsPrivileged(user)
                    });
                }
            }
            return results;
        }
        
        private bool IsPrivileged(UserPrincipal user)
        {
            var highPrivilegeGroups = _cfg.AccessControl.HighPrivilegeGroups.Select(g => g.ToLowerInvariant());
            var userGroups = user.GetGroups().Select(g => g.Name.ToLowerInvariant());
            return userGroups.Any(ug => highPrivilegeGroups.Contains(ug));
        }

        public CreateUserResult CreateUser(CreateUserRequest req, string createdBy)
        {
            using var ctx = GetPrincipalContext(req.Domain);
            var d = _cfg.Domains.First(d => d.Name.Equals(req.Domain, StringComparison.OrdinalIgnoreCase));

            // Create standard user
            var standardUserPrincipal = CreateStandardUser(ctx, d, req, createdBy);

            // Fetch the underlying DirectoryEntry to get fresh properties
            var standardUserDe = (DirectoryEntry)standardUserPrincipal.GetUnderlyingObject();

            // Optionally create privileged user
            if (req.CreatePrivileged)
            {
                CreatePrivilegedUser(ctx, d, req, standardUserPrincipal);
            }
            
            // Generate passwords
            var initialPassword = _pwSvc.Generate();
            var adminInitialPassword = req.CreatePrivileged ? _pwSvc.Generate() : null;
            
            standardUserPrincipal.SetPassword(initialPassword);

            return new CreateUserResult
            {
                Domain = req.Domain,
                SamAccountName = standardUserPrincipal.SamAccountName,
                DisplayName = standardUserPrincipal.DisplayName,
                DistinguishedName = standardUserPrincipal.DistinguishedName,
                OuCreatedIn = d.UserOu,
                Enabled = standardUserPrincipal.Enabled ?? false,
                IsLocked = standardUserPrincipal.IsAccountLockedOut(),
                ExpirationDate = standardUserPrincipal.AccountExpirationDate ?? DateTime.MaxValue,
                MobileNumber = req.MobileNumber,
                InitialPassword = initialPassword,
                AdminInitialPassword = adminInitialPassword,
                HasPrivileged = req.CreatePrivileged,
                GroupsAdded = standardUserPrincipal.GetGroups().Select(g => g.Name).ToArray()
            };
        }

        private UserPrincipal CreateStandardUser(PrincipalContext ctx, AdDomainSettings domain, CreateUserRequest req, string createdBy)
        {
            var user = new UserPrincipal(ctx)
            {
                SamAccountName = req.SamAccountName,
                UserPrincipalName = $"{req.SamAccountName}@{domain.Name}",
                DisplayName = $"{req.FirstName} {req.LastName}",
                GivenName = req.FirstName,
                Surname = req.LastName,
                Description = $"Created by {createdBy} via ADWebManager",
                Enabled = true,
                PasswordNeverExpires = false,
                UserCannotChangePassword = false,
                AccountExpirationDate = req.ExpirationDate?.ToDateTime(TimeOnly.MinValue)
            };
            
            user.Save();

            if (!string.IsNullOrWhiteSpace(req.MobileNumber))
            {
                var de = user.GetUnderlyingObject() as DirectoryEntry;
                de.Properties["mobile"].Value = req.MobileNumber;
                de.CommitChanges();
            }

            foreach (var groupName in req.SelectedGeneralAccessGroups)
            {
                using var group = GroupPrincipal.FindByIdentity(ctx, groupName);
                if (group != null) group.Members.Add(user);
            }
            
            return user;
        }
        
        private void CreatePrivilegedUser(PrincipalContext ctx, AdDomainSettings domain, CreateUserRequest req, UserPrincipal standardUser)
        {
            var adminSam = req.SamAccountName + "-a";
            var adminUser = new UserPrincipal(ctx)
            {
                SamAccountName = adminSam,
                UserPrincipalName = $"{adminSam}@{domain.Name}",
                DisplayName = $"{req.FirstName} {req.LastName} (Admin)",
                GivenName = req.FirstName,
                Surname = req.LastName,
                Description = $"Admin account for {standardUser.SamAccountName}",
                Enabled = true,
                PasswordNeverExpires = true
            };
            
            adminUser.Save();
            adminUser.SetPassword(_pwSvc.Generate());
            
            foreach (var groupName in req.SelectedPrivilegeAccessGroups)
            {
                using var group = GroupPrincipal.FindByIdentity(ctx, groupName);
                if (group != null) group.Members.Add(adminUser);
            }
        }

        public async Task SelfServiceResetPasswordAsync(SelfServiceResetRequest req)
        {
            using var ctx = GetPrincipalContext(req.Domain);
            var user = UserPrincipal.FindByIdentity(ctx, IdentityType.SamAccountName, req.SamAccountName);

            if (user == null) throw new Exception("User not found.");

            var de = user.GetUnderlyingObject() as DirectoryEntry;
            var mobile = de.Properties["mobile"].Value as string;
            var birthDateStr = de.Properties["extensionAttribute1"].Value as string; // Assuming birthdate is stored here in a specific format

            if (string.IsNullOrWhiteSpace(mobile) || !mobile.EndsWith(req.MobileLast4))
                throw new Exception("Mobile number does not match.");
            
            if (string.IsNullOrWhiteSpace(birthDateStr) || !birthDateStr.Equals(req.Birthdate))
                throw new Exception("Birthdate does not match.");

            await Task.Run(() => user.SetPassword(req.NewPassword));
        }

        public void UpdateUser(UpdateUserRequest req, string updatedBy)
        {
            using var ctx = GetPrincipalContext(req.Domain);
            using var user = UserPrincipal.FindByIdentity(ctx, IdentityType.SamAccountName, req.SamAccountName);
            if (user == null) throw new Exception("User not found.");
            
            user.GivenName = req.FirstName;
            user.Surname = req.LastName;
            user.DisplayName = $"{req.FirstName} {req.LastName}";
            user.AccountExpirationDate = req.ExpirationDate?.ToDateTime(TimeOnly.MinValue);
            user.Description = $"Updated by {updatedBy} via ADWebManager";
            
            var de = user.GetUnderlyingObject() as DirectoryEntry;
            de.Properties["mobile"].Value = req.MobileNumber;
            de.CommitChanges();
            
            user.Save();
        }
        
        public void SetPassword(string domain, string sam, string newPassword, bool unlock)
        {
            using var ctx = GetPrincipalContext(domain);
            using var user = UserPrincipal.FindByIdentity(ctx, IdentityType.SamAccountName, sam);
            if (user == null) throw new Exception("User not found.");
            
            if (unlock && user.IsAccountLockedOut()) user.UnlockAccount();
            user.SetPassword(newPassword);
        }
        
        public string ResetPassword(string domain, string sam, bool unlock)
        {
            var newPassword = _pwSvc.Generate();
            SetPassword(domain, sam, newPassword, unlock);
            return newPassword;
        }

        public UserDetails GetUserDetails(string domain, string sam)
        {
            using var ctx = GetPrincipalContext(domain);
            using var user = UserPrincipal.FindByIdentity(ctx, IdentityType.SamAccountName, sam);
            if (user == null) throw new Exception("User not found.");

            var de = user.GetUnderlyingObject() as DirectoryEntry;
            var mobile = de.Properties["mobile"].Value as string;

            return new UserDetails
            {
                Domain = domain,
                SamAccountName = user.SamAccountName,
                DisplayName = user.DisplayName,
                FirstName = user.GivenName,
                LastName = user.Surname,
                MobileNumber = mobile ?? string.Empty,
                Enabled = user.Enabled ?? false,
                IsLocked = user.IsAccountLockedOut(),
                ExpirationDate = user.AccountExpirationDate.HasValue ? DateOnly.FromDateTime(user.AccountExpirationDate.Value) : null,
                Birthdate = null // Logic to retrieve birthdate needs to be implemented
            };
        }
    }
}