using System;

namespace ADWebManager.Models
{
    public class DomainConfig
    {
        public string Name { get; set; } = "";
        public string LdapBaseDn { get; set; } = "";
        public string UserOuDn { get; set; } = "";
        public string AdminOuDn { get; set; } = "";
        public string GroupsBaseDn { get; set; } = "";
        public string ServiceAccountUser { get; set; } = "";
        public string ServiceAccountPassword { get; set; } = "";

        public string[]? StandardGroups { get; set; }
        public string[]? PrivilegedGroups { get; set; }   // list of candidate privileged groups for UI
        public string? PrivilegedPrimaryGroup { get; set; } // (fallback) default if UI doesn't choose
    }

    public class CreateUserRequest
    {
        public string Domain { get; set; } = "";
        public string FirstName { get; set; } = "";
        public string LastName { get; set; } = "";
        public DateOnly? Birthdate { get; set; }
        public DateOnly? ExpirationDate { get; set; }
        public string SamAccountName { get; set; } = "";
        public string? MobileNumber { get; set; }
        public bool CreatePrivileged { get; set; }

        // NEW: privileged group selection at creation time
        public string? SelectedPrivilegedGroupCn { get; set; } // e.g. "Domain Admins"
        public bool MakeSelectedPrimary { get; set; } = false; // if true and -a is created, set as primary
    }

    public class UpdateUserRequest
    {
        public string Domain { get; set; } = "";
        public string SamAccountName { get; set; } = "";
        public string FirstName { get; set; } = "";
        public string LastName { get; set; } = "";
        public DateOnly? Birthdate { get; set; }
        public DateOnly? ExpirationDate { get; set; }
        public string? MobileNumber { get; set; }
        public bool CreatePrivileged { get; set; }           // kept for parity (ignored by update)
    }

    public class CreateUserResult
    {
        public string Domain { get; set; } = "";
        public string SamAccountName { get; set; } = "";
        public string DisplayName { get; set; } = "";
        public string DistinguishedName { get; set; } = "";
        public string OuCreatedIn { get; set; } = "";
        public bool Enabled { get; set; }
        public bool IsLocked { get; set; }
        public DateTime? ExpirationDate { get; set; }
        public string? MobileNumber { get; set; }

        public string InitialPassword { get; set; } = "";
        public string? AdminInitialPassword { get; set; } = null;
        public bool HasPrivileged { get; set; }
        public string[] GroupsAdded { get; set; } = Array.Empty<string>();
    }

    public class UserRow
    {
        public string Domain { get; set; } = "";
        public string SamAccountName { get; set; } = "";
        public string DisplayName { get; set; } = "";
        public bool Enabled { get; set; }
        public bool IsLocked { get; set; }
        public DateTime? ExpirationDate { get; set; }
        public bool IsPrivileged { get; set; }
    }

    public class SelfServiceResetRequest
    {
        public string Domain { get; set; } = "";
        public string SamAccountName { get; set; } = "";
        public string Birthdate { get; set; } = ""; // yyyy-MM-dd
        public string? MobileLast4 { get; set; }
        public string NewPassword { get; set; } = "";
    }
}
using System;

namespace ADWebManager.Models
{
    public class DomainConfig
    {
        public string Name { get; set; } = "";
        public string LdapBaseDn { get; set; } = "";
        public string UserOuDn { get; set; } = "";
        public string AdminOuDn { get; set; } = "";
        public string GroupsBaseDn { get; set; } = "";
        public string ServiceAccountUser { get; set; } = "";
        public string ServiceAccountPassword { get; set; } = "";

        public string[]? StandardGroups { get; set; }
        public string[]? PrivilegedGroups { get; set; }   // list of candidate privileged groups for UI
        public string? PrivilegedPrimaryGroup { get; set; } // (fallback) default if UI doesn't choose
    }

    public class CreateUserRequest
    {
        public string Domain { get; set; } = "";
        public string FirstName { get; set; } = "";
        public string LastName { get; set; } = "";
        public DateOnly? Birthdate { get; set; }
        public DateOnly? ExpirationDate { get; set; }
        public string SamAccountName { get; set; } = "";
        public string? MobileNumber { get; set; }
        public bool CreatePrivileged { get; set; }

        // NEW: privileged group selection at creation time
        public string? SelectedPrivilegedGroupCn { get; set; } // e.g. "Domain Admins"
        public bool MakeSelectedPrimary { get; set; } = false; // if true and -a is created, set as primary
    }

    public class UpdateUserRequest
    {
        public string Domain { get; set; } = "";
        public string SamAccountName { get; set; } = "";
        public string FirstName { get; set; } = "";
        public string LastName { get; set; } = "";
        public DateOnly? Birthdate { get; set; }
        public DateOnly? ExpirationDate { get; set; }
        public string? MobileNumber { get; set; }
        public bool CreatePrivileged { get; set; }           // kept for parity (ignored by update)
    }

    public class CreateUserResult
    {
        public string Domain { get; set; } = "";
        public string SamAccountName { get; set; } = "";
        public string DisplayName { get; set; } = "";
        public string DistinguishedName { get; set; } = "";
        public string OuCreatedIn { get; set; } = "";
        public bool Enabled { get; set; }
        public bool IsLocked { get; set; }
        public DateTime? ExpirationDate { get; set; }
        public string? MobileNumber { get; set; }

        public string InitialPassword { get; set; } = "";
        public string? AdminInitialPassword { get; set; } = null;
        public bool HasPrivileged { get; set; }
        public string[] GroupsAdded { get; set; } = Array.Empty<string>();
    }

    public class UserRow
    {
        public string Domain { get; set; } = "";
        public string SamAccountName { get; set; } = "";
        public string DisplayName { get; set; } = "";
        public bool Enabled { get; set; }
        public bool IsLocked { get; set; }
        public DateTime? ExpirationDate { get; set; }
        public bool IsPrivileged { get; set; }
    }

    public class SelfServiceResetRequest
    {
        public string Domain { get; set; } = "";
        public string SamAccountName { get; set; } = "";
        public string Birthdate { get; set; } = ""; // yyyy-MM-dd
        public string? MobileLast4 { get; set; }
        public string NewPassword { get; set; } = "";
    }
}
