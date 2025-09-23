using System;

namespace ADWebManager.Models
{
    public class DomainConfig
    {
        public string Name { get; set; } = "";              // e.g., "lab.local"
        public string LdapBaseDn { get; set; } = "";        // e.g., "DC=lab,DC=local"
        public string UserOuDn { get; set; } = "";          // e.g., "OU=Users,DC=lab,DC=local"
        public string AdminOuDn { get; set; } = "";         // e.g., "OU=Admins,DC=lab,DC=local"
        public string GroupsBaseDn { get; set; } = "";      // e.g., "OU=Groups,DC=lab,DC=local"

        public string ServiceAccountUser { get; set; } = "";     // DOMAIN\\svcAccount or UPN
        public string ServiceAccountPassword { get; set; } = ""; // password

        public string[]? StandardGroups { get; set; }
        public string[]? PrivilegedGroups { get; set; }
        public string? PrivilegedPrimaryGroup { get; set; }  // CN of primary group for -a accounts
    }

    public class CreateUserRequest
    {
        public string Domain { get; set; } = "";
        public string FirstName { get; set; } = "";
        public string LastName { get; set; } = "";
        public DateOnly? Birthdate { get; set; }             // stored in configured attribute, e.g., extensionAttribute1
        public DateOnly? ExpirationDate { get; set; }
        public string SamAccountName { get; set; } = "";
        public string? MobileNumber { get; set; }            // AD "mobile"
        public bool CreatePrivileged { get; set; }           // also create <sam>-a
    }

    public class UpdateUserRequest
    {
        public string Domain { get; set; } = "";
        public string SamAccountName { get; set; } = "";
        public string FirstName { get; set; } = "";
        public string LastName { get; set; } = "";
        public DateOnly? Birthdate { get; set; }
        public DateOnly? ExpirationDate { get; set; }
        public string? MobileNumber { get; set; }            // AD "mobile"
        public bool CreatePrivileged { get; set; }           // (present for parity; ignored by update)
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

        public string InitialPassword { get; set; } = "";           // 12-char (regular)
        public string? AdminInitialPassword { get; set; } = null;    // 8-char (admin -a), if created
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
        public string Birthdate { get; set; } = "";       // "yyyy-MM-dd"
        public string? MobileLast4 { get; set; }          // last 4 digits of mobile
        public string NewPassword { get; set; } = "";
    }
}
