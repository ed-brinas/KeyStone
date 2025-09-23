namespace ADWebManager.Models
{
    public class DomainConfig
    {
        public string Name { get; set; } = "";
        public string LdapBaseDn { get; set; } = "";
        public string UserOuDn { get; set; } = "";
        public string AdminOuDn { get; set; } = "";     // used for -a accounts
        public string GroupsBaseDn { get; set; } = "";
        public string ServiceAccountUser { get; set; } = "";
        public string ServiceAccountPassword { get; set; } = "";
        public List<string>? StandardGroups { get; set; }
        public List<string>? PrivilegedGroups { get; set; }
        public string? PrivilegedPrimaryGroup { get; set; }
    }

    public class CreateUserRequest
    {
        public string Domain { get; set; } = "";
        public string FirstName { get; set; } = "";
        public string LastName { get; set; } = "";
        public DateOnly? Birthdate { get; set; }
        public DateOnly? ExpirationDate { get; set; }
        public string SamAccountName { get; set; } = "";
        public bool CreatePrivileged { get; set; }
    }

    public class UpdateUserRequest
    {
        public string Domain { get; set; } = "";
        public string SamAccountName { get; set; } = "";
        public string FirstName { get; set; } = "";
        public string LastName { get; set; } = "";
        public DateOnly? Birthdate { get; set; }
        public DateOnly? ExpirationDate { get; set; }
        public bool CreatePrivileged { get; set; }
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
        public string InitialPassword { get; set; } = "";
        public string[] GroupsAdded { get; set; } = Array.Empty<string>();
    }
}
