namespace ADWebManager.Models;

// ---------- Self-Service ----------
public record SelfServiceResetRequest(string Domain, string SamAccountName, string Birthdate, string MobileLast4, string NewPassword);

// ---------- Admin - User Management ----------
public record CreateUserRequest(
    string Domain,
    string SamAccountName,
    string FirstName,
    string LastName,
    DateOnly? Birthdate,
    DateOnly? ExpirationDate,
    string MobileNumber,
    bool CreatePrivileged,
    string? SelectedPrivilegedGroupCn,
    bool MakeSelectedPrimary,
    string[] SelectedGeneralAccessGroups,
    string[] SelectedPrivilegeAccessGroups
);

public record CreateUserResult
{
    public string Domain { get; set; } = string.Empty;
    public string SamAccountName { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string DistinguishedName { get; set; } = string.Empty;
    public string OuCreatedIn { get; set; } = string.Empty;
    public bool Enabled { get; set; }
    public bool IsLocked { get; set; }
    public DateTime? ExpirationDate { get; set; }
    public string? MobileNumber { get; set; }
    public string InitialPassword { get; set; } = string.Empty;
    public string? AdminInitialPassword { get; set; }
    public bool HasPrivileged { get; set; }
    public string[]? GroupsAdded { get; set; }
}

public record UpdateUserRequest(
    string Domain,
    string SamAccountName,
    string FirstName,
    string LastName,
    DateOnly? Birthdate,
    DateOnly? ExpirationDate,
    string MobileNumber
);

public record UserRow
{
    public string Domain { get; set; } = string.Empty;
    public string SamAccountName { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public bool Enabled { get; set; }
    public bool IsLocked { get; set; }
    public DateTime? ExpirationDate { get; set; }
    public bool IsPrivileged { get; set; }
}

public record UserDetails
{
    public string Domain { get; set; } = string.Empty;
    public string SamAccountName { get; set; } = string.Empty;
    public string FirstName { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;
    public string? MobileNumber { get; set; }
    public string? Birthdate { get; set; } // Using string for yyyy-MM-dd format
    public DateTime? ExpirationDate { get; set; }
}
