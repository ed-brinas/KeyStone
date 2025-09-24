using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace ADWebManager.Models
{
    public class SelfServiceResetRequest
    {
        public string Domain { get; set; } = "";
        public string SamAccountName { get; set; } = "";
        public string Birthdate { get; set; } = "";
        public string MobileLast4 { get; set; } = "";
        public string NewPassword { get; set; } = "";
    }

    public class CreateUserRequest
    {
        public string Domain { get; set; } = "";
        public string SamAccountName { get; set; } = "";
        public string FirstName { get; set; } = "";
        public string LastName { get; set; } = "";
        public DateOnly? Birthdate { get; set; }
        public DateOnly? ExpirationDate { get; set; }
        public string MobileNumber { get; set; } = "";
        public bool CreatePrivileged { get; set; }
        public string? SelectedPrivilegedGroupCn { get; set; }
        public bool MakeSelectedPrimary { get; set; }
        public List<string>? SelectedGeneralAccessGroups { get; set; }
        public List<string>? SelectedPrivilegeAccessGroups { get; set; }
    }
    
    public class UpdateUserRequest
    {
        public string Domain { get; set; } = "";
        public string SamAccountName { get; set; } = "";
        public string FirstName { get; set; } = "";
        public string LastName { get; set; } = "";
        public DateOnly? Birthdate { get; set; }
        public DateOnly? ExpirationDate { get; set; }
        public string MobileNumber { get; set; } = "";
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
        public string? AdminInitialPassword { get; set; }
        public bool HasPrivileged { get; set; }
        public string[]? GroupsAdded { get; set; }
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

    public class UserDetails : UserRow
    {
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public DateOnly? Birthdate { get; set; }
        public string? MobileNumber { get; set; }
    }
    
    public class HealthReport
    {
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public List<DcCheckResult> DomainControllerChecks { get; set; } = new();
    }

    public class DcCheckResult
    {
        public string? Name { get; set; }
        public string? Domain { get; set; }
        public bool IsReachable { get; set; }
        public long LatencyMs { get; set; }
        public string? Error { get; set; }
    }
}

