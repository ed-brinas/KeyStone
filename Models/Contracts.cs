using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace ADWebManager.Models
{
    public class UserRow
    {
        public string Domain { get; set; } = string.Empty;
        public string SamAccountName { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public bool Enabled { get; set; }
        public bool IsLocked { get; set; }
        public DateTime? ExpirationDate { get; set; }
        public bool IsPrivileged { get; set; }
    }

    public class CreateUserRequest
    {
        public string Domain { get; set; } = string.Empty;
        public string SamAccountName { get; set; } = string.Empty;
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public DateOnly? Birthdate { get; set; }
        public DateOnly? ExpirationDate { get; set; }
        public string MobileNumber { get; set; } = string.Empty;
        public bool CreatePrivileged { get; set; }
        public string? SelectedPrivilegedGroupCn { get; set; }
        public bool MakeSelectedPrimary { get; set; }
        public List<string> SelectedGeneralAccessGroups { get; set; } = new();
        public List<string> SelectedPrivilegeAccessGroups { get; set; } = new();
    }
    
    public class UpdateUserRequest
    {
        public string Domain { get; set; } = string.Empty;
        public string SamAccountName { get; set; } = string.Empty;
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public DateOnly? Birthdate { get; set; }
        public DateOnly? ExpirationDate { get; set; }
        public string MobileNumber { get; set; } = string.Empty;
    }

    public class UserDetails : UpdateUserRequest { }

    public class CreateUserResult
    {
        public string Domain { get; set; } = string.Empty;
        public string SamAccountName { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public string DistinguishedName { get; set; } = string.Empty;
        public string OuCreatedIn { get; set; } = string.Empty;
        public bool Enabled { get; set; }
        public bool IsLocked { get; set; }
        public DateTime ExpirationDate { get; set; }
        public string MobileNumber { get; set; } = string.Empty;
        public string InitialPassword { get; set; } = string.Empty;
        public string? AdminInitialPassword { get; set; }
        public bool HasPrivileged { get; set; }
        public string[] GroupsAdded { get; set; } = Array.Empty<string>();
    }

    public class SelfServiceResetRequest
    {
        public string Domain { get; set; } = string.Empty;
        public string SamAccountName { get; set; } = string.Empty;
        public string Birthdate { get; set; } = string.Empty;
        public string MobileLast4 { get; set; } = string.Empty;
        public string NewPassword { get; set; } = string.Empty;
    }

    public class HealthReport
    {
        public DateTime Timestamp { get; set; }
        public long OverallDurationMs { get; set; }
        public List<DcCheckResult> DcChecks { get; set; } = new();
    }

    public class DcCheckResult
    {
        public string Domain { get; set; } = string.Empty;
        public string Host { get; set; } = string.Empty;
        public string Status { get; set; } = string.Empty;
        public long DurationMs { get; set; }
        public string? Error { get; set; }
    }
}

