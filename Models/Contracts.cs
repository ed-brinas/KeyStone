using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
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
        [Required]
        public string Domain { get; set; } = string.Empty;
        [Required]
        [StringLength(20, MinimumLength = 3)]
        public string SamAccountName { get; set; } = string.Empty;
        [Required]
        public string FirstName { get; set; } = string.Empty;
        [Required]
        public string LastName { get; set; } = string.Empty;
        public DateOnly? Birthdate { get; set; }
        public DateOnly? ExpirationDate { get; set; }
        [Phone]
        public string MobileNumber { get; set; } = string.Empty;
        public bool CreatePrivileged { get; set; }
        public string? SelectedPrivilegedGroupCn { get; set; }
        public bool MakeSelectedPrimary { get; set; }
        public List<string> SelectedGeneralAccessGroups { get; set; } = new();
        public List<string> SelectedPrivilegeAccessGroups { get; set; } = new();
    }
    
    public class UpdateUserRequest
    {
        [Required]
        public string Domain { get; set; } = string.Empty;
        [Required]
        public string SamAccountName { get; set; } = string.Empty;
        [Required]
        public string FirstName { get; set; } = string.Empty;
        [Required]
        public string LastName { get; set; } = string.Empty;
        public DateOnly? Birthdate { get; set; }
        public DateOnly? ExpirationDate { get; set; }
        [Phone]
        public string MobileNumber { get; set; } = string.Empty;
    }

    public class UserDetails : UpdateUserRequest 
    {
        public string DisplayName { get; set; } = string.Empty;
        public bool Enabled { get; set; }
        public bool IsLocked { get; set; }
    }

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
        [Required]
        public string Domain { get; set; } = string.Empty;
        [Required]
        public string SamAccountName { get; set; } = string.Empty;
        [Required]
        public string Birthdate { get; set; } = string.Empty;
        [Required]
        [StringLength(4, MinimumLength = 4)]
        public string MobileLast4 { get; set; } = string.Empty;
        [Required]
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