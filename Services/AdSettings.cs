using System.Collections.Generic;

namespace ADWebManager.Services
{
    public class AdSettings
    {
        public string? ForestRootDomain { get; set; }
        public List<string>? ForestChildDomain { get; set; }
        public SecuritySettings? Security { get; set; }
        public ProvisioningSettings? Provisioning { get; set; }
        public PasswordPolicy? PasswordPolicy { get; set; }
        public HealthCheckSettings? HealthChecks { get; set; }
        public AuditSettings? Audit { get; set; }
        public string? BirthdateAttribute { get; set; }
        public int PrivilegedAccountValidityDays { get; set; } = 90;
    }

    public class SecuritySettings
    {
        public SessionSettings? Session { get; set; }
        public List<string>? GeneralAccessGroups { get; set; }
        public List<string>? HighPrivilegeGroups { get; set; }
    }

    public class SessionSettings
    {
        public int IdleTimeoutMinutes { get; set; } = 30;
        public int AbsoluteTimeoutMinutes { get; set; } = 240;
    }

    public class ProvisioningSettings
    {
        public string? ServiceAccountUser { get; set; }
        public string? ServiceAccountPassword { get; set; }
        public string? DefaultUserOuFormat { get; set; }
        public string? AdminUserOuFormat { get; set; }
        public List<string>? SearchBaseOus { get; set; }
        public List<string>? OptionalGeneralAccessGroup { get; set; }
        public List<string>? OptionalPrivilegeGroup { get; set; }
    }

    public class PasswordPolicy
    {
        public PasswordPolicyDetail? Standard { get; set; }
        public PasswordPolicyDetail? Admin { get; set; }
    }

    public class PasswordPolicyDetail
    {
        public int Length { get; set; }
        public bool IncludeLetters { get; set; }
        public bool IncludeDigits { get; set; }
        public bool IncludeSpecials { get; set; }
        public string? AllowedSpecials { get; set; }
    }

    public class HealthCheckSettings
    {
        public List<DcTarget>? DomainControllers { get; set; }
    }

    public class DcTarget
    {
        public string? Name { get; set; }
        public string? Domain { get; set; }
    }
    
    public class AuditSettings
    {
        public AuditFileSettings? LocalFile { get; set; }
    }

    public class AuditFileSettings
    {
        public string? Path { get; set; }
    }
}

