namespace ADWebManager.Services
{
    public class AdSettings
    {
        public string ForestRootDomain { get; set; } = string.Empty;
        public List<string> ForestChildDomain { get; set; } = new();
        public List<AdDomainSettings> Domains { get; set; } = new();
        public AdProvisioningSettings Provisioning { get; set; } = new();
        public AdAccessControlSettings AccessControl { get; set; } = new();
        public AdHealthSettings Health { get; set; } = new();
        public AdSecuritySettings Security { get; set; } = new();
        public AdAuditSettings Audit { get; set; } = new();
        public string? BirthdateAttribute { get; set; }
        public int PrivilegedAccountValidityDays { get; set; } = 90;
    }

    public class AdDomainSettings
    {
        public string Name { get; set; } = string.Empty;
        public string ServiceAccountUser { get; set; } = string.Empty;
        public string ServiceAccountPassword { get; set; } = string.Empty;
        public string UserOu { get; set; } = string.Empty;
    }

    public class AdProvisioningSettings
    {
        public string ServiceAccountUser { get; set; } = string.Empty;
        public string ServiceAccountPassword { get; set; } = string.Empty;
        public List<string> OptionalGeneralAccessGroup { get; set; } = new();
        public List<string> OptionalPrivilegeGroup { get; set; } = new();
        public string DefaultUserOuFormat { get; set; } = string.Empty;
        public string AdminUserOuFormat { get; set; } = string.Empty;
        public List<string> SearchBaseOus { get; set; } = new();
        public PasswordPolicy PasswordPolicy { get; set; } = new();
    }

    public class AdAccessControlSettings
    {
        public List<string> GeneralAccessGroups { get; set; } = new();
        public List<string> HighPrivilegeGroups { get; set; } = new();
    }

    public class AdHealthSettings
    {
        public int LdapLatencyWarnMs { get; set; } = 100;
        public int LdapLatencyCritMs { get; set; } = 500;
        public List<DcTarget> DomainControllers { get; set; } = new();
    }
    
    public class DcTarget
    {
        public string Domain { get; set; } = string.Empty;
        public string Host { get; set; } = string.Empty;
    }

    public class AdSecuritySettings
    {
        public SessionSettings Session { get; set; } = new();
    }
    
    public class SessionSettings
    {
        public int IdleTimeoutMinutes { get; set; } = 20;
        public int AbsoluteTimeoutMinutes { get; set; } = 240;
    }
    
    public class AdAuditSettings
    {
        public AuditFileSettings LocalFile { get; set; } = new();
    }

    public class AuditFileSettings
    {
        public string Path { get; set; } = string.Empty;
    }
    
    public class PasswordPolicy
    {
        public PasswordPolicyDetail Standard { get; set; } = new();
        public PasswordPolicyDetail Admin { get; set; } = new();
    }

    public class PasswordPolicyDetail
    {
        public int Length { get; set; } = 14;
        public bool IncludeLetters { get; set; } = true;
        public bool IncludeDigits { get; set; } = true;
        public bool IncludeSpecials { get; set; } = true;
        public string AllowedSpecials { get; set; } = "!@#$%^&*()";
    }
}