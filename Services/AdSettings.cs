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
        public PasswordPolicySettings PasswordPolicy { get; set; } = new();
    }

    public class PasswordPolicySettings
    {
        public int MinLength { get; set; } = 12;
        public int MaxLength { get; set; } = 64;
        public bool RequireUppercase { get; set; } = true;
        public bool RequireLowercase { get; set; } = true;
        public bool RequireNumber { get; set; } = true;
        public bool RequireSymbol { get; set; } = true;
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
}