namespace ADWebManager.Services
{
    public class AdSettings
    {
        public string ForestRootDomain { get; set; } = string.Empty;
        public List<string> ForestChildDomain { get; set; } = new();
        public AccessControlSettings AccessControl { get; set; } = new();
        public ProvisioningSettings Provisioning { get; set; } = new();
        public string BirthdateAttribute { get; set; } = string.Empty;
        public int PrivilegedAccountValidityDays { get; set; }
        public PasswordPolicy PasswordPolicy { get; set; } = new();
        public SecuritySettings Security { get; set; } = new();
        public AuditSettings Audit { get; set; } = new();
        public HealthCheckSettings Health { get; set; } = new();
    }

    public class AccessControlSettings
    {
        public List<string> GeneralAccessGroups { get; set; } = new();
        public List<string> HighPrivilegeGroups { get; set; } = new();
    }

    public class ProvisioningSettings
    {
        public string ServiceAccountUser { get; set; } = string.Empty;
        public string ServiceAccountPassword { get; set; } = string.Empty;
        public string DefaultUserOuFormat { get; set; } = string.Empty;
        public string AdminUserOuFormat { get; set; } = string.Empty;
        public List<string> OptionalGeneralAccessGroup { get; set; } = new();
        public List<string> OptionalPrivilegeGroup { get; set; } = new();
        public List<string> SearchBaseOus { get; set; } = new();
    }

    public class PasswordPolicy
    {
        public PolicyDetails Standard { get; set; } = new();
        public PolicyDetails Admin { get; set; } = new();
    }

    public class PolicyDetails
    {
        public int Length { get; set; }
        public bool IncludeLetters { get; set; }
        public bool IncludeDigits { get; set; }
        public bool IncludeSpecials { get; set; }
        public string AllowedSpecials { get; set; } = string.Empty;
    }

    public class SecuritySettings
    {
        public CsrfSettings Csrf { get; set; } = new();
        public CookieSettings Cookies { get; set; } = new();
        public SessionSettings Session { get; set; } = new();
    }

    public class CsrfSettings
    {
        public bool Enabled { get; set; }
        public string HeaderName { get; set; } = string.Empty;
    }

    public class CookieSettings
    {
        public string SameSite { get; set; } = string.Empty;
        public bool Secure { get; set; }
        public bool HttpOnly { get; set; }
    }
    
    public class SessionSettings
    {
        public int IdleTimeoutMinutes { get; set; }
        public int AbsoluteTimeoutMinutes { get; set; }
        public bool DeviceFingerprint { get; set; }
    }

    public class AuditSettings
    {
        public LocalFileAuditSettings LocalFile { get; set; } = new();
        public SyslogAuditSettings Syslog { get; set; } = new();
        public CefAuditSettings CEF { get; set; } = new();
    }

    public class LocalFileAuditSettings
    {
        public bool Enabled { get; set; }
        public string Path { get; set; } = string.Empty;
        public string Rolling { get; set; } = string.Empty;
    }

    public class SyslogAuditSettings
    {
        public bool Enabled { get; set; }
        public string Host { get; set; } = string.Empty;
        public int Port { get; set; }
        public string Protocol { get; set; } = string.Empty;
        public string Format { get; set; } = string.Empty;
    }

    public class CefAuditSettings
    {
        public bool Enabled { get; set; }
        public string Endpoint { get; set; } = string.Empty;
    }
    
    public class HealthCheckSettings
    {
        public List<DcTarget> DomainControllers { get; set; } = new();
        public int LdapLatencyWarnMs { get; set; }
        public int LdapLatencyCritMs { get; set; }
    }

    public class DcTarget
    {
        public string Domain { get; set; } = string.Empty;
        public string Host { get; set; } = string.Empty;
    }
}