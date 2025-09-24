
using System.Collections.Generic;

namespace ADWebManager.Models
{
    public class AdSettings
    {
        public string ForestRootDomain { get; set; } = "";
        public List<string> ForestChildDomain { get; set; } = new();
        public AccessControl AccessControl { get; set; } = new();
        public Provisioning Provisioning { get; set; } = new();

        // Newly surfaced knobs
        public string BirthdateAttribute { get; set; } = "extensionAttribute1";
        public int PrivilegedAccountValidityDays { get; set; } = 30;
        public PasswordPolicy PasswordPolicy { get; set; } = new();
        public SecuritySettings Security { get; set; } = new();
        public AuditSettings Audit { get; set; } = new();
        public HealthSettings Health { get; set; } = new();
    }

    public class AccessControl
    {
        public List<string> GeneralAccessGroups { get; set; } = new();
        public List<string> HighPrivilegeGroups { get; set; } = new();
    }

    public class Provisioning
    {
        public string ServiceAccountUser { get; set; } = "";
        public string ServiceAccountPassword { get; set; } = "";
        public string DefaultUserOuFormat { get; set; } = "";
        public string AdminUserOuFormat { get; set; } = "";
        public List<string> OptionalGeneralAccessGroup { get; set; } = new();
        public List<string> OptionalPrivilegeGroup { get; set; } = new();
        public List<string> SearchBaseOus { get; set; } = new();
    }

    public class PasswordPolicy
    {
        public PolicyBucket Standard { get; set; } = new();
        public PolicyBucket Admin { get; set; } = new();
    }

    public class PolicyBucket
    {
        public int Length { get; set; } = 12;
        public bool IncludeLetters { get; set; } = true;
        public bool IncludeDigits { get; set; } = true;
        public bool IncludeSpecials { get; set; } = true;
        public string AllowedSpecials { get; set; } = "!@#$%^&*()-_=+[]{}";
    }

    public class SecuritySettings
    {
        public CsrfSettings Csrf { get; set; } = new();
        public CookieSettings Cookies { get; set; } = new();
        public SessionSettings Session { get; set; } = new();
    }
    public class CsrfSettings { public bool Enabled { get; set; } = true; public string HeaderName { get; set; } = "X-CSRF-Token"; }
    public class CookieSettings { public string SameSite { get; set; } = "Strict"; public bool Secure { get; set; } = true; public bool HttpOnly { get; set; } = true; }
    public class SessionSettings { public int IdleTimeoutMinutes { get; set; } = 20; public int AbsoluteTimeoutMinutes { get; set; } = 240; public bool DeviceFingerprint { get; set; } = true; }

    public class AuditSettings
    {
        public FileSink LocalFile { get; set; } = new();
        public SyslogSink Syslog { get; set; } = new();
        public CefSink CEF { get; set; } = new();
    }
    public class FileSink { public bool Enabled { get; set; } = true; public string Path { get; set; } = "logs/audit.log"; public string Rolling { get; set; } = "Daily"; }
    public class SyslogSink { public bool Enabled { get; set; } = false; public string Host { get; set; } = "127.0.0.1"; public int Port { get; set; } = 514; public string Protocol { get; set; } = "UDP"; public string Format { get; set; } = "RFC5424"; }
    public class CefSink { public bool Enabled { get; set; } = false; public string Endpoint { get; set; } = ""; }

    public class HealthSettings
    {
        public List<DcTarget> DomainControllers { get; set; } = new();
        public int LdapLatencyWarnMs { get; set; } = 500;
        public int LdapLatencyCritMs { get; set; } = 1500;
        public int ServiceAccountLockoutWarnThreshold { get; set; } = 1;
        public string LogDiskPath { get; set; } = "logs";
        public int LogDiskMinFreeMB { get; set; } = 1024;
    }
    public class DcTarget { public string Domain { get; set; } = ""; public string Host { get; set; } = ""; }
}
