using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.IO;
using System.Linq;
using ADWebManager.Models;
using Microsoft.Extensions.Options;

namespace ADWebManager.Services
{
    public class HealthService
    {
        private readonly AdSettings _cfg;

        public HealthService(IOptions<AdSettings> cfg)
        {
            _cfg = cfg.Value ?? new AdSettings();
        }

        public HealthReport GetReport()
        {
            var r = new HealthReport
            {
                GeneratedUtc = DateTime.UtcNow,
                Domains = new List<DomainHealth>()
            };

            // Group DC targets by domain, then check each host
            var byDomain = (_cfg.Health?.DomainControllers ?? new List<DcTarget>()).GroupBy(dc => dc.Domain, StringComparer.OrdinalIgnoreCase);
            foreach (var g in byDomain)
            {
                foreach (var dc in g)
                    r.Domains.Add(CheckDomain(dc));
            }

            r.LogStorage = CheckLogStorage(_cfg.Health?.LogDiskPath ?? "logs");
            return r;
        }

        private DomainHealth CheckDomain(DcTarget dc)
        {
            var dh = new DomainHealth
            {
                Domain = dc.Domain ?? "",
                Host = dc.Host ?? "",
                LdapBaseDn = ToBaseDn(dc.Domain)
            };

            var saUser = _cfg.Provisioning?.ServiceAccountUser ?? "";
            var saPass = _cfg.Provisioning?.ServiceAccountPassword ?? "";
            var healthyMs = _cfg.Health?.LdapLatencyWarnMs ?? 500; // warn threshold for “healthy”

            // --- LDAP latency & bind health (against the specific DC host if provided) ---
            try
            {
                var ldapPath = string.IsNullOrWhiteSpace(dc.Host)
                    ? $"LDAP://{dh.LdapBaseDn}"
                    : $"LDAP://{dc.Host}/{dh.LdapBaseDn}";

                var sw = Stopwatch.StartNew();
                using var root = new DirectoryEntry(ldapPath, saUser, saPass);
                using var ds = new DirectorySearcher(root)
                {
                    Filter = "(objectClass=domain)",
                    SearchScope = SearchScope.Base,
                    PageSize = 1
                };
                ds.PropertiesToLoad.Add("distinguishedName");
                _ = ds.FindOne();
                sw.Stop();

                dh.LdapLatencyMs = sw.ElapsedMilliseconds;
                dh.LdapHealthy = sw.ElapsedMilliseconds <= healthyMs;
            }
            catch (Exception ex)
            {
                dh.LdapHealthy = false;
                dh.Error = Shorten(ex.Message);
            }

            // --- Service account status (enabled / locked out) ---
            try
            {
                using var ctx = new PrincipalContext(ContextType.Domain, dc.Domain, saUser, saPass);
                var (idType, idValue) = ParseIdentity(saUser);
                using var up = UserPrincipal.FindByIdentity(ctx, idType, idValue);
                if (up != null)
                {
                    dh.ServiceAccountEnabled = up.Enabled ?? true;
                    try { dh.ServiceAccountLockedOut = up.IsAccountLockedOut(); } catch { dh.ServiceAccountLockedOut = null; }
                    dh.ServiceAccountFound = true;
                }
                else
                {
                    dh.ServiceAccountFound = false;
                }
            }
            catch (Exception ex)
            {
                dh.ServiceAccountFound = false;
                dh.Error = string.IsNullOrEmpty(dh.Error) ? Shorten(ex.Message) : dh.Error + " | " + Shorten(ex.Message);
            }

            return dh;
        }

        private LogStorageHealth CheckLogStorage(string logDir)
        {
            try
            {
                if (!Directory.Exists(logDir)) Directory.CreateDirectory(logDir);

                var root = Path.GetPathRoot(Path.GetFullPath(logDir)) ?? logDir;
                var di = new DriveInfo(root);

                var free = di.IsReady ? di.AvailableFreeSpace : 0;
                var total = di.IsReady ? di.TotalSize : 0;

                var minMb = _cfg.Health?.LogDiskMinFreeMB ?? 1024;
                var warn = free > 0 && (free / (1024 * 1024)) < minMb;

                return new LogStorageHealth
                {
                    Path = Path.GetFullPath(logDir),
                    Drive = root,
                    TotalBytes = total,
                    FreeBytes = free,
                    Warning = warn
                };
            }
            catch (Exception ex)
            {
                return new LogStorageHealth
                {
                    Path = logDir,
                    Drive = "(unknown)",
                    TotalBytes = 0,
                    FreeBytes = 0,
                    Warning = true,
                    Error = Shorten(ex.Message)
                };
            }
        }

        private static string ToBaseDn(string domain)
        {
            if (string.IsNullOrWhiteSpace(domain)) return "";
            return string.Join(",", domain.Split('.').Select(part => $"DC={part}"));
        }

        private static (IdentityType type, string value) ParseIdentity(string user)
        {
            var u = user ?? "";
            if (u.Contains("@")) return (IdentityType.UserPrincipalName, u);
            if (u.Contains("\\")) return (IdentityType.SamAccountName, u.Split('\\').Last());
            return (IdentityType.SamAccountName, u);
        }

        private static string Shorten(string s) => string.IsNullOrWhiteSpace(s) ? s : (s.Length > 240 ? s.Substring(0, 240) + "…" : s);
    }

    public class HealthReport
    {
        public DateTime GeneratedUtc { get; set; }
        public List<DomainHealth> Domains { get; set; } = new();
        public LogStorageHealth? LogStorage { get; set; }
    }

    public class DomainHealth
    {
        public string Domain { get; set; } = "";
        public string Host { get; set; } = "";
        public string LdapBaseDn { get; set; } = "";
        public long? LdapLatencyMs { get; set; }
        public bool LdapHealthy { get; set; }
        public bool? ServiceAccountEnabled { get; set; }
        public bool? ServiceAccountLockedOut { get; set; }
        public bool ServiceAccountFound { get; set; }
        public string? Error { get; set; }
    }

    public class LogStorageHealth
    {
        public string Path { get; set; } = "";
        public string Drive { get; set; } = "";
        public long TotalBytes { get; set; }
        public long FreeBytes { get; set; }
        public bool Warning { get; set; }
        public string? Error { get; set; }
    }
}
