using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using ADWebManager.Models;
using Microsoft.Extensions.Options;

namespace ADWebManager.Services
{
    public class HealthOptions
    {
        /// <summary>Maximum milliseconds considered healthy for a simple LDAP query.</summary>
        public int LdapHealthyMs { get; set; } = 800;

        /// <summary>Warn when free space for the audit logs drive falls below this many megabytes.</summary>
        public long LogFreeSpaceWarnMB { get; set; } = 2048;
    }

    public class HealthService
    {
        private readonly AdOptions _ad;
        private readonly AuditLogOptions _audit;
        private readonly HealthOptions _opts;

        public HealthService(IOptions<AdOptions> ad, IOptions<AuditLogOptions> audit, IOptions<HealthOptions> opts)
        {
            _ad = ad.Value ?? new AdOptions();
            _audit = audit.Value ?? new AuditLogOptions();
            _opts = opts.Value ?? new HealthOptions();
        }

        public HealthReport GetReport()
        {
            var r = new HealthReport
            {
                GeneratedUtc = DateTime.UtcNow,
                Domains = new List<DomainHealth>()
            };

            foreach (var d in _ad.Domains)
            {
                r.Domains.Add(CheckDomain(d));
            }

            r.LogStorage = CheckLogStorage(_audit.Directory);
            return r;
        }

        private DomainHealth CheckDomain(DomainConfig d)
        {
            var dh = new DomainHealth
            {
                Domain = d.Name,
                LdapBaseDn = d.LdapBaseDn
            };

            // --- LDAP latency & bind health ---
            try
            {
                var sw = Stopwatch.StartNew();
                using var root = new DirectoryEntry($"LDAP://{d.LdapBaseDn}", d.ServiceAccountUser, d.ServiceAccountPassword);
                using var ds = new DirectorySearcher(root)
                {
                    Filter = "(objectClass=domain)", SearchScope = SearchScope.Base, PageSize = 1
                };
                ds.PropertiesToLoad.Add("distinguishedName");
                _ = ds.FindOne();
                sw.Stop();

                dh.LdapLatencyMs = sw.ElapsedMilliseconds;
                dh.LdapHealthy = sw.ElapsedMilliseconds <= _opts.LdapHealthyMs;
            }
            catch (Exception ex)
            {
                dh.LdapHealthy = false;
                dh.Error = Shorten(ex.Message);
            }

            // --- Service account status (enabled / locked out) ---
            try
            {
                using var ctx = new PrincipalContext(ContextType.Domain, d.Name, d.ServiceAccountUser, d.ServiceAccountPassword);
                var (idType, idValue) = ParseIdentity(d);
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

        private static (IdentityType type, string value) ParseIdentity(DomainConfig d)
        {
            // d.ServiceAccountUser may be "DOMAIN\\user", or UPN "user@domain"
            var u = d.ServiceAccountUser ?? "";
            if (u.Contains("@")) return (IdentityType.UserPrincipalName, u);
            if (u.Contains("\\")) return (IdentityType.SamAccountName, u.Split('\\').Last());
            return (IdentityType.SamAccountName, u);
        }

        private LogStorageHealth CheckLogStorage(string logDir)
        {
            try
            {
                if (!Directory.Exists(logDir)) Directory.CreateDirectory(logDir);

                var root = Path.GetPathRoot(Path.GetFullPath(logDir)) ?? logDir;
                var di = new DriveInfo(root);

                // Some environments (containers) might not expose DriveInfo – fall back to directory size check if needed.
                var free = di.IsReady ? di.AvailableFreeSpace : 0;
                var total = di.IsReady ? di.TotalSize : 0;
                var warn = free > 0 && (free / (1024 * 1024)) < _opts.LogFreeSpaceWarnMB;

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
