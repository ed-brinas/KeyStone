using System;
using System.DirectoryServices;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using ADWebManager.Models;
using Microsoft.Extensions.Options;

namespace ADWebManager.Services
{
    public class HealthService
    {
        private readonly AdSettings _cfg;

        public HealthService(IOptions<AdSettings> cfg)
        {
            _cfg = cfg.Value;
        }

        public async Task<HealthReport> GetReportAsync()
        {
            var sw = Stopwatch.StartNew();
            var checkTasks = _cfg.Health.DomainControllers
                .Select(dc => CheckDcAsync(dc))
                .ToList();

            var checks = await Task.WhenAll(checkTasks);

            return new HealthReport
            {
                Timestamp = DateTime.UtcNow,
                OverallDurationMs = sw.ElapsedMilliseconds,
                DcChecks = checks.ToList()
            };
        }

        private Task<DcCheckResult> CheckDcAsync(DcTarget dc)
        {
            return Task.Run(() =>
            {
                var sw = Stopwatch.StartNew();
                var result = new DcCheckResult { Domain = dc.Domain, Host = dc.Host, Status = "FAIL" };
                try
                {
                    using var de = new DirectoryEntry($"LDAP://{dc.Host}", _cfg.Provisioning.ServiceAccountUser, _cfg.Provisioning.ServiceAccountPassword);
                    de.RefreshCache(new[] { "serverName" });

                    result.Status = (sw.ElapsedMilliseconds > _cfg.Health.LdapLatencyCritMs) ? "CRIT"
                                  : (sw.ElapsedMilliseconds > _cfg.Health.LdapLatencyWarnMs) ? "WARN"
                                  : "OK";
                }
                catch (Exception ex)
                {
                    result.Error = ex.Message;
                }
                finally
                {
                    result.DurationMs = sw.ElapsedMilliseconds;
                }
                return result;
            });
        }
    }
}