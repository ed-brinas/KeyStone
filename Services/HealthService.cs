using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices.ActiveDirectory;
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

        public HealthReport GetReport()
        {
            var report = new HealthReport();
            var targets = _cfg.HealthChecks?.DomainControllers ?? new List<DcTarget>();

            foreach (var target in targets)
            {
                var result = new DcCheckResult { Name = target.Name, Domain = target.Domain };
                var stopwatch = new Stopwatch();
                try
                {
                    stopwatch.Start();
                    using var dc = DomainController.FindOne(new DirectoryContext(DirectoryContextType.DirectoryServer, target.Name));
                    result.IsReachable = dc != null;
                    stopwatch.Stop();
                    result.LatencyMs = stopwatch.ElapsedMilliseconds;
                }
                catch (Exception ex)
                {
                    stopwatch.Stop();
                    result.IsReachable = false;
                    result.Error = ex.Message;
                    result.LatencyMs = stopwatch.ElapsedMilliseconds;
                }
                report.DomainControllerChecks.Add(result);
            }
            return report;
        }
    }
}
