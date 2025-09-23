using System;
using System.Collections.Concurrent;
using System.IO;
using System.Text;

namespace ADWebManager.Services
{
    public class AuditLogOptions
    {
        public string Directory { get; set; } = "logs";
        public int InMemoryEntries { get; set; } = 500;
    }

    public class AuditLogService
    {
        private readonly AuditLogOptions _opts;
        private readonly ConcurrentQueue<string> _buffer = new();

        public AuditLogService(AuditLogOptions opts)
        {
            _opts = opts ?? new AuditLogOptions();
            if (!System.IO.Directory.Exists(_opts.Directory)) System.IO.Directory.CreateDirectory(_opts.Directory);
        }

        public void Write(string actor, string action, string target, bool success, string? details = null, string? remoteIp = null)
        {
            var line = $"{DateTime.UtcNow:O}\t{actor}\t{remoteIp ?? "-"}\t{action}\t{target}\t{(success ? "OK" : "FAIL")}\t{details ?? "-"}";
            _buffer.Enqueue(line);
            while (_buffer.Count > _opts.InMemoryEntries && _buffer.TryDequeue(out _)) { /* trim */ }

            var file = Path.Combine(_opts.Directory, $"audit-{DateTime.UtcNow:yyyyMMdd}.log");
            File.AppendAllText(file, line + Environment.NewLine, Encoding.UTF8);
        }

        public string[] Tail() => _buffer.ToArray();
    }
}
