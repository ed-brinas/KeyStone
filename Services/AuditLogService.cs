using System.Text;

namespace ADWebManager.Services
{
    public class AuditOptions
    {
        public string LogDirectory { get; set; } = "logs";
        public int MaxFileSizeMB { get; set; } = 5;
        public int RetainFiles { get; set; } = 20;
    }

    public class AuditEvent
    {
        public DateTime TimestampUtc { get; set; }
        public string Administrator { get; set; } = "";
        public string SourceIp { get; set; } = "";
        public string ActionType { get; set; } = "";
        public string TargetUser { get; set; } = "";
        public string Outcome { get; set; } = "";
        public override string ToString() =>
            $"{TimestampUtc:O}\t{Administrator}\t{SourceIp}\t{ActionType}\t{TargetUser}\t{Outcome}";
    }

    public class AuditLogService
    {
        private readonly AuditOptions _opts;
        private readonly object _lock = new();

        public AuditLogService(Microsoft.Extensions.Options.IOptions<AuditOptions> opts) => _opts = opts.Value;

        public void EnsureReady()
        {
            Directory.CreateDirectory(_opts.LogDirectory);
        }

        private string LogFilePath() => Path.Combine(_opts.LogDirectory, "audit.log");

        public Task WriteAsync(AuditEvent ev)
        {
            lock (_lock)
            {
                Directory.CreateDirectory(_opts.LogDirectory);
                var path = LogFilePath();
                RotateIfNeeded(path);
                File.AppendAllText(path, ev + Environment.NewLine, Encoding.UTF8);
            }
            return Task.CompletedTask;
        }

        private void RotateIfNeeded(string path)
        {
            try
            {
                if (!File.Exists(path)) return;
                var maxBytes = _opts.MaxFileSizeMB * 1024L * 1024L;
                var fi = new FileInfo(path);
                if (fi.Length < maxBytes) return;

                // rotate: audit.log -> audit-YYYYMMDDHHmmss.log
                var ts = DateTime.UtcNow.ToString("yyyyMMddHHmmss");
                var newName = Path.Combine(_opts.LogDirectory, $"audit-{ts}.log");
                File.Move(path, newName);
                // delete older files beyond RetainFiles
                var files = Directory.GetFiles(_opts.LogDirectory, "audit-*.log").OrderByDescending(f => f).ToList();
                foreach (var f in files.Skip(_opts.RetainFiles)) File.Delete(f);
            }
            catch { /* ignore rotation errors */ }
        }

        public string[] ReadTail(int max = 500)
        {
            try
            {
                var path = LogFilePath();
                if (!File.Exists(path)) return Array.Empty<string>();
                var lines = File.ReadAllLines(path, Encoding.UTF8);
                return lines.TakeLast(max).ToArray();
            }
            catch { return Array.Empty<string>(); }
        }
    }
}
