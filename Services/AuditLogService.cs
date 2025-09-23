
using ADWebManager.Models;
using Microsoft.Extensions.Options;
using System.Text;

namespace ADWebManager.Services {
    public class AuditEvent {
        public DateTime TimestampUtc { get; set; }
        public string Administrator { get; set; } = "";
        public string SourceIp { get; set; } = "";
        public string ActionType { get; set; } = "";
        public string TargetUser { get; set; } = "";
        public string Outcome { get; set; } = "";
        public override string ToString() =>
            $"{TimestampUtc:O},{Escape(Administrator)},{Escape(SourceIp)},{Escape(ActionType)},{Escape(TargetUser)},{Escape(Outcome)}";
        private static string Escape(string s) => "\"" + (s ?? "").Replace("\"", "\"\"") + "\"";
    }

    public class AuditLogService {
        private readonly AuditOptions _opts;
        private readonly object _sync = new();
        public AuditLogService(IOptions<AuditOptions> opts) {
            _opts = opts.Value;
        }
        public void EnsureReady() {
            Directory.CreateDirectory(_opts.LogDirectory);
        }
        private string CurrentFilePath {
            get {
                var date = DateTime.UtcNow.ToString("yyyyMMdd");
                return Path.Combine(_opts.LogDirectory, $"audit_{date}.csv");
            }
        }
        public async Task WriteAsync(AuditEvent e) {
            var line = e.ToString() + Environment.NewLine;
            lock (_sync) {
                File.AppendAllText(CurrentFilePath, line, Encoding.UTF8);
                RotateIfNeeded();
            }
            await Task.CompletedTask;
        }
        public string[] ReadTail(int maxLines) {
            var files = Directory.GetFiles(_opts.LogDirectory, "audit_*.csv").OrderBy(f => f).ToList();
            var lines = new List<string>();
            for (int i = files.Count - 1; i >= 0 && lines.Count < maxLines; i--) {
                var fileLines = File.ReadAllLines(files[i]);
                for (int j = fileLines.Length - 1; j >= 0 && lines.Count < maxLines; j--) {
                    lines.Add(fileLines[j]);
                }
            }
            lines.Reverse();
            return lines.ToArray();
        }
        private void RotateIfNeeded() {
            var file = CurrentFilePath;
            if (new FileInfo(file).Length > _opts.MaxFileSizeMB * 1024L * 1024L) {
                var ts = DateTime.UtcNow.ToString("HHmmss");
                var rotated = file.Replace(".csv", $"_{ts}.csv");
                File.Move(file, rotated);
                var files = Directory.GetFiles(_opts.LogDirectory, "audit_*.csv")
                    .OrderByDescending(f => File.GetCreationTimeUtc(f)).ToList();
                if (files.Count > _opts.RetainFiles) {
                    foreach (var f in files.Skip(_opts.RetainFiles)) {
                        try { File.Delete(f); } catch { }
                    }
                }
            }
        }
    }
}
