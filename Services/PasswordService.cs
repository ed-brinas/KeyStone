using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace ADWebManager.Services
{
    public class PasswordPolicyOptions
    {
        public int MinLength { get; set; } = 8;
        public bool RequireUpper { get; set; } = true;
        public bool RequireLower { get; set; } = true;
        public bool RequireDigit { get; set; } = true;
        public bool RequireSpecial { get; set; } = true;
        public int HistoryRemember { get; set; } = 5; // advisory (AD enforces actual history)
        public string? LocalBannedListPath { get; set; } // optional (offline)
    }

    public class PasswordService
    {
        private readonly PasswordPolicyOptions _opts;
        private readonly HashSet<string> _bannedSha1 = new(StringComparer.OrdinalIgnoreCase);

        public PasswordService(PasswordPolicyOptions opts)
        {
            _opts = opts ?? new PasswordPolicyOptions();
            LoadBannedList();
        }

        public (bool ok, string[] problems) CheckStrength(string password)
        {
            var issues = new List<string>();
            if (string.IsNullOrEmpty(password) || password.Length < _opts.MinLength) issues.Add($"Minimum length is {_opts.MinLength}.");
            if (_opts.RequireUpper && !password.Any(char.IsUpper)) issues.Add("At least one uppercase letter is required.");
            if (_opts.RequireLower && !password.Any(char.IsLower)) issues.Add("At least one lowercase letter is required.");
            if (_opts.RequireDigit && !password.Any(char.IsDigit)) issues.Add("At least one digit is required.");
            if (_opts.RequireSpecial && !password.Any(ch => !char.IsLetterOrDigit(ch))) issues.Add("At least one special character is required.");
            if (IsBanned(password)) issues.Add("This password appears in the banned list.");
            return (!issues.Any(), issues.ToArray());
        }

        private void LoadBannedList()
        {
            if (string.IsNullOrWhiteSpace(_opts.LocalBannedListPath)) return;
            if (!File.Exists(_opts.LocalBannedListPath)) return;
            foreach (var line in File.ReadLines(_opts.LocalBannedListPath))
            {
                var p = line.Trim();
                if (p.Length == 0) continue;
                var sha1 = Sha1Hex(Encoding.UTF8.GetBytes(p));
                _bannedSha1.Add(sha1);
            }
        }

        private bool IsBanned(string password)
        {
            if (_bannedSha1.Count == 0) return false;
            var sha1 = Sha1Hex(Encoding.UTF8.GetBytes(password));
            return _bannedSha1.Contains(sha1);
        }

        private static string Sha1Hex(byte[] data)
        {
            using var sha1 = SHA1.Create();
            var hash = sha1.ComputeHash(data);
            var sb = new StringBuilder(hash.Length * 2);
            foreach (var b in hash) sb.Append(b.ToString("x2"));
            return sb.ToString();
        }
    }
}
