using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using ADWebManager.Models;

namespace ADWebManager.Services
{
    public class PasswordService
    {
        private readonly Policy _std;
        private readonly Policy _adm;
        private readonly HashSet<string> _bannedSha1 = new(StringComparer.OrdinalIgnoreCase);

        private sealed class Policy
        {
            public int Length { get; init; }
            public bool IncludeLetters { get; init; }
            public bool IncludeDigits { get; init; }
            public bool IncludeSpecials { get; init; }
            public string AllowedSpecials { get; init; } = "";
        }

        public PasswordService(IOptions<AdSettings> cfg)
        {
            var ad  = cfg.Value ?? new AdSettings();
            var std = ad.PasswordPolicy?.Standard ?? new PolicyBucket();
            var adm = ad.PasswordPolicy?.Admin    ?? new PolicyBucket();

            _std = new Policy
            {
                Length = Math.Max(1, std.Length),
                IncludeLetters = std.IncludeLetters,
                IncludeDigits  = std.IncludeDigits,
                IncludeSpecials = std.IncludeSpecials,
                AllowedSpecials = std.AllowedSpecials ?? ""
            };
            _adm = new Policy
            {
                Length = Math.Max(1, adm.Length),
                IncludeLetters = adm.IncludeLetters,
                IncludeDigits  = adm.IncludeDigits,
                IncludeSpecials = adm.IncludeSpecials,
                AllowedSpecials = adm.AllowedSpecials ?? ""
            };

            // Optional: environment-based banned list
            var bannedPath = Environment.GetEnvironmentVariable("PASSWORD_BANNED_LIST");
            if (!string.IsNullOrWhiteSpace(bannedPath) && File.Exists(bannedPath))
                LoadBannedList(bannedPath);
        }

        // Back-compat: validates against Standard policy
        public (bool ok, string[] problems) CheckStrength(string password) =>
            ValidateAgainstPolicy(_std, password);

        // New: chooses Admin policy if SAM ends with "-a" (case-insensitive), else Standard
        public (bool ok, string[] problems) CheckStrengthForUser(string samAccountName, string password)
        {
            var policy = samAccountName?.EndsWith("-a", StringComparison.OrdinalIgnoreCase) == true ? _adm : _std;
            return ValidateAgainstPolicy(policy, password);
        }

        private (bool ok, string[] problems) ValidateAgainstPolicy(Policy policy, string password)
        {
            var issues = new List<string>();
            if (string.IsNullOrEmpty(password) || password.Length < policy.Length)
                issues.Add($"Minimum length is {policy.Length}.");

            bool hasLetter = password.Any(char.IsLetter);
            bool hasDigit  = password.Any(char.IsDigit);

            var specials = password.Where(ch => !char.IsLetterOrDigit(ch)).ToArray();
            bool hasAllowedSpecial = specials.Any(ch => policy.AllowedSpecials.Contains(ch));
            bool hasAnyDisallowedSpecial = specials.Any(ch => !policy.AllowedSpecials.Contains(ch));

            if (policy.IncludeLetters && !hasLetter)
                issues.Add("At least one letter is required.");

            if (policy.IncludeDigits && !hasDigit)
                issues.Add("At least one digit is required.");

            if (policy.IncludeSpecials)
            {
                if (policy.AllowedSpecials.Length == 0)
                {
                    if (specials.Length == 0)
                        issues.Add("At least one special character is required.");
                }
                else
                {
                    if (!hasAllowedSpecial)
                        issues.Add($"At least one special character from the allowed set is required: {policy.AllowedSpecials}");
                    if (hasAnyDisallowedSpecial)
                        issues.Add("Contains special characters outside the allowed set.");
                }
            }
            else
            {
                if (policy.AllowedSpecials.Length > 0 && hasAnyDisallowedSpecial)
                    issues.Add("Contains special characters outside the allowed set.");
            }

            if (IsBanned(password))
                issues.Add("This password appears in the banned list.");

            return (issues.Count == 0, issues.ToArray());
        }

        private void LoadBannedList(string path)
        {
            foreach (var line in File.ReadLines(path))
            {
                var p = line.Trim();
                if (p.Length == 0) continue;
                _bannedSha1.Add(Sha1Hex(Encoding.UTF8.GetBytes(p)));
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
