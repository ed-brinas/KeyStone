using System;
using System.Collections.Generic;
using System.Linq;
using ADWebManager.Services;
using Microsoft.Extensions.Options;

namespace ADWebManager.Services
{
    public enum PolicyBucket { Standard, Admin }

    public class PasswordService
    {
        private readonly AdSettings _cfg;

        public PasswordService(IOptions<AdSettings> cfg)
        {
            _cfg = cfg.Value;
        }

        public (bool, IReadOnlyList<string>) CheckStrengthForUser(string sam, string password)
        {
            var isAdmin = sam.EndsWith("-a", StringComparison.OrdinalIgnoreCase);
            var policy = isAdmin ? _cfg.PasswordPolicy?.Admin : _cfg.PasswordPolicy?.Standard;
            var bucket = isAdmin ? PolicyBucket.Admin : PolicyBucket.Standard;

            return CheckStrength(password, bucket);
        }

        public (bool, IReadOnlyList<string>) CheckStrength(string password, PolicyBucket bucket)
        {
            var policy = bucket == PolicyBucket.Admin ? _cfg.PasswordPolicy?.Admin : _cfg.PasswordPolicy?.Standard;
            if (policy == null) return (true, new List<string>()); 

            var problems = new List<string>();
            if (string.IsNullOrEmpty(password) || password.Length < policy.Length)
                problems.Add($"Password must be at least {policy.Length} characters long.");

            if (policy.IncludeLetters && !password.Any(char.IsLetter))
                problems.Add("Password must include letters.");

            if (policy.IncludeDigits && !password.Any(char.IsDigit))
                problems.Add("Password must include digits.");
            
            if (policy.IncludeSpecials)
            {
                var allowed = policy.AllowedSpecials ?? "";
                if (!password.Any(c => allowed.Contains(c)))
                    problems.Add($"Password must include at least one special character: {allowed}");
            }

            return (!problems.Any(), problems);
        }
    }
}
