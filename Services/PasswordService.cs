using System;
using System.Linq;
using System.Text;
using ADWebManager.Models;
using Microsoft.Extensions.Options;

namespace ADWebManager.Services
{
    public class PasswordService
    {
        private readonly AdSettings _cfg;

        public PasswordService(IOptions<AdSettings> cfg)
        {
            _cfg = cfg.Value;
        }

        public string Generate()
        {
            var policy = _cfg.Provisioning.PasswordPolicy.Standard;
            const string lowers = "abcdefghijklmnopqrstuvwxyz";
            const string uppers = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            const string numbers = "0123456789";
            const string symbols = "!@#$%^&*()_+-=[]{}|;':,./<>?";

            var charPool = new StringBuilder();
            if (policy.IncludeLetters) charPool.Append(lowers).Append(uppers);
            if (policy.IncludeDigits) charPool.Append(numbers);
            if (policy.IncludeSpecials) charPool.Append(symbols);
            
            if (charPool.Length == 0) throw new Exception("Password policy is too restrictive to generate a password.");

            var random = new Random();
            var password = new StringBuilder();
            
            for (int i = password.Length; i < policy.Length; i++)
            {
                password.Append(charPool[random.Next(charPool.Length)]);
            }

            return password.ToString();
        }

        public (bool, string[]) CheckStrengthForUser(string sam, string password)
        {
            var policy = _cfg.Provisioning.PasswordPolicy.Standard;
            var problems = new System.Collections.Generic.List<string>();

            if (password.Length < policy.Length) problems.Add($"Password must be at least {policy.Length} characters long.");
            if (policy.IncludeLetters && !password.Any(char.IsLetter)) problems.Add("Password must contain at least one letter.");
            if (policy.IncludeDigits && !password.Any(char.IsDigit)) problems.Add("Password must contain at least one number.");
            if (policy.IncludeSpecials && !password.Any(c => !char.IsLetterOrDigit(c))) problems.Add("Password must contain at least one symbol.");

            return (problems.Count == 0, problems.ToArray());
        }
    }
}