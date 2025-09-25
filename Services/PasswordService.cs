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
            var policy = _cfg.Provisioning.PasswordPolicy;
            const string lowers = "abcdefghijklmnopqrstuvwxyz";
            const string uppers = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            const string numbers = "0123456789";
            const string symbols = "!@#$%^&*()_+-=[]{}|;':,./<>?";

            var charPool = new StringBuilder();
            if (policy.RequireLowercase) charPool.Append(lowers);
            if (policy.RequireUppercase) charPool.Append(uppers);
            if (policy.RequireNumber) charPool.Append(numbers);
            if (policy.RequireSymbol) charPool.Append(symbols);
            
            if (charPool.Length == 0) throw new Exception("Password policy is too restrictive to generate a password.");

            var random = new Random();
            var password = new StringBuilder();
            
            // Ensure at least one of each required character type
            if (policy.RequireLowercase) password.Append(lowers[random.Next(lowers.Length)]);
            if (policy.RequireUppercase) password.Append(uppers[random.Next(uppers.Length)]);
            if (policy.RequireNumber) password.Append(numbers[random.Next(numbers.Length)]);
            if (policy.RequireSymbol) password.Append(symbols[random.Next(symbols.Length)]);

            // Fill the rest of the password length
            for (int i = password.Length; i < policy.MinLength; i++)
            {
                password.Append(charPool[random.Next(charPool.Length)]);
            }

            // Shuffle the password to randomize character positions
            return new string(password.ToString().ToCharArray().OrderBy(c => random.Next()).ToArray());
        }

        public (bool, string[]) CheckStrengthForUser(string sam, string password)
        {
            // This is a placeholder for a real strength check.
            // In a real application, you would check against the domain's actual password policy.
            var policy = _cfg.Provisioning.PasswordPolicy;
            var problems = new System.Collections.Generic.List<string>();

            if (password.Length < policy.MinLength) problems.Add($"Password must be at least {policy.MinLength} characters long.");
            if (policy.RequireUppercase && !password.Any(char.IsUpper)) problems.Add("Password must contain at least one uppercase letter.");
            if (policy.RequireLowercase && !password.Any(char.IsLower)) problems.Add("Password must contain at least one lowercase letter.");
            if (policy.RequireNumber && !password.Any(char.IsDigit)) problems.Add("Password must contain at least one number.");
            if (policy.RequireSymbol && !password.Any(c => !char.IsLetterOrDigit(c))) problems.Add("Password must contain at least one symbol.");

            return (problems.Count == 0, problems.ToArray());
        }
    }
}