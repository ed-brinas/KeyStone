
using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using System.Text;
using ADWebManager.Models;

namespace ADWebManager.Services {
    public class PasswordService {
        private readonly PasswordPolicy _policy;
        private const string Specials = "!@#$%^&*()-_=+[]{};:,.<>?";
        public PasswordService(IOptions<AdOptions> opts) {
            _policy = opts.Value.PasswordPolicy ?? new PasswordPolicy();
        }
        public string Generate() {
            var rng = RandomNumberGenerator.Create();
            var chars = new List<char>();
            if (_policy.IncludeUpper) chars.AddRange("ABCDEFGHIJKLMNPQRSTUVWXYZ");
            if (_policy.IncludeLower) chars.AddRange("abcdefghijklmnpqrstuvwxyz");
            if (_policy.IncludeDigit) chars.AddRange("123456789");
            if (_policy.IncludeSpecial) chars.AddRange(Specials);
            if (chars.Count == 0) throw new InvalidOperationException("Password policy has no character sets.");
            var bytes = new byte[_policy.Length];
            rng.GetBytes(bytes);
            var sb = new StringBuilder();
            for (int i = 0; i < bytes.Length; i++) {
                sb.Append(chars[bytes[i] % chars.Count]);
            }
            return sb.ToString();
        }
    }
}
