using System.Text;
using System.Text.RegularExpressions;

namespace ADWebManager.Services
{
    public class PdfService
    {
        // Minimal stub — replace with your real PDF implementation if you have one.
        // This returns a simple PDF-like byte[]; for real PDF, use an on-prem lib you’ve vendored.
        public byte[] GenerateUserSummaryPdf(ADWebManager.Models.CreateUserResult result, string watermark = "Confidential")
        {
            // Text content we want in the PDF
            var sb = new StringBuilder();
            sb.AppendLine("User Summary");
            sb.AppendLine("========================");
            sb.AppendLine($"Domain: {result.Domain}");
            sb.AppendLine($"Username (SAM): {result.SamAccountName}");
            sb.AppendLine($"Display Name: {result.DisplayName}");
            sb.AppendLine($"OU: {result.OuCreatedIn}");
            sb.AppendLine($"Enabled: {result.Enabled}");
            sb.AppendLine($"Locked: {result.IsLocked}");
            sb.AppendLine($"Expires: {(result.ExpirationDate?.ToString("yyyy-MM-dd") ?? "(none)")}");
            sb.AppendLine($"Groups: {string.Join(", ", result.GroupsAdded ?? Array.Empty<string>())}");
            sb.AppendLine($"Must change password at next logon: {(result.SamAccountName.EndsWith("-a", StringComparison.OrdinalIgnoreCase) ? "No" : "Yes")}");
            sb.AppendLine($"Initial Password: {result.InitialPassword}");
            sb.AppendLine();
            sb.AppendLine($"Watermark: {watermark}");

            // For simplicity, return the text as a .txt but label as PDF.
            // In production, render to actual PDF bytes with an offline lib.
            return Encoding.UTF8.GetBytes(sb.ToString());
        }
    }
}
