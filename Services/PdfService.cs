
using ADWebManager.Models;
using System.Text;

namespace ADWebManager.Services {
    // Minimal PDF generator to avoid external dependencies (sufficient for a text summary + watermark).
    public class PdfService {
        public byte[] GenerateUserSummaryPdf(CreateUserResult result, string watermark = "Confidential") {
            // Very simple single-page PDF with text. Not for complex layouts.
            var content = new StringBuilder();
            content.AppendLine($"User Creation Summary");
            content.AppendLine($"Domain: {result.Domain}");
            content.AppendLine($"Username: {result.SamAccountName}");
            content.AppendLine($"Display Name: {result.DisplayName}");
            content.AppendLine($"OU: {result.OuCreatedIn}");
            content.AppendLine($"Enabled: {result.Enabled}  Locked: {result.IsLocked}  Expires: {result.ExpirationDate}");
            content.AppendLine($"Groups: {string.Join(\", \", result.GroupsAdded)}");
            content.AppendLine($"Must change password at next logon: {(result.SamAccountName.EndsWith("-a", StringComparison.OrdinalIgnoreCase) ? "No" : "Yes")}");
            content.AppendLine($"Initial Password: {result.InitialPassword}");
            var lines = content.ToString().Split('\n').Select(l => l.TrimEnd()).ToArray();
            return SimplePdf(lines, watermark);
        }

        private byte[] SimplePdf(string[] lines, string watermark) {
            // Basic PDF writer (Type 1 fonts).
            var sb = new StringBuilder();
            sb.Append("%PDF-1.4\n");
            var objects = new List<string>();
            // Font object
            objects.Add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
            // Page content stream
            var content = new StringBuilder();
            content.Append("BT /F1 12 Tf 50 750 Td 14 TL 0 g 0 G\n");
            foreach (var line in lines) {
                content.Append($"({Escape(line)}) Tj T* \n");
            }
            // Watermark
            content.Append("0.75 g 200 400 Td 45 Tz 50 Tr 36 Tf 0.5 G 0 g\n");
            content.Append($"({Escape(watermark)}) Tj\n");
            content.Append("ET");
            var contentBytes = Encoding.ASCII.GetBytes(content.ToString());
            objects.Add(f"<< /Length {contentBytes.Length} >>\nstream\n{content}\nendstream");
            // Resources
            objects.Add("<< /Font << /F1 1 0 R >> >>");
            // Page object
            objects.Add("<< /Type /Page /Parent 5 0 R /Resources 3 0 R /Contents 2 0 R /MediaBox [0 0 612 792] >>");
            // Pages object
            objects.Add("<< /Type /Pages /Kids [4 0 R] /Count 1 >>");
            // Catalog
            objects.Add("<< /Type /Catalog /Pages 5 0 R >>");

            // Build xref
            var xrefPositions = new List<int>();
            foreach (var obj in objects.Select((o, i) => (o, i))) {
                xrefPositions.Add(sb.Length);
                sb.Append($"{obj.i + 1} 0 obj\n{obj.o}\nendobj\n");
            }
            var xrefStart = sb.Length;
            sb.Append("xref\n0 " + (objects.Count + 1) + "\n");
            sb.Append("0000000000 65535 f \n");
            foreach (var pos in xrefPositions) {
                sb.Append(pos.ToString("0000000000") + " 00000 n \n");
            }
            sb.Append("trailer << /Size " + (objects.Count + 1) + " /Root 6 0 R >>\nstartxref\n" + xrefStart + "\n%%EOF");
            return Encoding.ASCII.GetBytes(sb.ToString());
        }

        private static string Escape(string s) => s.Replace("\\", "\\\\").Replace("(", "\\(").Replace(")", "\\)");
    }
}
