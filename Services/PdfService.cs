using System;
using System.IO;
using System.Text;
using ADWebManager.Models;

namespace ADWebManager.Services
{
    // Minimal PDF generator (no external deps). Creates a one-page, monospaced summary.
    public class PdfService
    {
        public byte[] CreateSummary(CreateUserResult r)
        {
            // Build a plain-text body (admin creds intentionally not included)
            var sb = new StringBuilder();
            sb.AppendLine("ACCOUNT CREATION SUMMARY");
            sb.AppendLine("========================");
            sb.AppendLine($"Domain           : {r.Domain}");
            sb.AppendLine($"Username (SAM)   : {r.SamAccountName}");
            sb.AppendLine($"Display Name     : {r.DisplayName}");
            sb.AppendLine($"Mobile Number    : {r.MobileNumber ?? "(not set)"}");
            sb.AppendLine($"OU               : {r.OuCreatedIn}");
            sb.AppendLine($"Enabled / Locked : {(r.Enabled ? "Enabled" : "Disabled")} / {(r.IsLocked ? "Locked" : "Unlocked")}");
            sb.AppendLine($"Expires          : {(r.ExpirationDate.HasValue ? r.ExpirationDate.ToString() : "(none)")}");
            sb.AppendLine($"Groups           : {(r.GroupsAdded != null && r.GroupsAdded.Length>0 ? string.Join(", ", r.GroupsAdded) : "(none)")}");
            sb.AppendLine();
            sb.AppendLine($"Initial Password : {r.InitialPassword}");
            sb.AppendLine();
            sb.AppendLine("Note: Admin (-a) credentials are excluded by policy.");

            return MakeSimplePdf(sb.ToString());
        }

        // Bare-minimum PDF writer for a mono text page
        private static byte[] MakeSimplePdf(string text)
        {
            // Escape parentheses
            string esc(string s) => s.Replace("\\", "\\\\").Replace("(", "\\(").Replace(")", "\\)");
            var lines = esc(text).Replace("\r\n", "\n").Split('\n');

            var content = new StringBuilder();
            float y = 770; // start near top
            content.AppendLine("BT /F1 10 Tf 50 " + y.ToString("0", System.Globalization.CultureInfo.InvariantCulture) + " Td");
            foreach (var line in lines)
            {
                content.AppendLine($"({line}) Tj T*");
            }
            content.AppendLine("ET");
            var contentBytes = Encoding.ASCII.GetBytes(content.ToString());
            var contentLen = contentBytes.Length;

            using var ms = new MemoryStream();
            var w = new StreamWriter(ms, Encoding.ASCII) { NewLine = "\n" };

            w.WriteLine("%PDF-1.4");
            long xrefStart;

            // Objects:
            // 1: Catalog
            // 2: Pages
            // 3: Page
            // 4: Font
            // 5: Content

            var offsets = new long[6];
            void obj(int i, string s)
            {
                w.Flush(); offsets[i] = ms.Position; w.WriteLine($"{i} 0 obj"); w.Write(s); w.WriteLine("\nendobj");
            }

            obj(1, "<< /Type /Catalog /Pages 2 0 R >>");
            obj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
            obj(4, "<< /Type /Font /Subtype /Type1 /Name /F1 /BaseFont /Courier >>");
            obj(5, $"<< /Length {contentLen} >>\nstream\n{Encoding.ASCII.GetString(contentBytes)}endstream");
            obj(3, "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /MediaBox [0 0 595 842] /Contents 5 0 R >>");

            w.Flush();
            xrefStart = ms.Position;
            w.WriteLine("xref");
            w.WriteLine("0 6");
            w.WriteLine("0000000000 65535 f ");
            for (int i = 1; i <= 5; i++)
                w.WriteLine(offsets[i].ToString("0000000000") + " 00000 n ");
            w.WriteLine("trailer << /Size 6 /Root 1 0 R >>");
            w.WriteLine($"startxref");
            w.WriteLine(xrefStart);
            w.WriteLine("%%EOF");
            w.Flush();
            return ms.ToArray();
        }
    }
}
