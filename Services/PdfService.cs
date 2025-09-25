using System;
using System.IO;
using ADWebManager.Models;
using iText.Kernel.Pdf;
using iText.Layout;
using iText.Layout.Element;
using iText.Layout.Properties;
using iText.IO.Font.Constants;

namespace ADWebManager.Services
{
    public class PdfService
    {
        public byte[] CreateSummary(CreateUserResult r)
        {
            using var ms = new MemoryStream();
            using var writer = new PdfWriter(ms);
            using var pdf = new PdfDocument(writer);
            var doc = new Document(pdf);

            doc.Add(new Paragraph("New Account Summary").SetTextAlignment(TextAlignment.CENTER).SetFontSize(20));
            doc.Add(new Paragraph($"Created: {DateTime.Now:yyyy-MM-dd HH:mm:ss}").SetTextAlignment(TextAlignment.CENTER));
            
            var table = new Table(UnitValue.CreatePercentArray(new float[] { 1, 2 })).UseAllAvailableWidth();
            
            table.AddCell(new Cell().Add(new Paragraph("Display Name")));
            table.AddCell(new Cell().Add(new Paragraph(r.DisplayName)));
            table.AddCell(new Cell().Add(new Paragraph("SAM Account Name")));
            table.AddCell(new Cell().Add(new Paragraph(r.SamAccountName)));
            
            if (r.ExpirationDate != DateTime.MaxValue && r.ExpirationDate != DateTime.MinValue)
            {
                table.AddCell(new Cell().Add(new Paragraph("Account Expires")));
                table.AddCell(new Cell().Add(new Paragraph($"{r.ExpirationDate:yyyy-MM-dd}")));
            }

            table.AddCell(new Cell().Add(new Paragraph("Initial Password")));
            table.AddCell(new Cell().Add(new Paragraph(r.InitialPassword).SetFontFamily(StandardFonts.COURIER)));

            if (r.HasPrivileged && !string.IsNullOrWhiteSpace(r.AdminInitialPassword))
            {
                table.AddCell(new Cell().Add(new Paragraph("Admin Account")));
                table.AddCell(new Cell().Add(new Paragraph(r.SamAccountName + "-a")));
                table.AddCell(new Cell().Add(new Paragraph("Admin Password")));
                table.AddCell(new Cell().Add(new Paragraph(r.AdminInitialPassword).SetFontFamily(StandardFonts.COURIER)));
            }
            
            doc.Add(table);
            
            doc.Close();
            return ms.ToArray();
        }
    }
}