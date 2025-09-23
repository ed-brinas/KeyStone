using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.Extensions.Options;
using ADWebManager.Services;
using ADWebManager.Models;

var builder = WebApplication.CreateBuilder(args);

// Windows Auth (IIS/Negotiate) – adjust if you use a different scheme
builder.Services.AddAuthentication(NegotiateDefaults.AuthenticationScheme).AddNegotiate();
builder.Services.AddAuthorization(options =>
{
    options.FallbackPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
});

// Options & Services
builder.Services.Configure<AdOptions>(builder.Configuration.GetSection("AD"));
builder.Services.Configure<AuditOptions>(builder.Configuration.GetSection("Audit"));

builder.Services.AddSingleton<IPasswordGenerator, DefaultPasswordGenerator>();
builder.Services.AddSingleton<AdService>();
builder.Services.AddSingleton<AuditLogService>();
builder.Services.AddSingleton<PdfService>();

builder.Services.AddRouting();
builder.Services.AddEndpointsApiExplorer();

var app = builder.Build();

// Audit log directory ensure
app.Services.GetRequiredService<AuditLogService>().EnsureReady();

// Static files
var contentTypes = new FileExtensionContentTypeProvider();
contentTypes.Mappings[".map"] = "application/json";
app.UseStaticFiles(new StaticFileOptions { ContentTypeProvider = contentTypes });

app.UseAuthentication();
app.UseAuthorization();

// Health
app.MapGet("/healthz", () => Results.Ok(new { ok = true, time = DateTimeOffset.UtcNow })).AllowAnonymous();

// UI redirects
app.MapGet("/admin", ctx => { ctx.Response.Redirect("/admin/index.html"); return Task.CompletedTask; }).RequireAuthorization();
app.MapGet("/selfservice", ctx => { ctx.Response.Redirect("/selfservice/index.html"); return Task.CompletedTask; }).AllowAnonymous();

// Helper
string Caller(HttpContext ctx) => ctx.User?.Identity?.Name ?? "anonymous";

// Config for UI dropdowns
app.MapGet("/api/config/domains", (IOptions<AdOptions> opts) =>
{
    var names = opts.Value.Domains?.Select(d => d.Name).Where(s => !string.IsNullOrWhiteSpace(s)).ToArray() ?? Array.Empty<string>();
    return Results.Ok(names);
}).AllowAnonymous();

// ---------- Admin APIs ----------

// Aggregate user list across all configured domains
app.MapGet("/api/admin/users", (AdService ad, IOptions<AdOptions> opts) =>
{
    var rows = new List<UserRow>();
    foreach (var d in opts.Value.Domains ?? Enumerable.Empty<DomainConfig>())
    {
        try { rows.AddRange(ad.ListUsers(d.Name)); } catch { /* ignore domain errors */ }
    }
    return Results.Ok(rows);
}).RequireAuthorization();

// Create user – returns JSON for modal (no PDF here)
app.MapPost("/api/admin/create-user", async (HttpContext ctx, AdService ad, AuditLogService audit, CreateUserRequest req) =>
{
    if (string.IsNullOrWhiteSpace(req.Domain) ||
        string.IsNullOrWhiteSpace(req.FirstName) ||
        string.IsNullOrWhiteSpace(req.LastName) ||
        !req.Birthdate.HasValue ||
        !req.ExpirationDate.HasValue ||
        string.IsNullOrWhiteSpace(req.SamAccountName))
    {
        return Results.BadRequest(new { error = "All fields are mandatory: Domain, FirstName, LastName, Birthdate, ExpirationDate, SamAccountName." });
    }

    var caller = Caller(ctx);
    try
    {
        var result = ad.CreateUser(req, caller);
        var admin = new
        {
            created = req.CreatePrivileged,
            sam = req.CreatePrivileged ? result.SamAccountName + "-a" : null,
            password = req.CreatePrivileged ? result.InitialPassword : null
        };

        await audit.WriteAsync(new AuditEvent
        {
            TimestampUtc = DateTime.UtcNow,
            Administrator = caller,
            SourceIp = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            ActionType = "CreateUser",
            TargetUser = $"{result.Domain}\\{result.SamAccountName}",
            Outcome = "Success (JSON returned)"
        });

        return Results.Ok(new { ok = true, result, admin });
    }
    catch (Exception ex)
    {
        await audit.WriteAsync(new AuditEvent
        {
            TimestampUtc = DateTime.UtcNow,
            Administrator = caller,
            SourceIp = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            ActionType = "CreateUser",
            TargetUser = $"{req.Domain}\\{req.SamAccountName}",
            Outcome = "Failed: " + ex.Message
        });
        return Results.BadRequest(new { error = ex.Message });
    }
}).RequireAuthorization();

// Export PDF (regular user only; excludes admin creds)
app.MapPost("/api/admin/create-user/export-pdf", (PdfService pdf, CreateUserResult payload) =>
{
    var pdfBytes = pdf.GenerateUserSummaryPdf(payload, watermark: "Confidential");
    var fileName = $"UserSummary_{payload.Domain}_{payload.SamAccountName}_{DateTime.UtcNow:yyyyMMddHHmmss}.pdf";
    return Results.File(pdfBytes, "application/pdf", fileName);
}).RequireAuthorization();

// Update user
app.MapPost("/api/admin/update-user", async (HttpContext ctx, AdService ad, AuditLogService audit, UpdateUserRequest req) =>
{
    if (string.IsNullOrWhiteSpace(req.Domain) ||
        string.IsNullOrWhiteSpace(req.SamAccountName) ||
        string.IsNullOrWhiteSpace(req.FirstName) ||
        string.IsNullOrWhiteSpace(req.LastName) ||
        !req.Birthdate.HasValue ||
        !req.ExpirationDate.HasValue)
    {
        return Results.BadRequest(new { error = "All fields are mandatory: Domain, SamAccountName, FirstName, LastName, Birthdate, ExpirationDate." });
    }

    var caller = Caller(ctx);
    try
    {
        ad.UpdateUser(req, caller);
        await audit.WriteAsync(new AuditEvent
        {
            TimestampUtc = DateTime.UtcNow,
            Administrator = caller,
            SourceIp = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            ActionType = "UpdateUser",
            TargetUser = $"{req.Domain}\\{req.SamAccountName}",
            Outcome = "Success"
        });
        return Results.Ok(new { ok = true });
    }
    catch (Exception ex)
    {
        await audit.WriteAsync(new AuditEvent
        {
            TimestampUtc = DateTime.UtcNow,
            Administrator = caller,
            SourceIp = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            ActionType = "UpdateUser",
            TargetUser = $"{req.Domain}\\{req.SamAccountName}",
            Outcome = "Failed: " + ex.Message
        });
        return Results.BadRequest(new { error = ex.Message });
    }
}).RequireAuthorization();

// Unlock
app.MapPost("/api/admin/unlock", async (HttpContext ctx, AdService ad, AuditLogService audit, UnlockRequest req) =>
{
    var caller = Caller(ctx);
    try
    {
        ad.UnlockAccount(req.Domain, req.SamAccountName);
        await audit.WriteAsync(new AuditEvent
        {
            TimestampUtc = DateTime.UtcNow,
            Administrator = caller,
            SourceIp = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            ActionType = "Unlock",
            TargetUser = $"{req.Domain}\\{req.SamAccountName}",
            Outcome = "Success"
        });
        return Results.Ok(new { ok = true });
    }
    catch (Exception ex)
    {
        await audit.WriteAsync(new AuditEvent
        {
            TimestampUtc = DateTime.UtcNow,
            Administrator = caller,
            SourceIp = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            ActionType = "Unlock",
            TargetUser = $"{req.Domain}\\{req.SamAccountName}",
            Outcome = "Failed: " + ex.Message
        });
        return Results.BadRequest(new { error = ex.Message });
    }
}).RequireAuthorization();

// Enable/Disable
app.MapPost("/api/admin/enable", async (HttpContext ctx, AdService ad, AuditLogService audit, EnableDisableRequest req) =>
{
    var caller = Caller(ctx);
    try
    {
        ad.SetEnabled(req.Domain, req.SamAccountName, req.Enable);
        await audit.WriteAsync(new AuditEvent
        {
            TimestampUtc = DateTime.UtcNow,
            Administrator = caller,
            SourceIp = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            ActionType = req.Enable ? "Enable" : "Disable",
            TargetUser = $"{req.Domain}\\{req.SamAccountName}",
            Outcome = "Success"
        });
        return Results.Ok(new { ok = true });
    }
    catch (Exception ex)
    {
        await audit.WriteAsync(new AuditEvent
        {
            TimestampUtc = DateTime.UtcNow,
            Administrator = caller,
            SourceIp = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            ActionType = req.Enable ? "Enable" : "Disable",
            TargetUser = $"{req.Domain}\\{req.SamAccountName}",
            Outcome = "Failed: " + ex.Message
        });
        return Results.BadRequest(new { error = ex.Message });
    }
}).RequireAuthorization();

// Reset Password (returns generated pw; optionally unlocks)
app.MapPost("/api/admin/reset-password", async (HttpContext ctx, AdService ad, AuditLogService audit, ResetPasswordRequest req) =>
{
    var caller = Caller(ctx);
    try
    {
        var newPass = ad.ResetPassword(req.Domain, req.SamAccountName, req.Unlock);
        await audit.WriteAsync(new AuditEvent
        {
            TimestampUtc = DateTime.UtcNow,
            Administrator = caller,
            SourceIp = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            ActionType = "ResetPassword",
            TargetUser = $"{req.Domain}\\{req.SamAccountName}",
            Outcome = "Success"
        });
        return Results.Ok(new { password = newPass });
    }
    catch (Exception ex)
    {
        await audit.WriteAsync(new AuditEvent
        {
            TimestampUtc = DateTime.UtcNow,
            Administrator = caller,
            SourceIp = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            ActionType = "ResetPassword",
            TargetUser = $"{req.Domain}\\{req.SamAccountName}",
            Outcome = "Failed: " + ex.Message
        });
        return Results.BadRequest(new { error = ex.Message });
    }
}).RequireAuthorization();

// Logs
app.MapGet("/api/admin/logs", (AuditLogService audit) =>
{
    var lines = audit.ReadTail(500);
    return Results.Ok(new { entries = lines });
}).RequireAuthorization();

// ---------- Self-Service (public) ----------
app.MapPost("/api/selfservice/reset-password", async (HttpContext ctx, AdService ad, AuditLogService audit, SelfServiceResetRequest req) =>
{
    if (string.IsNullOrWhiteSpace(req.Domain) ||
        string.IsNullOrWhiteSpace(req.SamAccountName) ||
        string.IsNullOrWhiteSpace(req.Birthdate) ||
        string.IsNullOrWhiteSpace(req.NewPassword))
    {
        return Results.BadRequest(new { error = "All fields are required." });
    }
    if (req.SamAccountName.EndsWith("-a", StringComparison.OrdinalIgnoreCase))
    {
        return Results.BadRequest(new { error = "Privileged (-a) accounts cannot use self-service. Contact the helpdesk." });
    }

    var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    try
    {
        await ad.SelfServiceResetPasswordAsync(req);
        await audit.WriteAsync(new AuditEvent
        {
            TimestampUtc = DateTime.UtcNow,
            Administrator = "selfservice",
            SourceIp = ip,
            ActionType = "SelfServiceReset",
            TargetUser = $"{req.Domain}\\{req.SamAccountName}",
            Outcome = "Success"
        });
        return Results.Ok(new { ok = true });
    }
    catch (Exception ex)
    {
        await audit.WriteAsync(new AuditEvent
        {
            TimestampUtc = DateTime.UtcNow,
            Administrator = "selfservice",
            SourceIp = ip,
            ActionType = "SelfServiceReset",
            TargetUser = $"{req.Domain}\\{req.SamAccountName}",
            Outcome = "Failed: " + ex.Message
        });
        return Results.BadRequest(new { error = ex.Message });
    }
}).AllowAnonymous();

app.Run();

// ---------- Request DTOs for endpoints ----------
public record UnlockRequest(string Domain, string SamAccountName);
public record EnableDisableRequest(string Domain, string SamAccountName, bool Enable);
public record ResetPasswordRequest(string Domain, string SamAccountName, bool Unlock);
public record CreateUserExportPdfRequest(CreateUserResult Result);
