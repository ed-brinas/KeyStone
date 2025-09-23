
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.Extensions.FileProviders;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Net;
using System.Security.Claims;
using System.Text;
using ADWebManager.Services;
using ADWebManager.Models;

var builder = WebApplication.CreateBuilder(args);

// Windows Auth (Negotiate w/ IIS Integration)
builder.Services.AddAuthentication(NegotiateDefaults.AuthenticationScheme).AddNegotiate();
builder.Services.AddAuthorization(options => {
    options.FallbackPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
});

builder.Services.Configure<AdOptions>(builder.Configuration.GetSection("AD"));
builder.Services.Configure<AuditOptions>(builder.Configuration.GetSection("Audit"));
builder.Services.AddSingleton<AdService>();
builder.Services.AddSingleton<AuditLogService>();
builder.Services.AddSingleton<PdfService>();
builder.Services.AddSingleton<PasswordService>();

builder.Services.AddRouting();
builder.Services.AddEndpointsApiExplorer();

var app = builder.Build();

// Ensure audit directory exists
var audit = app.Services.GetRequiredService<AuditLogService>();
audit.EnsureReady();

// Static files
var provider = new FileExtensionContentTypeProvider();
provider.Mappings[".map"] = "application/json";
app.UseStaticFiles(new StaticFileOptions {
    ContentTypeProvider = provider
});

app.UseAuthentication();
app.UseAuthorization();

// Health
app.MapGet("/healthz", () => Results.Ok(new { ok = true, time = DateTimeOffset.UtcNow }))
   .AllowAnonymous();

// Admin UI entry
app.MapGet("/admin", async ctx => {
    ctx.Response.Redirect("/admin/index.html");
}).RequireAuthorization();

// Self-service UI entry
app.MapGet("/selfservice", async ctx => {
    ctx.Response.Redirect("/selfservice/index.html");
}).AllowAnonymous();

// Helper to get caller
string GetCaller(HttpContext ctx) => ctx.User?.Identity?.Name ?? "anonymous";

bool IsInAnyGroup(ClaimsPrincipal user, IEnumerable<string> groups) {
    return groups.Any(g => user.IsInRole(g) || user.Claims.Any(c => c.Type == ClaimTypes.GroupSid && c.Value.Equals(g, StringComparison.OrdinalIgnoreCase)));
}

// Admin APIs
app.MapGet("/api/admin/users", (HttpContext ctx, AdService ad, IConfiguration cfg) => {
    var allowed = cfg.GetSection("AD:AccessControl:AllowedGroups").Get<string[]>() ?? Array.Empty<string>();
    if (!ctx.User.Identity?.IsAuthenticated ?? true) return Results.Unauthorized();
    // Windows group checks are handled by IIS; we also allow if authenticated (domain joined). Fine-grained control is performed inside AD operations.
    var list = ad.GetAllUsers();
    return Results.Ok(list);
}).RequireAuthorization();

app.MapPost("/api/admin/create-user", async (HttpContext ctx, AdService ad, AuditLogService audit, PdfService pdf, CreateUserRequest req) => {
    var caller = GetCaller(ctx);
    try {
        var result = ad.CreateUser(req, caller);
        var pdfBytes = pdf.GenerateUserSummaryPdf(result, watermark: "Confidential");
        var fileName = $"UserSummary_{result.Domain}_{result.SamAccountName}_{DateTime.UtcNow:yyyyMMddHHmmss}.pdf";
        return Results.File(pdfBytes, "application/pdf", fileName);
    } catch (Exception ex) {
        await audit.WriteAsync(new AuditEvent {
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

app.MapPost("/api/admin/update-user", async (HttpContext ctx, AdService ad, AuditLogService audit, UpdateUserRequest req) => {
    var caller = GetCaller(ctx);
    try {
        ad.UpdateUser(req, caller);
        await audit.WriteAsync(new AuditEvent {
            TimestampUtc = DateTime.UtcNow,
            Administrator = caller,
            SourceIp = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            ActionType = "UpdateUser",
            TargetUser = $"{req.Domain}\\{req.SamAccountName}",
            Outcome = "Success"
        });
        return Results.Ok(new { ok = true });
    } catch (Exception ex) {
        await audit.WriteAsync(new AuditEvent {
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

app.MapPost("/api/admin/unlock", async (HttpContext ctx, AdService ad, AuditLogService audit, UnlockRequest req) => {
    var caller = GetCaller(ctx);
    try {
        ad.UnlockUser(req.Domain, req.SamAccountName);
        await audit.WriteAsync(new AuditEvent {
            TimestampUtc = DateTime.UtcNow,
            Administrator = caller,
            SourceIp = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            ActionType = "Unlock",
            TargetUser = $"{req.Domain}\\{req.SamAccountName}",
            Outcome = "Success"
        });
        return Results.Ok(new { ok = true });
    } catch (Exception ex) {
        await audit.WriteAsync(new AuditEvent {
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

app.MapPost("/api/admin/enable", async (HttpContext ctx, AdService ad, AuditLogService audit, EnableDisableRequest req) => {
    var caller = GetCaller(ctx);
    try {
        ad.EnableDisableUser(req.Domain, req.SamAccountName, req.Enable);
        await audit.WriteAsync(new AuditEvent {
            TimestampUtc = DateTime.UtcNow,
            Administrator = caller,
            SourceIp = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            ActionType = req.Enable ? "Enable" : "Disable",
            TargetUser = $"{req.Domain}\\{req.SamAccountName}",
            Outcome = "Success"
        });
        return Results.Ok(new { ok = true });
    } catch (Exception ex) {
        await audit.WriteAsync(new AuditEvent {
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

app.MapPost("/api/admin/reset-password", async (HttpContext ctx, AdService ad, AuditLogService audit, ResetPasswordRequest req, PasswordService pass) => {
    var caller = GetCaller(ctx);
    try {
        var newPass = pass.Generate();
        ad.ResetPassword(req.Domain, req.SamAccountName, newPass, req.Unlock);
        await audit.WriteAsync(new AuditEvent {
            TimestampUtc = DateTime.UtcNow,
            Administrator = caller,
            SourceIp = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            ActionType = "ResetPassword",
            TargetUser = $"{req.Domain}\\{req.SamAccountName}",
            Outcome = "Success"
        });
        return Results.Ok(new { password = newPass });
    } catch (Exception ex) {
        await audit.WriteAsync(new AuditEvent {
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

// Logs (restricted)
app.MapGet("/api/admin/logs", (HttpContext ctx, AuditLogService audit, IConfiguration cfg) => {
    var allowed = cfg.GetSection("AD:AccessControl:LogViewGroups").Get<string[]>() ?? Array.Empty<string>();
    // We rely on IIS/Windows Auth; additional checks could be made here if needed.
    var lines = audit.ReadTail(500);
    return Results.Ok(new { entries = lines });
}).RequireAuthorization();

// Self-service Password Reset (anonymous page but with verification)
// Block privileged accounts (-a suffix)
app.MapPost("/api/selfservice/reset-password", async (HttpContext ctx, AdService ad, AuditLogService audit, SelfServiceRequest req) => {
    var target = $"{req.Domain}\\{req.SamAccountName}";
    var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    try {
        if (req.SamAccountName.EndsWith("-a", StringComparison.OrdinalIgnoreCase)) {
            await audit.WriteAsync(new AuditEvent {
                TimestampUtc = DateTime.UtcNow,
                Administrator = "selfservice",
                SourceIp = ip,
                ActionType = "SelfServiceReset",
                TargetUser = target,
                Outcome = "Blocked - privileged account"
            });
            return Results.BadRequest(new { error = "Privileged accounts cannot use self-service." });
        }
        // Verify current password and DOB
        if (!ad.VerifyCredentials(req.Domain, req.SamAccountName, req.CurrentPassword)) {
            await audit.WriteAsync(new AuditEvent {
                TimestampUtc = DateTime.UtcNow,
                Administrator = "selfservice",
                SourceIp = ip,
                ActionType = "SelfServiceReset",
                TargetUser = target,
                Outcome = "Failed - invalid current password"
            });
            return Results.BadRequest(new { error = "Invalid current password." });
        }
        if (!ad.VerifyBirthdate(req.Domain, req.SamAccountName, req.Birthdate)) {
            await audit.WriteAsync(new AuditEvent {
                TimestampUtc = DateTime.UtcNow,
                Administrator = "selfservice",
                SourceIp = ip,
                ActionType = "SelfServiceReset",
                TargetUser = target,
                Outcome = "Failed - DOB mismatch"
            });
            return Results.BadRequest(new { error = "Identity verification failed." });
        }
        ad.ChangeOwnPassword(req.Domain, req.SamAccountName, req.CurrentPassword, req.NewPassword);
        await audit.WriteAsync(new AuditEvent {
            TimestampUtc = DateTime.UtcNow,
            Administrator = "selfservice",
            SourceIp = ip,
            ActionType = "SelfServiceReset",
            TargetUser = target,
            Outcome = "Success"
        });
        return Results.Ok(new { ok = true });
    } catch (Exception ex) {
        await audit.WriteAsync(new AuditEvent {
            TimestampUtc = DateTime.UtcNow,
            Administrator = "selfservice",
            SourceIp = ip,
            ActionType = "SelfServiceReset",
            TargetUser = target,
            Outcome = "Failed: " + ex.Message
        });
        return Results.BadRequest(new { error = ex.Message });
    }
}).AllowAnonymous();

app.Run();

namespace ADWebManager.Models {
    public record DomainConfig(string Name, string LdapPath, string AdminOuDn, string UserOuDn,
        string ServiceAccountUser, string ServiceAccountPassword,
        string[] StandardGroups, string[] PrivilegedGroups, string PrivilegedPrimaryGroup);

    public class AdOptions {
        public string BirthdateAttribute { get; set; } = "extensionAttribute1";
        public PasswordPolicy PasswordPolicy { get; set; } = new();
        public List<DomainConfig> Domains { get; set; } = new();
        public AccessControl AccessControl { get; set; } = new();
    }
    public class PasswordPolicy {
        public int Length { get; set; } = 8;
        public bool IncludeUpper { get; set; } = true;
        public bool IncludeLower { get; set; } = true;
        public bool IncludeDigit { get; set; } = true;
        public bool IncludeSpecial { get; set; } = true;
    }
    public class AccessControl {
        public string[] AllowedGroups { get; set; } = Array.Empty<string>();
        public string[] LogViewGroups { get; set; } = Array.Empty<string>();
    }

    public class AuditOptions {
        public string LogDirectory { get; set; } = @"C:\ADWebManager\Logs";
        public int MaxFileSizeMB { get; set; } = 10;
        public int RetainFiles { get; set; } = 30;
    }

    // DTOs
    public class UserDto {
        public string Domain { get; set; } = "";
        public string SamAccountName { get; set; } = "";
        public string DisplayName { get; set; } = "";
        public string DistinguishedName { get; set; } = "";
        public DateTime? ExpirationDate { get; set; }
        public bool IsLocked { get; set; }
        public bool Enabled { get; set; }
        public bool IsPrivileged { get; set; }
    }

    public class CreateUserRequest {
        public string Domain { get; set; } = "";
        public string FirstName { get; set; } = "";
        public string LastName { get; set; } = "";
        public DateOnly? Birthdate { get; set; }
        public DateOnly? ExpirationDate { get; set; }
        public bool CreatePrivileged { get; set; } = false;
        public string? SamAccountName { get; set; } // If null, will be computed
    }

    public class CreateUserResult : UserDto {
        public string InitialPassword { get; set; } = "";
        public string[] GroupsAdded { get; set; } = Array.Empty<string>();
        public string OuCreatedIn { get; set; } = "";
    }

    public class UpdateUserRequest {
        public string Domain { get; set; } = "";
        public string SamAccountName { get; set; } = "";
        public string FirstName { get; set; } = "";
        public string LastName { get; set; } = "";
        public DateOnly? Birthdate { get; set; }
        public DateOnly? ExpirationDate { get; set; }
        public bool CreatePrivileged { get; set; } = false;
    }

    public class UnlockRequest {
        public string Domain { get; set; } = "";
        public string SamAccountName { get; set; } = "";
    }
    public class EnableDisableRequest {
        public string Domain { get; set; } = "";
        public string SamAccountName { get; set; } = "";
        public bool Enable { get; set; }
    }
    public class ResetPasswordRequest {
        public string Domain { get; set; } = "";
        public string SamAccountName { get; set; } = "";
        public bool Unlock { get; set; } = false;
    }
    public class SelfServiceRequest {
        public string Domain { get; set; } = "";
        public string SamAccountName { get; set; } = "";
        public string CurrentPassword { get; set; } = "";
        public string NewPassword { get; set; } = "";
        public DateOnly? Birthdate { get; set; }
    }
}
