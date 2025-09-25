// Explicit usings so it compiles even if ImplicitUsings is disabled
using System;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using ADWebManager.Models;
using ADWebManager.Services;

// Centralized definition of authorization policy names
public static class AuthorizationPolicies
{
    public const string AdminPortalAccess = "AdminPortalAccess";
    public const string PrivilegedAdmin = "PrivilegedAdmin";
}

var builder = WebApplication.CreateBuilder(args);

// ---------- Options / DI ----------
builder.Services.Configure<AdSettings>(builder.Configuration.GetSection("AdSettings"));

builder.Services.AddSingleton<AuditLogService>(sp =>
{
    var ad = sp.GetRequiredService<IOptions<AdSettings>>().Value;
    var dir = ad.Audit?.LocalFile?.Path ?? "logs";
    return new AuditLogService(new AuditLogOptions { Directory = Path.GetDirectoryName(dir) ?? "logs" });
});

builder.Services.AddSingleton<PasswordService>(sp =>
    new PasswordService(sp.GetRequiredService<IOptions<AdSettings>>()));

builder.Services.AddSingleton<PdfService>();
builder.Services.AddSingleton<AdService>();
builder.Services.AddSingleton<HealthService>();

builder.Services.AddSingleton<SecurityService>(sp =>
{
    var ad = sp.GetRequiredService<IOptions<AdSettings>>().Value;
    var sess = ad.Security?.Session ?? new SessionSettings();
    return new SecurityService(new SecurityOptions
    {
        IdleTimeoutMinutes = sess.IdleTimeoutMinutes,
        AbsoluteTimeoutMinutes = sess.AbsoluteTimeoutMinutes,
        SessionCookieName = "adwm.sid"
    });
});

builder.Services.AddAuthentication(NegotiateDefaults.AuthenticationScheme).AddNegotiate();

// Correctly configure Authorization by binding settings directly from IConfiguration
builder.Services.AddAuthorization(o =>
{
    // Bind AdSettings from configuration to access AccessControl
    var adSettings = new AdSettings();
    builder.Configuration.GetSection("AdSettings").Bind(adSettings);
    
    var generalGroups = adSettings.AccessControl?.GeneralAccessGroups ?? new List<string>();
    var highPrivilegeGroups = adSettings.AccessControl?.HighPrivilegeGroups ?? new List<string>();
    var allAdminGroups = generalGroups.Concat(highPrivilegeGroups).Distinct().ToArray();

    o.AddPolicy(AuthorizationPolicies.AdminPortalAccess, policy => 
        policy.RequireRole(allAdminGroups));
        
    o.AddPolicy(AuthorizationPolicies.PrivilegedAdmin, policy => 
        policy.RequireRole(highPrivilegeGroups));
});


builder.Services.AddRouting();

var app = builder.Build();

// ---------- Global Exception Handler ----------
app.UseExceptionHandler(appError =>
{
    appError.Run(async context =>
    {
        context.Response.StatusCode = StatusCodes.Status500InternalServerError;
        context.Response.ContentType = "application/json";

        var contextFeature = context.Features.Get<IExceptionHandlerFeature>();
        if(contextFeature != null)
        { 
            var logger = context.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogError($"Something went wrong: {contextFeature.Error}");

            await context.Response.WriteAsJsonAsync(new 
            {
                ok = false,
                message = "An unexpected error occurred. Please try again later."
            });
        }
    });
});


// ---------- Static & Auth ----------
app.UseDefaultFiles();
app.UseStaticFiles();

app.UseAuthentication();
app.UseAuthorization();

// --- Session/CSRF bootstrap endpoint ---
app.MapGet("/api/session/bootstrap", (HttpContext ctx, SecurityService sec) =>
{
    var csrf = sec.GetCsrf(ctx);
    var fpTail = "…" + sec.EnsureSession(ctx).Fingerprint[^8..];
    return Results.Ok(new { ok = true, csrf, cookie = "set", fpTail });
}).AllowAnonymous();

// --- Logout endpoint ---
app.MapPost("/api/admin/logout", (HttpContext ctx, SecurityService sec) =>
{
    sec.DestroySession(ctx);
    return Results.Ok(new { ok = true, message = "Logged out" });
}).RequireAuthorization(AuthorizationPolicies.AdminPortalAccess);

// --- Permissions check endpoint ---
app.MapGet("/api/session/permissions", (HttpContext ctx, IOptions<AdSettings> cfg) =>
{
    var highPrivilegeGroups = cfg.Value?.AccessControl?.HighPrivilegeGroups ?? new List<string>();
    var canCreatePrivileged = highPrivilegeGroups.Any(group => ctx.User.IsInRole(group));
    return Results.Ok(new { canCreatePrivileged });
}).RequireAuthorization(AuthorizationPolicies.AdminPortalAccess);


// --- CSRF guard for unsafe admin calls ---
app.Use(async (ctx, next) =>
{
    var path = ctx.Request.Path.Value ?? "";
    var method = ctx.Request.Method?.ToUpperInvariant() ?? "GET";
    bool isUnsafe = method is "POST" or "PUT" or "PATCH" or "DELETE";

    if (isUnsafe && path.StartsWith("/api/admin/", StringComparison.OrdinalIgnoreCase))
    {
        var sec = ctx.RequestServices.GetRequiredservice<SecurityService>();
        if (!sec.ValidateCsrf(ctx))
        {
            ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
            await ctx.Response.WriteAsJsonAsync(new { ok = false, message = "CSRF validation failed or session expired." });
            return;
        }
    }
    await next();
});

// Helpers
async Task<T> ReadJson<T>(HttpContext ctx)
{
    var obj = await JsonSerializer.DeserializeAsync<T>(ctx.Request.Body, new JsonSerializerOptions
    {
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() }
    });
    if (obj == null) throw new Exception("Invalid JSON.");
    return obj;
}
string Caller(HttpContext ctx) => ctx.User?.Identity?.Name ?? "(anon)";
string RemoteIp(HttpContext ctx) => ctx.Connection.RemoteIpAddress?.ToString() ?? "(unknown)";

static string[] AllDomains(AdSettings ad)
{
    var root = string.IsNullOrWhiteSpace(ad.ForestRootDomain) ? Array.Empty<string>() : new[] { ad.ForestRootDomain };
    var children = ad.ForestChildDomain ?? new();
    return root.Concat(children).ToArray();
}

// ---------- Routes ----------
app.MapGet("/", ctx => { ctx.Response.Redirect("/index.html"); return Task.CompletedTask; }).AllowAnonymous();

app.MapGet("/api/config/domains", (IOptions<AdSettings> cfg) =>
{
    var ad = cfg.Value ?? new AdSettings();
    return Results.Ok(AllDomains(ad));
}).AllowAnonymous();

app.MapGet("/api/config/optional-groups", (HttpContext ctx, IOptions<AdSettings> cfg) =>
{
    var ad = cfg.Value ?? new AdSettings();
    var optionalGroups = new
    {
        optionalGeneralAccessGroup = ad.Provisioning?.OptionalGeneralAccessGroup ?? new List<string>(),
        optionalPrivilegeGroup = ad.Provisioning?.OptionalPrivilegeGroup ?? new List<string>()
    };
    return Results.Ok(optionalGroups);
}).AllowAnonymous();

// -------- Admin (Windows auth) --------
app.MapGet("/api/admin/health", async (HealthService health, AuditLogService audit, HttpContext ctx) =>
{
    var report = await health.GetReportAsync();
    return Results.Ok(new { ok = true, report }); 
}).RequireAuthorization(AuthorizationPolicies.AdminPortalAccess);

app.MapGet("/api/admin/users", (HttpContext ctx, AdService adSvc, AuditLogService audit, IOptions<AdSettings> cfg) =>
{
    var ad = cfg.Value ?? new AdSettings();
    var queryDomain = ctx.Request.Query["domain"].ToString();
    var results = new System.Collections.Generic.List<UserRow>();
    var domains = string.IsNullOrWhiteSpace(queryDomain) ? AllDomains(ad) : new[] { queryDomain };

    foreach (var d in domains) results.AddRange(adSvc.ListUsers(d));
    return Results.Ok(results);
}).RequireAuthorization(AuthorizationPolicies.AdminPortalAccess);

app.MapGet("/api/admin/user-details", (string domain, string sam, AdService adSvc, AuditLogService audit, HttpContext ctx) =>
{
    var user = adSvc.GetUserDetails(domain, sam);
    return Results.Ok(user);
}).RequireAuthorization(AuthorizationPolicies.AdminPortalAccess);

app.MapPost("/api/selfservice/reset", async (HttpContext ctx, AdService ad, AuditLogService audit, PasswordService pw) =>
{
    var req = await ReadJson<SelfServiceResetRequest>(ctx);
    var (ok, problems) = pw.CheckStrengthForUser(req.SamAccountName, req.NewPassword);
    if (!ok) return Results.BadRequest(new { ok = false, message = "Password does not meet policy.", problems });

    await ad.SelfServiceResetPasswordAsync(req);
    audit.Write("(selfservice)", "reset", $"{req.Domain}\\{req.SamAccountName}", true, "Self-service reset", RemoteIp(ctx));
    return Results.Ok(new { ok = true });
}).AllowAnonymous();

app.MapPost("/api/admin/create-user", async (HttpContext ctx, AdService ad, AuditLogService audit, IOptions<AdSettings> cfg) =>
{
    var caller = Caller(ctx);
    var req = await ReadJson<CreateUserRequest>(ctx);
    
    var highPrivilegeGroups = cfg.Value?.AccessControl?.HighPrivilegeGroups ?? new List<string>();
    var canCreatePrivileged = highPrivilegeGroups.Any(group => ctx.User.IsInRole(group));

    if (req.CreatePrivileged && !canCreatePrivileged)
    {
        audit.Write(caller, "create", req.SamAccountName, false, "Forbidden: insufficient privilege to create admin account.", RemoteIp(ctx));
        return Results.Forbid();
    }

    var result = ad.CreateUser(req, caller);
    
    result.InitialPassword = string.Empty; 
    result.AdminInitialPassword = null;

    var admin = new
    {
        created = req.CreatePrivileged,
        sam = req.CreatePrivileged ? result.SamAccountName + "-a" : null,
    };
    audit.Write(caller, "create", $"{result.Domain}\\{result.SamAccountName}", true, $"priv={req.CreatePrivileged}", RemoteIp(ctx));
    return Results.Ok(new { ok = true, result, admin });
}).RequireAuthorization(AuthorizationPolicies.AdminPortalAccess);

app.MapPost("/api/admin/create-user/export-pdf", async (HttpContext ctx, PdfService pdf, AuditLogService audit) =>
{
    var caller = Caller(ctx);
    var r = await ReadJson<CreateUserResult>(ctx);
    var bytes = pdf.CreateSummary(r);
    return Results.File(bytes, "application/pdf", $"acct-{r.SamAccountName}.pdf");
}).RequireAuthorization(AuthorizationPolicies.AdminPortalAccess);

app.MapPost("/api/admin/update-user", async (HttpContext ctx, AdService ad, AuditLogService audit) =>
{
    var caller = Caller(ctx);
    var req = await ReadJson<UpdateUserRequest>(ctx);
    ad.UpdateUser(req, caller);
    audit.Write(caller, "update", $"{req.Domain}\\{req.SamAccountName}", true, null, RemoteIp(ctx));
    return Results.Ok(new { ok = true });
}).RequireAuthorization(AuthorizationPolicies.AdminPortalAccess);

app.MapPost("/api/admin/reset-password", async (HttpContext ctx, AdService ad, AuditLogService audit, PasswordService pw) =>
{
    var caller = Caller(ctx);
    using var doc = await JsonDocument.ParseAsync(ctx.Request.Body);
    var root = doc.RootElement;

    if (!root.TryGetProperty("domain", out var domainProp) || domainProp.GetString() is not { } domain ||
        !root.TryGetProperty("samAccountName", out var samProp) || samProp.GetString() is not { } sam)
    {
        return Results.BadRequest(new { ok = false, message = "Missing domain or samAccountName." });
    }

    var unlock = root.TryGetProperty("unlock", out var u) && u.GetBoolean();

    string? newPassword = null;
    if (root.TryGetProperty("newPassword", out var np) && np.ValueKind == JsonValueKind.String)
        newPassword = np.GetString();

    if (!string.IsNullOrWhiteSpace(newPassword))
    {
        var (ok, problems) = pw.CheckStrengthForUser(sam, newPassword!);
        if (!ok) return Results.BadRequest(new { ok = false, message = "Password does not meet policy.", problems });

        ad.SetPassword(domain, sam, newPassword!, unlock);
        audit.Write(caller, "reset-password", $"{domain}\\{sam}", true, "custom=true; unlock=" + unlock, RemoteIp(ctx));
        return Results.Ok(new { ok = true, generated = false });
    }
    else
    {
        var generated = ad.ResetPassword(domain, sam, unlock);
        audit.Write(caller, "reset-password", $"{domain}\\{sam}", true, "custom=false; unlock=" + unlock, RemoteIp(ctx));
        return Results.Ok(new { ok = true, generated = true, password = generated });
    }
}).RequireAuthorization(AuthorizationPolicies.AdminPortalAccess);

app.MapGet("/api/admin/logs", (AuditLogService audit) => Results.Ok(new { entries = audit.Tail() })).RequireAuthorization(AuthorizationPolicies.AdminPortalAccess);

app.Run();