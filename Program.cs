// Explicit usings so it compiles even if ImplicitUsings is disabled
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

using ADWebManager.Models;
using ADWebManager.Services;

var builder = WebApplication.CreateBuilder(args);

// ---------- Options / DI ----------
builder.Services.Configure<AdSettings>(builder.Configuration.GetSection("AdSettings"));

builder.Services.AddSingleton<AuditLogService>(sp =>
{
    var ad = sp.GetRequiredService<IOptions<AdSettings>>().Value ?? new AdSettings();
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
    var ad = sp.GetRequiredService<IOptions<AdSettings>>().Value ?? new AdSettings();
    var sess = ad.Security?.Session ?? new SessionSettings();
    return new SecurityService(new SecurityOptions
    {
        IdleTimeoutMinutes = sess.IdleTimeoutMinutes,
        AbsoluteTimeoutMinutes = sess.AbsoluteTimeoutMinutes,
        SessionCookieName = "adwm.sid"
    });
});

builder.Services.AddAuthentication(NegotiateDefaults.AuthenticationScheme).AddNegotiate();
builder.Services.AddAuthorization(o =>
{
    var adSettings = builder.Configuration.GetSection("AdSettings").Get<AdSettings>();
    var generalGroups = adSettings?.Security?.GeneralAccessGroups ?? new List<string>();
    var highPrivilegeGroups = adSettings?.Security?.HighPrivilegeGroups ?? new List<string>();
    var allAdminGroups = generalGroups.Concat(highPrivilegeGroups).Distinct().ToArray();

    o.AddPolicy("AdminPortalAccess", policy =>
    {
        policy.RequireAuthenticatedUser();
        if (allAdminGroups.Any())
        {
            policy.RequireRole(allAdminGroups);
        }
    });

    o.AddPolicy("PrivilegedAdmin", policy =>
    {
        policy.RequireAuthenticatedUser();
        if (highPrivilegeGroups.Any())
        {
            policy.RequireRole(highPrivilegeGroups);
        }
    });
});

builder.Services.AddRouting();

var app = builder.Build();

// ---------- Static & Auth ----------
app.UseDefaultFiles();
app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();

// --- API Endpoints ---
app.MapGet("/api/session/bootstrap", (HttpContext ctx, SecurityService sec) =>
{
    var csrf = sec.GetCsrf(ctx);
    var fpTail = "…" + sec.EnsureSession(ctx).Fingerprint[^8..];
    return Results.Ok(new { ok = true, csrf, cookie = "set", fpTail });
}).AllowAnonymous();

app.MapGet("/api/session/permissions", (HttpContext ctx, IAuthorizationService authService) =>
{
    var user = ctx.User;
    bool canCreatePrivileged = authService.AuthorizeAsync(user, "PrivilegedAdmin").Result.Succeeded;
    return Results.Ok(new { canCreatePrivileged });
}).RequireAuthorization("AdminPortalAccess");


app.Use(async (ctx, next) =>
{
    var path = ctx.Request.Path.Value ?? "";
    var method = ctx.Request.Method?.ToUpperInvariant() ?? "GET";
    bool isUnsafe = method is "POST" or "PUT" or "PATCH" or "DELETE";
    if (isUnsafe && path.StartsWith("/api/admin/", StringComparison.OrdinalIgnoreCase))
    {
        var sec = ctx.RequestServices.GetRequiredService<SecurityService>();
        if (!sec.ValidateCsrf(ctx))
        {
            ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
            await ctx.Response.WriteAsJsonAsync(new { ok = false, message = "CSRF validation failed or session expired." });
            return;
        }
    }
    await next();
});

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

app.MapGet("/", ctx => { ctx.Response.Redirect("/index.html"); return Task.CompletedTask; }).AllowAnonymous();

app.MapGet("/api/config/domains", (IOptions<AdSettings> cfg) =>
{
    var ad = cfg.Value ?? new AdSettings();
    return Results.Ok(AllDomains(ad));
}).AllowAnonymous();

app.MapGet("/api/config/optional-groups", (HttpContext ctx, IOptions<AdSettings> cfg) =>
{
    var ad = cfg.Value ?? new AdSettings();
    var domain = ctx.Request.Query["domain"].ToString();
    var optionalGroups = new
    {
        optionalGeneralAccessGroup = ad.Provisioning?.OptionalGeneralAccessGroup ?? new List<string>(),
        optionalPrivilegeGroup = ad.Provisioning?.OptionalPrivilegeGroup ?? new List<string>()
    };
    return Results.Ok(optionalGroups);
}).AllowAnonymous();

app.MapPost("/api/admin/create-user", async (HttpContext ctx, AdService ad, AuditLogService audit, IAuthorizationService authService) =>
{
    var caller = Caller(ctx);
    try
    {
        var req = await ReadJson<CreateUserRequest>(ctx);
        if (req.CreatePrivileged)
        {
            var authResult = await authService.AuthorizeAsync(ctx.User, "PrivilegedAdmin");
            if (!authResult.Succeeded)
            {
                audit.Write(caller, "create-privileged-denied", $"{req.Domain}\\{req.SamAccountName}", false, "Attempted privileged account creation without sufficient rights.", RemoteIp(ctx));
                return Results.Forbid();
            }
        }
        var result = ad.CreateUser(req, caller);
        var admin = new { created = req.CreatePrivileged, sam = req.CreatePrivileged ? result.SamAccountName + "-a" : null, password = req.CreatePrivileged ? result.AdminInitialPassword : null };
        audit.Write(caller, "create", $"{result.Domain}\\{result.SamAccountName}", true, $"priv={req.CreatePrivileged}", RemoteIp(ctx));
        return Results.Ok(new { ok = true, result, admin });
    }
    catch (Exception ex)
    {
        audit.Write(caller, "create", "-", false, ex.Message, RemoteIp(ctx));
        return Results.BadRequest(new { ok = false, message = ex.Message });
    }
}).RequireAuthorization("AdminPortalAccess");


// All other admin endpoints protected by the general portal access policy
app.MapGet("/api/admin/health", (HealthService health) => Results.Ok(new { ok = true, report = health.GetReport() })).RequireAuthorization("AdminPortalAccess");
app.MapGet("/api/admin/users", (HttpContext ctx, AdService adSvc, IOptions<AdSettings> cfg) => { /* ... implementation ... */ return Results.Ok(new List<UserRow>()); }).RequireAuthorization("AdminPortalAccess");
app.MapGet("/api/admin/user-details", (HttpContext ctx, AdService adSvc) => { /* ... implementation ... */ return Results.Ok(new UserDetails()); }).RequireAuthorization("AdminPortalAccess");
app.MapPost("/api/admin/update-user", async (HttpContext ctx, AdService ad, AuditLogService audit) => { /* ... */ return Results.Ok(new { ok = true }); }).RequireAuthorization("AdminPortalAccess");
app.MapPost("/api/admin/reset-password", async (HttpContext ctx, AdService ad, AuditLogService audit, PasswordService pw) => { /* ... */ return Results.Ok(new { ok = true }); }).RequireAuthorization("AdminPortalAccess");
app.MapGet("/api/admin/logs", (AuditLogService audit) => Results.Ok(new { entries = audit.Tail() })).RequireAuthorization("AdminPortalAccess");
app.MapPost("/api/admin/logout", (HttpContext ctx, SecurityService sec) => { sec.ClearSession(ctx); return Results.Ok(new { ok = true }); }).RequireAuthorization("AdminPortalAccess");
app.MapPost("/api/admin/create-user/export-pdf", async (HttpContext ctx, PdfService pdf) => { /* ... */ return Results.File(new byte[0], "application/pdf"); }).RequireAuthorization("AdminPortalAccess");
app.MapPost("/api/selfservice/reset", async (HttpContext ctx, AdService ad, AuditLogService audit, PasswordService pw) => { /* ... */ return Results.Ok(new { ok = true }); }).AllowAnonymous();


app.Run();

