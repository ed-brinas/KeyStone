// Explicit usings so it compiles even if ImplicitUsings is disabled
using System;
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

using ADWebManager.Models;
using ADWebManager.Services;

var builder = WebApplication.CreateBuilder(args);

// ---------- Options / DI ----------
builder.Services.Configure<AdOptions>(builder.Configuration.GetSection("Ad"));
builder.Services.Configure<AuditLogOptions>(builder.Configuration.GetSection("Audit"));
builder.Services.Configure<HealthOptions>(builder.Configuration.GetSection("Health"));
builder.Services.AddSingleton<AuditLogService>(_ =>
    new AuditLogService(builder.Configuration.GetSection("Audit").Get<AuditLogOptions>() ?? new AuditLogOptions()));
builder.Services.AddSingleton<PasswordService>(_ =>
    new PasswordService(builder.Configuration.GetSection("PasswordPolicy").Get<PasswordPolicyOptions>() ?? new PasswordPolicyOptions()));
builder.Services.AddSingleton<PdfService>();
builder.Services.AddSingleton<AdService>();
builder.Services.AddSingleton<HealthService>();
builder.Services.AddSingleton<SecurityService>(_ =>
    new SecurityService(builder.Configuration.GetSection("Security").Get<SecurityOptions>() ?? new SecurityOptions()));

// Windows (Negotiate) auth for /admin APIs
builder.Services.AddAuthentication(NegotiateDefaults.AuthenticationScheme).AddNegotiate();
builder.Services.AddAuthorization(o =>
{
    o.AddPolicy("AdminOnly", policy => policy.RequireAuthenticatedUser());
});

builder.Services.AddRouting();

var app = builder.Build();

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

// --- CSRF guard for unsafe admin calls ---
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

// ---------- Routes ----------
app.MapGet("/", ctx => { ctx.Response.Redirect("/index.html"); return Task.CompletedTask; }).AllowAnonymous();

app.MapGet("/api/config/domains", (Microsoft.Extensions.Options.IOptions<AdOptions> ao) =>
{
    var names = (ao.Value?.Domains ?? new()).Select(d => d.Name).ToArray();
    return Results.Ok(names);
}).AllowAnonymous();

app.MapPost("/api/selfservice/reset", async (HttpContext ctx, AdService ad, AuditLogService audit, PasswordService pw) =>
{
    try
    {
        var req = await ReadJson<SelfServiceResetRequest>(ctx);
        var (ok, problems) = pw.CheckStrength(req.NewPassword);
        if (!ok) return Results.BadRequest(new { ok = false, message = "Password does not meet policy.", problems });

        await ad.SelfServiceResetPasswordAsync(req);
        audit.Write("(selfservice)", "reset", $"{req.Domain}\\{req.SamAccountName}", true, "Self-service reset", RemoteIp(ctx));
        return Results.Ok(new { ok = true });
    }
    catch (Exception ex)
    {
        audit.Write("(selfservice)", "reset", "-", false, ex.Message, RemoteIp(ctx));
        return Results.BadRequest(new { ok = false, message = ex.Message });
    }
}).AllowAnonymous();

// Returns the configured privileged groups for a domain (from appsettings)
app.MapGet("/api/config/privileged-groups", (HttpContext ctx, Microsoft.Extensions.Options.IOptions<AdOptions> ao) =>
{
    var domain = ctx.Request.Query["domain"].ToString();
    var d = (ao.Value?.Domains ?? new()).FirstOrDefault(x => x.Name.Equals(domain, StringComparison.OrdinalIgnoreCase));
    if (d == null) return Results.Ok(Array.Empty<string>());
    return Results.Ok(d.PrivilegedGroups ?? Array.Empty<string>());
}).AllowAnonymous();

// -------- Admin (Windows auth) --------
app.MapGet("/api/admin/health", (HealthService health, AuditLogService audit, HttpContext ctx) =>
{
    try { return Results.Ok(new { ok = true, report = health.GetReport() }); }
    catch (Exception ex)
    {
        audit.Write(Caller(ctx), "health", "-", false, ex.Message, RemoteIp(ctx));
        return Results.BadRequest(new { ok = false, message = ex.Message });
    }
}).RequireAuthorization("AdminOnly");

app.MapGet("/api/admin/users", (HttpContext ctx, AdService ad, AuditLogService audit, Microsoft.Extensions.Options.IOptions<AdOptions> adOpts) =>
{
    try
    {
        var domain = ctx.Request.Query["domain"].ToString();
        var results = new System.Collections.Generic.List<UserRow>();
        var domains = adOpts.Value.Domains.Select(d => d.Name);
        if (!string.IsNullOrWhiteSpace(domain))
            results.AddRange(ad.ListUsers(domain));
        else
            foreach (var d in domains) results.AddRange(ad.ListUsers(d));
        return Results.Ok(results);
    }
    catch (Exception ex)
    {
        audit.Write(Caller(ctx), "users", "-", false, ex.Message, RemoteIp(ctx));
        return Results.BadRequest(new { ok = false, message = ex.Message });
    }
}).RequireAuthorization("AdminOnly");

app.MapPost("/api/admin/create-user", async (HttpContext ctx, AdService ad, AuditLogService audit) =>
{
    var caller = Caller(ctx);
    try
    {
        var req = await ReadJson<CreateUserRequest>(ctx);
        var result = ad.CreateUser(req, caller);
        var admin = new
        {
            created = req.CreatePrivileged,
            sam = req.CreatePrivileged ? result.SamAccountName + "-a" : null,
            password = req.CreatePrivileged ? result.AdminInitialPassword : null
        };
        audit.Write(caller, "create", $"{result.Domain}\\{result.SamAccountName}", true, $"priv={req.CreatePrivileged}", RemoteIp(ctx));
        return Results.Ok(new { ok = true, result, admin });
    }
    catch (Exception ex)
    {
        audit.Write(caller, "create", "-", false, ex.Message, RemoteIp(ctx));
        return Results.BadRequest(new { ok = false, message = ex.Message });
    }
}).RequireAuthorization("AdminOnly");

app.MapPost("/api/admin/create-user/export-pdf", async (HttpContext ctx, PdfService pdf, AuditLogService audit) =>
{
    var caller = Caller(ctx);
    try
    {
        var r = await ReadJson<CreateUserResult>(ctx);
        var bytes = pdf.CreateSummary(r);
        return Results.File(bytes, "application/pdf", $"acct-{r.SamAccountName}.pdf");
    }
    catch (Exception ex)
    {
        audit.Write(caller, "export-pdf", "-", false, ex.Message, RemoteIp(ctx));
        return Results.BadRequest(new { ok = false, message = ex.Message });
    }
}).RequireAuthorization("AdminOnly");

app.MapPost("/api/admin/update-user", async (HttpContext ctx, AdService ad, AuditLogService audit) =>
{
    var caller = Caller(ctx);
    try
    {
        var req = await ReadJson<UpdateUserRequest>(ctx);
        ad.UpdateUser(req, caller);
        audit.Write(caller, "update", $"{req.Domain}\\{req.SamAccountName}", true, null, RemoteIp(ctx));
        return Results.Ok(new { ok = true });
    }
    catch (Exception ex)
    {
        audit.Write(caller, "update", "-", false, ex.Message, RemoteIp(ctx));
        return Results.BadRequest(new { ok = false, message = ex.Message });
    }
}).RequireAuthorization("AdminOnly");

app.MapPost("/api/admin/unlock", async (HttpContext ctx, AdService ad, AuditLogService audit) =>
{
    var caller = Caller(ctx);
    try
    {
        using var doc = await JsonDocument.ParseAsync(ctx.Request.Body);
        var domain = doc.RootElement.GetProperty("domain").GetString()!;
        var sam = doc.RootElement.GetProperty("samAccountName").GetString()!;
        ad.UnlockAccount(domain, sam);
        audit.Write(caller, "unlock", $"{domain}\\{sam}", true, null, RemoteIp(ctx));
        return Results.Ok(new { ok = true });
    }
    catch (Exception ex)
    {
        audit.Write(caller, "unlock", "-", false, ex.Message, RemoteIp(ctx));
        return Results.BadRequest(new { ok = false, message = ex.Message });
    }
}).RequireAuthorization("AdminOnly");

app.MapPost("/api/admin/enable", async (HttpContext ctx, AdService ad, AuditLogService audit) =>
{
    var caller = Caller(ctx);
    try
    {
        using var doc = await JsonDocument.ParseAsync(ctx.Request.Body);
        var domain = doc.RootElement.GetProperty("domain").GetString()!;
        var sam = doc.RootElement.GetProperty("samAccountName").GetString()!;
        var enable = doc.RootElement.GetProperty("enable").GetBoolean();
        ad.SetEnabled(domain, sam, enable);
        audit.Write(caller, enable ? "enable" : "disable", $"{domain}\\{sam}", true, null, RemoteIp(ctx));
        return Results.Ok(new { ok = true });
    }
    catch (Exception ex)
    {
        audit.Write(caller, "enable/disable", "-", false, ex.Message, RemoteIp(ctx));
        return Results.BadRequest(new { ok = false, message = ex.Message });
    }
}).RequireAuthorization("AdminOnly");

app.MapPost("/api/admin/reset-password", async (HttpContext ctx, AdService ad, AuditLogService audit) =>
{
    var caller = Caller(ctx);
    try
    {
        using var doc = await JsonDocument.ParseAsync(ctx.Request.Body);
        var domain = doc.RootElement.GetProperty("domain").GetString()!;
        var sam = doc.RootElement.GetProperty("samAccountName").GetString()!;
        var unlock = doc.RootElement.TryGetProperty("unlock", out var u) && u.GetBoolean();

        var pw = ad.ResetPassword(domain, sam, unlock);
        audit.Write(caller, "reset-password", $"{domain}\\{sam}", true, "unlock=" + unlock, RemoteIp(ctx));
        return Results.Ok(new { ok = true, password = pw });
    }
    catch (Exception ex)
    {
        audit.Write(caller, "reset-password", "-", false, ex.Message, RemoteIp(ctx));
        return Results.BadRequest(new { ok = false, message = ex.Message });
    }
}).RequireAuthorization("AdminOnly");

// Logs tail
app.MapGet("/api/admin/logs", (AuditLogService audit) => Results.Ok(new { entries = audit.Tail() })).RequireAuthorization("AdminOnly");



app.Run();
