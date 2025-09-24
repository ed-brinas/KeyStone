using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace ADWebManager.Services;

public record SecurityOptions
{
    public int IdleTimeoutMinutes { get; init; } = 30;
    public int AbsoluteTimeoutMinutes { get; init; } = 240;
    public string SessionCookieName { get; init; } = "adwm.sid";
}

public class Session
{
    public string Sid { get; set; } = string.Empty;
    public string Fingerprint { get; set; } = string.Empty;
    public string CsrfToken { get; set; } = string.Empty;
    public DateTime Created { get; set; }
    public DateTime LastSeen { get; set; }
}

public class SecurityService
{
    private readonly SecurityOptions _opts;
    public string SessionCookieName => _opts.SessionCookieName;

    public SecurityService(SecurityOptions opts) { _opts = opts; }

    public Session EnsureSession(HttpContext ctx)
    {
        var session = GetSession(ctx);
        if (session != null)
        {
            var idle = DateTime.UtcNow - session.LastSeen;
            var total = DateTime.UtcNow - session.Created;
            if (idle.TotalMinutes > _opts.IdleTimeoutMinutes || total.TotalMinutes > _opts.AbsoluteTimeoutMinutes)
                session = null;
        }

        if (session == null)
        {
            session = new Session
            {
                Sid = Guid.NewGuid().ToString("N"),
                Fingerprint = CreateFingerprint(ctx),
                CsrfToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
                Created = DateTime.UtcNow,
                LastSeen = DateTime.UtcNow
            };
        }
        else
        {
            session.LastSeen = DateTime.UtcNow;
        }

        var json = JsonSerializer.Serialize(session);
        var encrypted = Protect(json, session.Fingerprint);
        ctx.Response.Cookies.Append(SessionCookieName, encrypted, new CookieOptions
        {
            HttpOnly = true,
            Secure = ctx.Request.IsHttps,
            SameSite = SameSiteMode.Strict
        });
        return session;
    }

    public string GetCsrf(HttpContext ctx) => EnsureSession(ctx).CsrfToken;

    public bool ValidateCsrf(HttpContext ctx)
    {
        var session = GetSession(ctx);
        if (session == null) return false;
        var header = ctx.Request.Headers["X-CSRF-Token"].FirstOrDefault();
        return header != null && header == session.CsrfToken;
    }

    public void ClearSession(HttpContext ctx)
    {
        ctx.Response.Cookies.Delete(SessionCookieName);
    }

    private Session? GetSession(HttpContext ctx)
    {
        var cookie = ctx.Request.Cookies[SessionCookieName];
        if (string.IsNullOrEmpty(cookie)) return null;

        var fp = CreateFingerprint(ctx);
        try
        {
            var json = Unprotect(cookie, fp);
            return JsonSerializer.Deserialize<Session>(json);
        }
        catch { return null; }
    }

    private static string CreateFingerprint(HttpContext ctx)
    {
        var ua = ctx.Request.Headers["User-Agent"].ToString();
        var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? string.Empty;
        using var sha = SHA256.Create();
        var bytes = sha.ComputeHash(System.Text.Encoding.UTF8.GetBytes(ua + ip));
        return Convert.ToBase64String(bytes);
    }
    
    // NOTE: In a real app, use ASP.NET Core Data Protection for this.
    // This is a placeholder symmetric encryption for demonstration.
    private static string Protect(string plaintext, string key)
    {
        using var aes = Aes.Create();
        aes.Key = new SHA256Managed().ComputeHash(System.Text.Encoding.UTF8.GetBytes(key));
        aes.IV = new byte[16]; // Fixed IV for simplicity, DO NOT use in production
        using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
        using var ms = new System.IO.MemoryStream();
        using var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);
        using (var sw = new System.IO.StreamWriter(cs)) sw.Write(plaintext);
        return Convert.ToBase64String(ms.ToArray());
    }

    private static string Unprotect(string ciphertext, string key)
    {
        using var aes = Aes.Create();
        aes.Key = new SHA256Managed().ComputeHash(System.Text.Encoding.UTF8.GetBytes(key));
        aes.IV = new byte[16]; // Fixed IV for simplicity, DO NOT use in production
        using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
        using var ms = new System.IO.MemoryStream(Convert.FromBase64String(ciphertext));
        using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
        using var sr = new System.IO.StreamReader(cs);
        return sr.ReadToEnd();
    }
}

