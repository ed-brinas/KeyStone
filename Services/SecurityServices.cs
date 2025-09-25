using Microsoft.AspNetCore.Http;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ADWebManager.Services
{
    public class SecurityOptions
    {
        public int IdleTimeoutMinutes { get; set; } = 20;
        public int AbsoluteTimeoutMinutes { get; set; } = 240;
        public string SessionCookieName { get; set; } = "adwm.sid";
    }

    public class SessionState
    {
        public DateTime Created { get; set; }
        public DateTime LastSeen { get; set; }
        public string CsrfToken { get; set; } = string.Empty;
        public string Fingerprint { get; set; } = string.Empty;
    }

    public class SecurityService
    {
        private readonly SecurityOptions _options;

        public SecurityService(SecurityOptions options)
        {
            _options = options;
        }

        public SessionState EnsureSession(HttpContext ctx)
        {
            var state = GetSession(ctx);
            if (state == null)
            {
                state = new SessionState
                {
                    Created = DateTime.UtcNow,
                    LastSeen = DateTime.UtcNow,
                    CsrfToken = Guid.NewGuid().ToString("N"),
                    Fingerprint = GetFingerprint(ctx)
                };
                SetSession(ctx, state);
            }
            else
            {
                state.LastSeen = DateTime.UtcNow;
                SetSession(ctx, state); 
            }
            return state;
        }

        public bool ValidateCsrf(HttpContext ctx)
        {
            var session = GetSession(ctx);
            if (session == null) return false;

            var fromHeader = ctx.Request.Headers["X-CSRF-Token"].FirstOrDefault();
            return !string.IsNullOrEmpty(fromHeader) && fromHeader == session.CsrfToken;
        }

        public string GetCsrf(HttpContext ctx) => EnsureSession(ctx).CsrfToken;

        public void DestroySession(HttpContext ctx)
        {
            ctx.Response.Cookies.Delete(_options.SessionCookieName);
        }

        private SessionState? GetSession(HttpContext ctx)
        {
            if (!ctx.Request.Cookies.TryGetValue(_options.SessionCookieName, out var cookie)) return null;
            try
            {
                var state = JsonSerializer.Deserialize<SessionState>(cookie);
                if (state == null) return null;

                // Validate session
                var now = DateTime.UtcNow;
                if ((now - state.Created).TotalMinutes > _options.AbsoluteTimeoutMinutes) return null;
                if ((now - state.LastSeen).TotalMinutes > _options.IdleTimeoutMinutes) return null;
                if (state.Fingerprint != GetFingerprint(ctx)) return null;

                return state;
            }
            catch { return null; }
        }

        private void SetSession(HttpContext ctx, SessionState state)
        {
            var json = JsonSerializer.Serialize(state);
            ctx.Response.Cookies.Append(_options.SessionCookieName, json, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddMinutes(_options.AbsoluteTimeoutMinutes)
            });
        }

        private static string GetFingerprint(HttpContext ctx)
        {
            var ua = ctx.Request.Headers["User-Agent"].ToString();
            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "?.?.?.?";
            using var sha = SHA256.Create();
            var bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(ua + ip));
            return Convert.ToBase64String(bytes);
        }
    }
}

