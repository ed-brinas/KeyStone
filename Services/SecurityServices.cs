using System;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;

namespace ADWebManager.Services
{
    public class SecurityOptions
    {
        /// <summary>Idle timeout (minutes) before a session is invalidated.</summary>
        public int IdleTimeoutMinutes { get; set; } = 20;

        /// <summary>Absolute session lifetime (minutes) before re-bootstrap is required.</summary>
        public int AbsoluteTimeoutMinutes { get; set; } = 120;

        /// <summary>Name of the session cookie you’ll see in the browser.</summary>
        public string SessionCookieName { get; set; } = "adwm.sid";
    }

    public record SessionInfo(string Id, string Fingerprint, string Csrf, DateTime CreatedUtc, DateTime LastSeenUtc);

    /// <summary>
    /// Minimal, offline session & CSRF manager on top of Windows auth.
    /// - Issues a session cookie with SameSite=Strict, HttpOnly, Secure.
    /// - Generates per-session device fingerprint (UA + IP hash).
    /// - Issues CSRF token; APIs must require header "X-CSRF-Token" on unsafe methods.
    /// - Enforces idle and absolute timeouts.
    /// </summary>
    public class SecurityService
    {
        private readonly SecurityOptions _opts;
        private readonly ConcurrentDictionary<string, SessionInfo> _sessions = new();

        public SecurityService(SecurityOptions opts) { _opts = opts ?? new SecurityOptions(); }

        public SessionInfo EnsureSession(HttpContext ctx, bool renewIfExpired = true)
        {
            var now = DateTime.UtcNow;
            var sid = ctx.Request.Cookies[_opts.SessionCookieName];
            var fp = ComputeFingerprint(ctx);

            if (string.IsNullOrWhiteSpace(sid) || !_sessions.TryGetValue(sid, out var s))
            {
                s = NewSession(fp, now);
                _sessions[s.Id] = s;
                WriteCookie(ctx, s.Id);
                return s;
            }

            // Enforce fingerprint pinning
            if (!string.Equals(s.Fingerprint, fp, StringComparison.Ordinal))
            {
                s = NewSession(fp, now);
                _sessions[s.Id] = s;
                WriteCookie(ctx, s.Id);
                return s;
            }

            // Enforce timeouts
            var idle = now - s.LastSeenUtc;
            var age  = now - s.CreatedUtc;
            if (idle.TotalMinutes > _opts.IdleTimeoutMinutes || age.TotalMinutes > _opts.AbsoluteTimeoutMinutes)
            {
                if (renewIfExpired)
                {
                    s = NewSession(fp, now);
                    _sessions[s.Id] = s;
                    WriteCookie(ctx, s.Id);
                }
                else
                {
                    // mark as expired; caller may reject
                    return s with { LastSeenUtc = s.LastSeenUtc.AddMinutes(_opts.IdleTimeoutMinutes + 1) };
                }
            }
            else
            {
                s = s with { LastSeenUtc = now };
                _sessions[s.Id] = s;
            }

            return s;
        }

        public bool ValidateCsrf(HttpContext ctx)
        {
            var sid = ctx.Request.Cookies[_opts.SessionCookieName];
            if (string.IsNullOrWhiteSpace(sid)) return false;
            if (!_sessions.TryGetValue(sid, out var s)) return false;

            // Reject if idle/absolute timeouts exceeded
            var now = DateTime.UtcNow;
            if ((now - s.LastSeenUtc).TotalMinutes > _opts.IdleTimeoutMinutes) return false;
            if ((now - s.CreatedUtc).TotalMinutes > _opts.AbsoluteTimeoutMinutes) return false;

            var header = ctx.Request.Headers["X-CSRF-Token"].ToString();
            if (string.IsNullOrWhiteSpace(header)) return false;
            if (!string.Equals(header, s.Csrf, StringComparison.Ordinal)) return false;

            // Update last seen
            _sessions[sid] = s with { LastSeenUtc = now };
            return true;
        }

        public string GetCsrf(HttpContext ctx)
        {
            var s = EnsureSession(ctx);
            return s.Csrf;
        }

        private static string ComputeFingerprint(HttpContext ctx)
        {
            var ua = ctx.Request.Headers["User-Agent"].ToString();
            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "0.0.0.0";
            using var sha256 = SHA256.Create();
            var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(ua + "|" + ip));
            return Convert.ToHexString(bytes);
        }

        private static string NewId()
        {
            var bytes = new byte[16]; RandomNumberGenerator.Fill(bytes);
            return Convert.ToHexString(bytes);
        }

        private static string NewToken()
        {
            var bytes = new byte[16]; RandomNumberGenerator.Fill(bytes);
            return Convert.ToHexString(bytes);
        }

        private SessionInfo NewSession(string fingerprint, DateTime now)
        {
            return new SessionInfo(NewId(), fingerprint, NewToken(), now, now);
        }

        private void WriteCookie(HttpContext ctx, string sid)
        {
            ctx.Response.Cookies.Append(_opts.SessionCookieName, sid, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Path = "/",
                IsEssential = true,
                Expires = DateTimeOffset.UtcNow.AddMinutes(_opts.AbsoluteTimeoutMinutes)
            });
        }
    }
}
