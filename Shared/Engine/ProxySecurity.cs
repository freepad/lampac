using Microsoft.Extensions.Caching.Memory;
using Shared.Models.ServerProxy;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Shared.Engine
{
    public static class ProxySecurity
    {
        // DNS cache: domain -> (IPAddress, expiryTime)
        private static readonly ConcurrentDictionary<string, (IPAddress ip, DateTime expiry)> _dnsCache = new();

        private static readonly Regex _wildcardRegex = new(@"^\*\.", RegexOptions.Compiled | RegexOptions.IgnoreCase);

        public static readonly ProxySecurityConf DefaultConfig = new ProxySecurityConf();

        private static readonly List<string> _defaultWhitelist = new List<string>
        {
            "api.themoviedb.org",
            "image.tmdb.org",
            "*.themoviedb.org",
            "*.tmdb.org"
        };

        private static readonly HashSet<string> _blockedSchemes = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "file",
            "ftp",
            "gopher",
            "mailto",
            "data",
            "javascript",
            "vbscript"
        };

        public static void Initialize(IMemoryCache cache)
        {
            Directory.CreateDirectory("cache/logs");
        }

        public static ProxySecurityConf GetEffectiveConfig(ProxySecurityConf? config)
        {
            return config ?? DefaultConfig;
        }

        public static bool IsDomainAllowed(string domain, List<string> whitelist)
        {
            if (string.IsNullOrWhiteSpace(domain))
                return false;

            var effectiveWhitelist = whitelist?.Count > 0 ? whitelist : _defaultWhitelist;

            foreach (var allowedDomain in effectiveWhitelist)
            {
                if (MatchesDomain(domain, allowedDomain))
                    return true;
            }

            return false;
        }

        private static bool MatchesDomain(string domain, string pattern)
        {
            if (string.Equals(domain, pattern, StringComparison.OrdinalIgnoreCase))
                return true;

            if (pattern.StartsWith("*."))
            {
                var wildcardPart = pattern.Substring(2); // Remove "*."
                return domain.Equals(wildcardPart, StringComparison.OrdinalIgnoreCase) ||
                       domain.EndsWith("." + wildcardPart, StringComparison.OrdinalIgnoreCase);
            }

            return false;
        }
        
        public static bool IsPrivateIp(string ip)
        {
            if (string.IsNullOrWhiteSpace(ip))
                return false;

            if (IPAddress.TryParse(ip, out var ipAddress) && ipAddress.AddressFamily == AddressFamily.InterNetwork)
            {
                var bytes = ipAddress.GetAddressBytes();

                return bytes[0] switch
                {
                    0 => true,       // 0.0.0.0/8 - Current network (only valid as source)
                    10 => true,       // 10.0.0.0/8 - Private Class A
                    127 => true,      // 127.0.0.0/8 - Loopback
                    169 when bytes[1] == 254 => true,  // 169.254.0.0/16 - Link-local
                    172 when bytes[1] >= 16 && bytes[1] <= 31 => true,  // 172.16.0.0/12 - Private Class B
                    192 when bytes[1] == 168 => true,      // 192.168.0.0/16 - Private Class C
                    >= 224 and <= 239 => true,  // 224.0.0.0/4 - Multicast
                    _ => false
                };
            }

            if (IPAddress.TryParse(ip, out var ipV6) && ipV6.AddressFamily == AddressFamily.InterNetworkV6)
            {
                var bytes = ipV6.GetAddressBytes();

                // ::1 - Loopback
                if (bytes.SequenceEqual(new byte[16] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }))
                    return true;

                // fc00::/7 - Unique Local
                if ((bytes[0] & 0xFE) == 0xFC)
                    return true;

                // fe80::/10 - Link-Local
                if ((bytes[0] & 0xFF) == 0xFE && (bytes[1] & 0xC0) == 0x80)
                    return true;

                // ff00::/8 - Multicast
                if ((bytes[0] & 0xFF) == 0xFF)
                    return true;
            }

            return false;
        }
        
        public static bool IsSchemeAllowed(string scheme, ProxySecurityConf config)
        {
            if (config.enforceHttps)
            {
                return "https".Equals(scheme, StringComparison.OrdinalIgnoreCase);
            }

            return !_blockedSchemes.Contains(scheme);
        }
        
        public static (bool Valid, string Reason) ValidateRequest(string uriString, ProxySecurityConf config, string clientIp)
        {
            if (string.IsNullOrWhiteSpace(uriString))
                return (false, "empty_uri");

            if (!Uri.TryCreate(uriString, UriKind.Absolute, out var uri))
                return (false, "invalid_uri");

            if (!IsSchemeAllowed(uri.Scheme, config))
            {
                return (false, $"blocked_scheme_{uri.Scheme}");
            }

            bool isIpRequest = IPAddress.TryParse(uri.Host, out _);

            if (isIpRequest)
            {
                if (!config.allowDirectIp)
                    return (false, "direct_ip_blocked");

                if (!config.allowPrivateIps && IsPrivateIp(uri.Host))
                    return (false, "private_ip_blocked");
            }
            else
            {
                if (config.whitelistEnabled)
                {
                    if (!IsDomainAllowed(uri.Host, config.whitelistDomains))
                        return (false, "domain_not_whitelisted");

                    var resolvedIp = ResolveDns(uri.Host, config.dnsCacheTtl);
                    if (resolvedIp != null && !config.allowPrivateIps && IsPrivateIp(resolvedIp.ToString()))
                    {
                        return (false, "dns_rebinding_detected");
                    }
                }
            }

            foreach (var blockedRange in config.blockedIpRanges)
            {
                if (IsIpInRange(uri.Host, blockedRange))
                    return (false, "blocked_ip_range");
            }

            return (true, null);
        }
        
        private static IPAddress? ResolveDns(string domain, int cacheTtl)
        {
            var now = DateTime.UtcNow;

            if (_dnsCache.TryGetValue(domain, out var cached) && cached.expiry > now)
            {
                return cached.ip;
            }

            try
            {
                var addresses = Dns.GetHostAddresses(domain);
                if (addresses.Length == 0)
                    return null;

                var firstIp = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);

                if (firstIp != null)
                {
                    _dnsCache.AddOrUpdate(domain,
                        (firstIp, now.AddSeconds(cacheTtl)),
                        (_, __) => (firstIp, now.AddSeconds(cacheTtl)));
                }

                return firstIp;
            }
            catch
            {
                return null;
            }
        }
        
        private static bool IsIpInRange(string ip, string range)
        {
            if (IPAddress.TryParse(ip, out var ipAddress) &&
                IPAddress.TryParse(range.Split('/')[0], out var rangeIp))
            {
                var ipBytes = ipAddress.GetAddressBytes();
                var rangeBytes = rangeIp.GetAddressBytes();

                for (int i = 0; i < ipBytes.Length && i < rangeBytes.Length; i++)
                {
                    if (ipBytes[i] != rangeBytes[i])
                        return false;
                }

                return true;
            }

            return range.StartsWith(ip, StringComparison.OrdinalIgnoreCase) ||
                   ip.StartsWith(range, StringComparison.OrdinalIgnoreCase);
        }
        
        public static void LogSecurityEvent(string action, string domain, string clientIp, bool blocked, string? reason = null)
        {
            try
            {
                var logEntry = new
                {
                    timestamp = DateTime.UtcNow.ToString("o"),
                    action = action,
                    domain = domain,
                    clientIp = clientIp,
                    blocked = blocked,
                    reason = reason
                };

                string logLine = Newtonsoft.Json.JsonConvert.SerializeObject(logEntry);
                File.AppendAllText("cache/logs/proxy-security.log", logLine + "\n");
            }
            catch
            {
                // Fail silently to avoid disrupting proxy operation
            }
        }

        public static (bool Allowed, string? ErrorReason, string Domain) ValidateRequestWithLogging(
            string uriString,
            ProxySecurityConf? config,
            string clientIp,
            string action)
        {
            var effectiveConfig = GetEffectiveConfig(config);

            string domain = "unknown";
            try
            {
                if (Uri.TryCreate(uriString, UriKind.Absolute, out var uriObj))
                    domain = uriObj.Host;
            }
            catch { }

            var (valid, reason) = ValidateRequest(uriString, effectiveConfig, clientIp);

            if (!valid)
            {
                if (effectiveConfig.enableSecurityLog)
                {
                    LogSecurityEvent(action, domain, clientIp, true, reason);
                }
                return (false, reason, domain);
            }

            if (effectiveConfig.enableSecurityLog)
            {
                LogSecurityEvent(action, domain, clientIp, false);
            }

            return (true, null, domain);
        }

        public static void ClearExpiredDnsCache()
        {
            var now = DateTime.UtcNow;

            foreach (var entry in _dnsCache)
            {
                if (entry.Value.expiry <= now)
                {
                    _dnsCache.TryRemove(entry.Key, out _);
                }
            }
        }
    }
}
