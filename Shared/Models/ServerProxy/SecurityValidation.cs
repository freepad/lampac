using System;
using System.Collections.Generic;
using System.Linq;

namespace Shared.Models.ServerProxy
{
    public class ProxySecurityValidationResult
    {
        public bool IsValid { get; set; }
        public List<string> Errors { get; set; } = new List<string>();
        public List<string> Warnings { get; set; } = new List<string>();
    }
    
    public static class ProxySecurityValidator
    {
        public static ProxySecurityValidationResult Validate(ProxySecurityConf config)
        {
            var result = new ProxySecurityValidationResult();

            if (config == null)
            {
                result.Errors.Add("Security configuration is null");
                result.IsValid = false;
                return result;
            }

            if (config.whitelistEnabled)
            {
                if (config.whitelistDomains == null || config.whitelistDomains.Count == 0)
                {
                    result.Warnings.Add("Whitelist is enabled but no domains configured - using default whitelist");
                }

                if (config.whitelistDomains != null)
                {
                    foreach (var domain in config.whitelistDomains)
                    {
                        if (string.IsNullOrWhiteSpace(domain))
                            result.Warnings.Add("Empty domain in whitelist configuration");
                        else if (!IsValidDomainFormat(domain))
                            result.Errors.Add($"Invalid domain format: {domain}");
                        else if (IsDangerousDomain(domain))
                            result.Warnings.Add($"Potentially dangerous domain in whitelist: {domain}");
                    }
                }
                result.IsValid = result.Errors.Count == 0;
            }

            if (config.allowPrivateIps)
                result.Warnings.Add("allowPrivateIps is enabled - this may expose internal services");

            if (config.allowDirectIp)
                result.Warnings.Add("allowDirectIp is enabled - this may allow bypass of domain controls");

            if (config.dnsCacheTtl < 0)
                result.Errors.Add("dnsCacheTtl must be >= 0");
            else if (config.dnsCacheTtl > 3600)
                result.Warnings.Add("dnsCacheTtl > 3600 seconds (1 hour) - consider reducing for faster security updates");

            if (string.IsNullOrWhiteSpace(config.securityLogFile))
                result.Warnings.Add("securityLogFile is not configured - logging to default path");

            if (config.blockedIpRanges != null && config.blockedIpRanges.Count > 0)
            {
                foreach (var range in config.blockedIpRanges)
                {
                    if (!IsValidIpRangeFormat(range))
                        result.Warnings.Add($"Potentially invalid IP range format: {range}");
                    else if (IsPrivateIpRange(range) && !config.allowPrivateIps)
                        result.Warnings.Add($"Blocked range includes private IP which is already blocked: {range}");
                }
            }

            result.IsValid = result.Errors.Count == 0;
            return result;
        }

        private static bool IsValidDomainFormat(string domain)
        {
            if (string.IsNullOrWhiteSpace(domain))
                return false;

            var domainToValidate = domain.StartsWith("*.")
                ? domain.Substring(2)
                : domain;

            var parts = domainToValidate.Split('.');
            if (parts.Length < 2)
                return false;

            foreach (var part in parts)
            {
                if (string.IsNullOrWhiteSpace(part))
                    return false;

                if (part.Length > 63)
                    return false;
            }

            if (domainToValidate.Length > 253)
                return false;

            return true;
        }

        private static bool IsDangerousDomain(string domain)
        {
            var lowerDomain = domain.ToLowerInvariant();

            // Internal/local domains
            if (lowerDomain.Contains("localhost") ||
                lowerDomain.Contains("127.") ||
                lowerDomain.Contains("192.168.") ||
                lowerDomain.Contains("10.") ||
                lowerDomain.Contains("172.16.") ||
                lowerDomain.Contains("internal") ||
                lowerDomain.Contains("intranet"))
                return true;

            return false;
        }

        private static bool IsValidIpRangeFormat(string range)
        {
            if (string.IsNullOrWhiteSpace(range))
                return false;

            var parts = range.Split('/', '-');
            if (parts.Length > 2)
                return false;

            if (!System.Net.IPAddress.TryParse(parts[0], out _))
                return false;

            return true;
        }

        private static bool IsPrivateIpRange(string range)
        {
            var lowerRange = range.ToLowerInvariant();

            return lowerRange.StartsWith("127.") ||
                   lowerRange.StartsWith("10.") ||
                   lowerRange.StartsWith("192.168.") ||
                   lowerRange.StartsWith("172.16.") ||
                   lowerRange.StartsWith("172.17.") ||
                   lowerRange.StartsWith("172.18.") ||
                   lowerRange.StartsWith("172.19.") ||
                   lowerRange.StartsWith("172.20.") ||
                   lowerRange.StartsWith("172.21.") ||
                   lowerRange.StartsWith("172.22.") ||
                   lowerRange.StartsWith("172.23.") ||
                   lowerRange.StartsWith("172.24.") ||
                   lowerRange.StartsWith("172.25.") ||
                   lowerRange.StartsWith("172.26.") ||
                   lowerRange.StartsWith("172.27.") ||
                   lowerRange.StartsWith("172.28.") ||
                   lowerRange.StartsWith("172.29.") ||
                   lowerRange.StartsWith("172.30.") ||
                   lowerRange.StartsWith("172.31.");
        }
    }
}
