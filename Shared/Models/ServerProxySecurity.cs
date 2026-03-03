using System.Collections.Generic;

namespace Shared.Models.ServerProxy
{
    public class ProxySecurityConf
    {
        public bool whitelistEnabled { get; set; } = true;

        public List<string> whitelistDomains { get; set; } = new List<string>
        {
            "api.themoviedb.org",
            "image.tmdb.org",
            "*.themoviedb.org",
            "*.tmdb.org"
        };

        public bool allowPrivateIps { get; set; } = false;

        public bool allowDirectIp { get; set; } = false;

        public bool enforceHttps { get; set; } = true;

        public List<string> blockedIpRanges { get; set; } = new List<string>();

        public int dnsCacheTtl { get; set; } = 60;

        public bool enableSecurityLog { get; set; } = true;

        public string securityLogFile { get; set; } = "cache/logs/proxy-security.log";
    }
}
