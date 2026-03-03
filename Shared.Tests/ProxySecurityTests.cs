using Microsoft.Extensions.Caching.Memory;
using Shared.Engine;
using Shared.Models.ServerProxy;
using Xunit;

namespace Shared.Tests
{
    public class ProxySecurityTests
    {
        private readonly IMemoryCache _memoryCache;
        private readonly ProxySecurityConf _config;

        public ProxySecurityTests()
        {
            _memoryCache = new MemoryCache(new MemoryCacheOptions());
            ProxySecurity.Initialize(_memoryCache);

            _config = new ProxySecurityConf
            {
                whitelistEnabled = true,
                whitelistDomains = new List<string>
                {
                    "api.themoviedb.org",
                    "image.tmdb.org",
                    "*.themoviedb.org",
                    "*.tmdb.org"
                },
                allowPrivateIps = false,
                allowDirectIp = false,
                enforceHttps = true,
                dnsCacheTtl = 60,
                enableSecurityLog = false
            };
        }

        #region Domain Whitelist Tests

        [Fact]
        public void IsDomainAllowed_WhitelistedDomain_ReturnsTrue()
        {
            var result = ProxySecurity.IsDomainAllowed("api.themoviedb.org", _config.whitelistDomains);
            Assert.True(result);
        }

        [Fact]
        public void IsDomainAllowed_WhitelistedSubdomain_ReturnsTrue()
        {
            var result = ProxySecurity.IsDomainAllowed("sub.tmdb.org", new List<string> { "*.tmdb.org" });
            Assert.True(result);
        }

        [Fact]
        public void IsDomainAllowed_NonWhitelistedDomain_ReturnsFalse()
        {
            var result = ProxySecurity.IsDomainAllowed("example.com", _config.whitelistDomains);
            Assert.False(result);
        }

        [Fact]
        public void IsDomainAllowed_EmptyDomain_ReturnsFalse()
        {
            var result = ProxySecurity.IsDomainAllowed("", _config.whitelistDomains);
            Assert.False(result);
        }

        [Fact]
        public void IsDomainAllowed_WildcardMatchesSubdomain()
        {
            var result = ProxySecurity.IsDomainAllowed("api.service.example.com", new List<string> { "*.example.com" });
            Assert.True(result);
        }

        [Fact]
        public void IsDomainAllowed_WildcardDoesNotMatchDifferentDomain()
        {
            var result = ProxySecurity.IsDomainAllowed("other.com", new List<string> { "*.example.com" });
            Assert.False(result);
        }

        [Fact]
        public void IsDomainAllowed_UsesDefaultWhitelistWhenEmpty()
        {
            var result = ProxySecurity.IsDomainAllowed("api.themoviedb.org", new List<string>());
            Assert.True(result);
        }

        #endregion

        #region Private IP Tests

        [Theory]
        [InlineData("127.0.0.1")]
        [InlineData("127.0.0.2")]
        [InlineData("127.255.255.255")]
        [InlineData("127.0.0.0")]
        public void IsPrivateIp_Loopback_ReturnsTrue(string ip)
        {
            Assert.True(ProxySecurity.IsPrivateIp(ip));
        }

        [Theory]
        [InlineData("10.0.0.1")]
        [InlineData("10.1.0.1")]
        [InlineData("10.255.255.255")]
        [InlineData("10.128.0.1")]
        public void IsPrivateIp_PrivateClassA_ReturnsTrue(string ip)
        {
            Assert.True(ProxySecurity.IsPrivateIp(ip));
        }

        [Theory]
        [InlineData("172.16.0.1")]
        [InlineData("172.16.255.255")]
        [InlineData("172.31.0.1")]
        [InlineData("172.31.255.255")]
        public void IsPrivateIp_PrivateClassB_ReturnsTrue(string ip)
        {
            Assert.True(ProxySecurity.IsPrivateIp(ip));
        }

        [Theory]
        [InlineData("192.168.0.1")]
        [InlineData("192.168.1.1")]
        [InlineData("192.168.100.1")]
        [InlineData("192.168.255.255")]
        public void IsPrivateIp_PrivateClassC_ReturnsTrue(string ip)
        {
            Assert.True(ProxySecurity.IsPrivateIp(ip));
        }

        [Theory]
        [InlineData("169.254.1.1")]
        [InlineData("169.254.100.1")]
        public void IsPrivateIp_LinkLocal_ReturnsTrue(string ip)
        {
            Assert.True(ProxySecurity.IsPrivateIp(ip));
        }

        [Theory]
        [InlineData("224.0.0.1")]
        [InlineData("224.0.1.1")]
        [InlineData("239.255.255.255")]
        public void IsPrivateIp_Multicast_ReturnsTrue(string ip)
        {
            Assert.True(ProxySecurity.IsPrivateIp(ip));
        }

        [Theory]
        [InlineData("0.0.0.0")]
        [InlineData("0.0.0.1")]
        public void IsPrivateIp_CurrentNetwork_ReturnsTrue(string ip)
        {
            Assert.True(ProxySecurity.IsPrivateIp(ip));
        }

        [Theory]
        [InlineData("8.8.8.8")]
        [InlineData("1.1.1.1")]
        [InlineData("203.0.113.1")]
        public void IsPrivateIp_PublicIP_ReturnsFalse(string ip)
        {
            Assert.False(ProxySecurity.IsPrivateIp(ip));
        }

        [Theory]
        [InlineData("google.com")]
        [InlineData("invalid-ip")]
        [InlineData("256.256.256.256")]
        public void IsPrivateIp_InvalidIP_ReturnsFalse(string ip)
        {
            Assert.False(ProxySecurity.IsPrivateIp(ip));
        }

        #endregion

        #region IPv6 Private IP Tests

        [Fact]
        public void IsPrivateIp_IPv6Loopback_ReturnsTrue()
        {
            Assert.True(ProxySecurity.IsPrivateIp("::1"));
        }

        [Fact]
        public void IsPrivateIp_IPv6UniqueLocal_ReturnsTrue()
        {
            Assert.True(ProxySecurity.IsPrivateIp("fc00::1"));
            Assert.True(ProxySecurity.IsPrivateIp("fd00::1"));
            Assert.True(ProxySecurity.IsPrivateIp("fc00:0:0:0::1"));
        }

        [Fact]
        public void IsPrivateIp_IPv6LinkLocal_ReturnsTrue()
        {
            Assert.True(ProxySecurity.IsPrivateIp("fe80::1"));
            Assert.True(ProxySecurity.IsPrivateIp("fe80::abcd:1"));
        }

        [Fact]
        public void IsPrivateIp_IPv6Multicast_ReturnsTrue()
        {
            Assert.True(ProxySecurity.IsPrivateIp("ff00::1"));
            Assert.True(ProxySecurity.IsPrivateIp("ff02::1"));
        }

        [Fact]
        public void IsPrivateIp_IPv6Public_ReturnsFalse()
        {
            Assert.False(ProxySecurity.IsPrivateIp("2001:db8::1"));
            Assert.False(ProxySecurity.IsPrivateIp("2001:0db8::85a3::0db8"));
        }

        #endregion

        #region Scheme Validation Tests

        [Fact]
        public void IsSchemeAllowed_HTTPS_WithEnforceHttps_ReturnsFalse()
        {
            var config = new ProxySecurityConf { enforceHttps = true };
            Assert.False(ProxySecurity.IsSchemeAllowed("http", config));
        }

        [Fact]
        public void IsSchemeAllowed_HTTPS_WithoutEnforceHttps_ReturnsTrue()
        {
            var config = new ProxySecurityConf { enforceHttps = false };
            Assert.True(ProxySecurity.IsSchemeAllowed("http", config));
        }

        [Theory]
        [InlineData("https")]
        [InlineData("HTTPS")]
        [InlineData("HttPs")]
        public void IsSchemeAllowed_HTTPS_ReturnsTrue(string scheme)
        {
            Assert.True(ProxySecurity.IsSchemeAllowed(scheme, _config));
        }

        [Theory]
        [InlineData("file")]
        [InlineData("ftp")]
        [InlineData("gopher")]
        [InlineData("mailto")]
        [InlineData("data")]
        [InlineData("javascript")]
        [InlineData("vbscript")]
        public void IsSchemeAllowed_BlockedSchemes_ReturnsFalse(string scheme)
        {
            Assert.False(ProxySecurity.IsSchemeAllowed(scheme, _config));
        }

        #endregion

        #region ValidateRequest Combined Tests

        [Fact]
        public void ValidateRequest_ValidHTTPSWhitelistedDomain_ReturnsTrue()
        {
            var (valid, reason) = ProxySecurity.ValidateRequest(
                "https://api.themoviedb.org/path",
                _config,
                "1.2.3.4"
            );

            Assert.True(valid);
            Assert.Null(reason);
        }

        [Fact]
        public void ValidateRequest_HTTP_URL_ReturnsFalse()
        {
            var (valid, reason) = ProxySecurity.ValidateRequest(
                "http://example.com/path",
                _config,
                "1.2.3.4"
            );

            Assert.False(valid);
            Assert.Equal("blocked_scheme_http", reason);
        }

        [Fact]
        public void ValidateRequest_FileURL_ReturnsFalse()
        {
            var (valid, reason) = ProxySecurity.ValidateRequest(
                "file:///etc/passwd",
                _config,
                "1.2.3.4"
            );

            Assert.False(valid);
            Assert.Equal("blocked_scheme_file", reason);
        }

        [Fact]
        public void ValidateRequest_NonWhitelistedDomain_ReturnsFalse()
        {
            var (valid, reason) = ProxySecurity.ValidateRequest(
                "https://example.com/path",
                _config,
                "1.2.3.4"
            );

            Assert.False(valid);
            Assert.Equal("domain_not_whitelisted", reason);
        }

        [Fact]
        public void ValidateRequest_PrivateIP_ReturnsFalse()
        {
            // When allowDirectIp is false (default), any IP URL is blocked first
            var (valid, reason) = ProxySecurity.ValidateRequest(
                "https://10.0.0.1/path",
                _config,
                "1.2.3.4"
            );

            Assert.False(valid);
            Assert.Equal("direct_ip_blocked", reason);
        }

        [Fact]
        public void ValidateRequest_PrivateIP_WithDirectIpAllowed_ReturnsFalse()
        {
            // Test private IP blocking when direct IPs are allowed
            var config = new ProxySecurityConf
            {
                whitelistEnabled = false,
                allowPrivateIps = false,
                allowDirectIp = true,
                enforceHttps = true
            };

            var (valid, reason) = ProxySecurity.ValidateRequest(
                "https://10.0.0.1/path",
                config,
                "1.2.3.4"
            );

            Assert.False(valid);
            Assert.Equal("private_ip_blocked", reason);
        }

        [Fact]
        public void ValidateRequest_DirectIP_ReturnsFalse()
        {
            var (valid, reason) = ProxySecurity.ValidateRequest(
                "https://8.8.8.8/path",
                _config,
                "1.2.3.4"
            );

            Assert.False(valid);
            Assert.Equal("direct_ip_blocked", reason);
        }

        [Fact]
        public void ValidateRequest_EmptyURI_ReturnsFalse()
        {
            var (valid, reason) = ProxySecurity.ValidateRequest("", _config, "1.2.3.4");

            Assert.False(valid);
            Assert.Equal("empty_uri", reason);
        }

        [Fact]
        public void ValidateRequest_InvalidURI_ReturnsFalse()
        {
            var (valid, reason) = ProxySecurity.ValidateRequest("://invalid", _config, "1.2.3.4");

            Assert.False(valid);
            Assert.Equal("invalid_uri", reason);
        }

        [Fact]
        public void ValidateRequest_WithAllowPrivateIps_AcceptsPrivateIP()
        {
            var config = new ProxySecurityConf
            {
                whitelistEnabled = true,
                whitelistDomains = _config.whitelistDomains,
                allowPrivateIps = true,
                allowDirectIp = true,  // Must be true to test allowPrivateIps with IP URLs
                enforceHttps = true
            };

            var (valid, reason) = ProxySecurity.ValidateRequest(
                "https://10.0.0.1/path",
                config,
                "1.2.3.4"
            );

            Assert.True(valid);
            Assert.Null(reason);
        }

        [Fact]
        public void ValidateRequest_WithAllowDirectIp_AcceptsDirectIP()
        {
            var config = new ProxySecurityConf
            {
                whitelistEnabled = true,
                whitelistDomains = _config.whitelistDomains,
                allowPrivateIps = false,
                allowDirectIp = true,
                enforceHttps = true
            };

            var (valid, reason) = ProxySecurity.ValidateRequest(
                "https://8.8.8.8/path",
                config,
                "1.2.3.4"
            );

            Assert.True(valid);
            Assert.Null(reason);
        }

        #endregion
    }
}
