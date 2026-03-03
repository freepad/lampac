using Microsoft.Extensions.Caching.Memory;
using Shared.Engine;
using Shared.Models.ServerProxy;
using Xunit;
using System.Collections.Generic;

namespace Shared.Tests
{
    /// <summary>
    /// Tests for ProxySecurity.ValidateRequestWithLogging method which is used by ProxyAPI middleware.
    /// These tests verify the security validation logic that protects against SSRF attacks.
    /// </summary>
    public class ProxyAPIIntegrationTests
    {
        private readonly IMemoryCache _memoryCache;
        private readonly ProxySecurityConf _config;
        private readonly string _testClientIp = "192.168.1.100";
        private readonly string _testAction = "proxy_request";

        public ProxyAPIIntegrationTests()
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
                enableSecurityLog = false  // Disable logging during tests to avoid file I/O
            };
        }

        #region Whitelisted Domain Tests

        /// <summary>
        /// Test that proxy request to whitelisted domain succeeds.
        /// Expected: Allowed with no error reason.
        /// </summary>
        [Fact]
        public void ProxyRequest_WhitelistedDomain_Succeeds()
        {
            // Arrange
            string uri = "https://api.themoviedb.org/3/movie/550";

            // Act
            var (allowed, errorReason, domain) = ProxySecurity.ValidateRequestWithLogging(
                uri, _config, _testClientIp, _testAction);

            // Assert
            Assert.True(allowed, "Whitelisted domain should be allowed");
            Assert.Null(errorReason);
            Assert.Equal("api.themoviedb.org", domain);
        }

        /// <summary>
        /// Test that proxy request to non-whitelisted domain fails.
        /// Expected: Not allowed with "domain_not_whitelisted" reason.
        /// </summary>
        [Fact]
        public void ProxyRequest_NonWhitelistedDomain_Returns403()
        {
            // Arrange
            string uri = "https://example.com/path";

            // Act
            var (allowed, errorReason, domain) = ProxySecurity.ValidateRequestWithLogging(
                uri, _config, _testClientIp, _testAction);

            // Assert
            Assert.False(allowed, "Non-whitelisted domain should be blocked");
            Assert.Equal("domain_not_whitelisted", errorReason);
            Assert.Equal("example.com", domain);
        }

        /// <summary>
        /// Test wildcard domain matching.
        /// Expected: Allowed with no error reason.
        /// </summary>
        [Fact]
        public void ProxyRequest_WildcardDomain_Succeeds()
        {
            // Arrange
            string uri = "https://sub.tmdb.org/path";

            // Act
            var (allowed, errorReason, domain) = ProxySecurity.ValidateRequestWithLogging(
                uri, _config, _testClientIp, _testAction);

            // Assert
            Assert.True(allowed, "Wildcard domain should be allowed");
            Assert.Null(errorReason);
            Assert.Equal("sub.tmdb.org", domain);
        }

        #endregion

        #region Private IP Blocking Tests

        /// <summary>
        /// Test that proxy request to loopback address is blocked.
        /// Expected: Not allowed with "direct_ip_blocked" reason (IP URLs are blocked first before checking if private).
        /// </summary>
        [Fact]
        public void ProxyRequest_LoopbackAddress_Returns403()
        {
            // Arrange
            string uri = "https://127.0.0.1/path";

            // Act
            var (allowed, errorReason, domain) = ProxySecurity.ValidateRequestWithLogging(
                uri, _config, _testClientIp, _testAction);

            // Assert
            Assert.False(allowed, "Loopback address should be blocked");
            Assert.Equal("direct_ip_blocked", errorReason);
            Assert.Equal("127.0.0.1", domain);
        }

        /// <summary>
        /// Test that proxy request to 10.0.0.0/8 private range is blocked.
        /// Expected: Not allowed with "direct_ip_blocked" reason (IP URLs are blocked first).
        /// </summary>
        [Fact]
        public void ProxyRequest_PrivateClassA_Returns403()
        {
            // Arrange
            string uri = "https://10.0.0.1/path";

            // Act
            var (allowed, errorReason, domain) = ProxySecurity.ValidateRequestWithLogging(
                uri, _config, _testClientIp, _testAction);

            // Assert
            Assert.False(allowed);
            Assert.Equal("direct_ip_blocked", errorReason);
        }

        /// <summary>
        /// Test that proxy request to 172.16.0.0/12 private range is blocked.
        /// Expected: Not allowed with "direct_ip_blocked" reason (IP URLs are blocked first).
        /// </summary>
        [Fact]
        public void ProxyRequest_PrivateClassB_Returns403()
        {
            // Arrange
            string uri = "https://172.16.0.1/path";

            // Act
            var (allowed, errorReason, domain) = ProxySecurity.ValidateRequestWithLogging(
                uri, _config, _testClientIp, _testAction);

            // Assert
            Assert.False(allowed);
            Assert.Equal("direct_ip_blocked", errorReason);
        }

        /// <summary>
        /// Test that proxy request to 192.168.0.0/16 private range is blocked.
        /// Expected: Not allowed with "direct_ip_blocked" reason (IP URLs are blocked first).
        /// </summary>
        [Fact]
        public void ProxyRequest_PrivateClassC_Returns403()
        {
            // Arrange
            string uri = "https://192.168.1.1/path";

            // Act
            var (allowed, errorReason, domain) = ProxySecurity.ValidateRequestWithLogging(
                uri, _config, _testClientIp, _testAction);

            // Assert
            Assert.False(allowed);
            Assert.Equal("direct_ip_blocked", errorReason);
        }

        /// <summary>
        /// Test that proxy request to 169.254.0.0/16 link-local range is blocked.
        /// Expected: Not allowed with "direct_ip_blocked" reason (IP URLs are blocked first).
        /// </summary>
        [Fact]
        public void ProxyRequest_LinkLocal_Returns403()
        {
            // Arrange
            string uri = "https://169.254.169.254/path";

            // Act
            var (allowed, errorReason, domain) = ProxySecurity.ValidateRequestWithLogging(
                uri, _config, _testClientIp, _testAction);

            // Assert
            Assert.False(allowed);
            Assert.Equal("direct_ip_blocked", errorReason);
        }

        /// <summary>
        /// Test that proxy request to IPv6 loopback is blocked.
        /// Expected: Not allowed with "direct_ip_blocked" reason (IP URLs are blocked first).
        /// </summary>
        [Fact]
        public void ProxyRequest_IPv6Loopback_Returns403()
        {
            // Arrange
            string uri = "https://[::1]/path";

            // Act
            var (allowed, errorReason, domain) = ProxySecurity.ValidateRequestWithLogging(
                uri, _config, _testClientIp, _testAction);

            // Assert
            Assert.False(allowed, "IPv6 loopback should be blocked");
            Assert.Equal("direct_ip_blocked", errorReason);
        }

        /// <summary>
        /// Test that private IP is blocked when allowDirectIp is true but allowPrivateIps is false.
        /// Expected: Not allowed with "private_ip_blocked" reason.
        /// </summary>
        [Fact]
        public void ProxyRequest_PrivateIP_WithDirectIpAllowed_Returns403()
        {
            // Arrange
            var config = new ProxySecurityConf
            {
                whitelistEnabled = false,
                allowPrivateIps = false,
                allowDirectIp = true,
                enforceHttps = true,
                enableSecurityLog = false
            };
            string uri = "https://127.0.0.1/path";

            // Act
            var (allowed, errorReason, domain) = ProxySecurity.ValidateRequestWithLogging(
                uri, config, _testClientIp, _testAction);

            // Assert
            Assert.False(allowed, "Private IP should be blocked even when allowDirectIp is true");
            Assert.Equal("private_ip_blocked", errorReason);
        }

        #endregion

        #region Scheme Blocking Tests

        /// <summary>
        /// Test that proxy request to file:// URL is blocked.
        /// Expected: Not allowed with "blocked_scheme_file" reason.
        /// </summary>
        [Fact]
        public void ProxyRequest_FileURL_Returns403()
        {
            // Arrange
            string uri = "file:///etc/passwd";

            // Act
            var (allowed, errorReason, domain) = ProxySecurity.ValidateRequestWithLogging(
                uri, _config, _testClientIp, _testAction);

            // Assert
            Assert.False(allowed, "File scheme should be blocked");
            Assert.Equal("blocked_scheme_file", errorReason);
        }

        /// <summary>
        /// Test that proxy request to ftp:// URL is blocked.
        /// Expected: Not allowed with "blocked_scheme_ftp" reason.
        /// </summary>
        [Fact]
        public void ProxyRequest_FtpURL_Returns403()
        {
            // Arrange
            string uri = "ftp://example.com/file.txt";

            // Act
            var (allowed, errorReason, domain) = ProxySecurity.ValidateRequestWithLogging(
                uri, _config, _testClientIp, _testAction);

            // Assert
            Assert.False(allowed);
            Assert.Equal("blocked_scheme_ftp", errorReason);
        }

        /// <summary>
        /// Test that proxy request to http:// URL is blocked when enforceHttps is true.
        /// Expected: Not allowed with "blocked_scheme_http" reason.
        /// </summary>
        [Fact]
        public void ProxyRequest_HTTPUrl_Returns403()
        {
            // Arrange
            string uri = "http://api.themoviedb.org/path";

            // Act
            var (allowed, errorReason, domain) = ProxySecurity.ValidateRequestWithLogging(
                uri, _config, _testClientIp, _testAction);

            // Assert
            Assert.False(allowed, "HTTP scheme should be blocked when enforceHttps is true");
            Assert.Equal("blocked_scheme_http", errorReason);
        }

        /// <summary>
        /// Test that proxy request to http:// URL is allowed when enforceHttps is false.
        /// Expected: Allowed with no error reason.
        /// </summary>
        [Fact]
        public void ProxyRequest_HTTPUrl_WithEnforceHttpsFalse_Succeeds()
        {
            // Arrange
            var config = new ProxySecurityConf
            {
                whitelistEnabled = true,
                whitelistDomains = _config.whitelistDomains,
                allowPrivateIps = false,
                allowDirectIp = false,
                enforceHttps = false,
                enableSecurityLog = false
            };
            string uri = "http://api.themoviedb.org/path";

            // Act
            var (allowed, errorReason, domain) = ProxySecurity.ValidateRequestWithLogging(
                uri, config, _testClientIp, _testAction);

            // Assert
            Assert.True(allowed, "HTTP scheme should be allowed when enforceHttps is false");
            Assert.Null(errorReason);
        }

        /// <summary>
        /// Test that proxy request to data:// URL is blocked.
        /// Expected: Not allowed with "blocked_scheme_data" reason.
        /// </summary>
        [Fact]
        public void ProxyRequest_DataURL_Returns403()
        {
            // Arrange
            string uri = "data:text/html,<script>alert(1)</script>";

            // Act
            var (allowed, errorReason, domain) = ProxySecurity.ValidateRequestWithLogging(
                uri, _config, _testClientIp, _testAction);

            // Assert
            Assert.False(allowed);
            Assert.Equal("blocked_scheme_data", errorReason);
        }

        #endregion

        #region Direct IP Blocking Tests

        /// <summary>
        /// Test that proxy request to direct IP address is blocked when allowDirectIp is false.
        /// Expected: Not allowed with "direct_ip_blocked" reason.
        /// </summary>
        [Fact]
        public void ProxyRequest_DirectPublicIP_Returns403()
        {
            // Arrange
            string uri = "https://8.8.8.8/path";

            // Act
            var (allowed, errorReason, domain) = ProxySecurity.ValidateRequestWithLogging(
                uri, _config, _testClientIp, _testAction);

            // Assert
            Assert.False(allowed, "Direct IP should be blocked when allowDirectIp is false");
            Assert.Equal("direct_ip_blocked", errorReason);
        }

        /// <summary>
        /// Test that proxy request to direct IP address is allowed when allowDirectIp is true.
        /// Expected: Allowed with no error reason for public IPs.
        /// </summary>
        [Fact]
        public void ProxyRequest_DirectPublicIP_WithAllowDirectIp_Succeeds()
        {
            // Arrange
            var config = new ProxySecurityConf
            {
                whitelistEnabled = false,
                allowPrivateIps = false,
                allowDirectIp = true,
                enforceHttps = true,
                enableSecurityLog = false
            };
            string uri = "https://8.8.8.8/path";

            // Act
            var (allowed, errorReason, domain) = ProxySecurity.ValidateRequestWithLogging(
                uri, config, _testClientIp, _testAction);

            // Assert
            Assert.True(allowed, "Public IP should be allowed when allowDirectIp is true");
            Assert.Null(errorReason);
        }

        #endregion

        #region Invalid URI Tests

        /// <summary>
        /// Test that empty URI is blocked.
        /// Expected: Not allowed with "empty_uri" reason.
        /// </summary>
        [Fact]
        public void ProxyRequest_EmptyURI_Returns403()
        {
            // Arrange
            string uri = "";

            // Act
            var (allowed, errorReason, domain) = ProxySecurity.ValidateRequestWithLogging(
                uri, _config, _testClientIp, _testAction);

            // Assert
            Assert.False(allowed);
            Assert.Equal("empty_uri", errorReason);
        }

        /// <summary>
        /// Test that invalid URI is blocked.
        /// Expected: Not allowed with "invalid_uri" reason.
        /// </summary>
        [Fact]
        public void ProxyRequest_InvalidURI_Returns403()
        {
            // Arrange
            string uri = "://invalid-uri";

            // Act
            var (allowed, errorReason, domain) = ProxySecurity.ValidateRequestWithLogging(
                uri, _config, _testClientIp, _testAction);

            // Assert
            Assert.False(allowed);
            Assert.Equal("invalid_uri", errorReason);
        }

        /// <summary>
        /// Test that whitespace-only URI is blocked.
        /// Expected: Not allowed with "empty_uri" reason.
        /// </summary>
        [Fact]
        public void ProxyRequest_WhitespaceURI_Returns403()
        {
            // Arrange
            string uri = "   ";

            // Act
            var (allowed, errorReason, domain) = ProxySecurity.ValidateRequestWithLogging(
                uri, _config, _testClientIp, _testAction);

            // Assert
            Assert.False(allowed);
            Assert.Equal("empty_uri", errorReason);
        }

        #endregion

        #region Whitelist Disabled Tests

        /// <summary>
        /// Test that all domains are allowed when whitelist is disabled.
        /// Expected: Allowed with no error reason.
        /// </summary>
        [Fact]
        public void ProxyRequest_WhitelistDisabled_AllowsAnyDomain()
        {
            // Arrange
            var config = new ProxySecurityConf
            {
                whitelistEnabled = false,
                allowPrivateIps = false,
                allowDirectIp = false,
                enforceHttps = true,
                enableSecurityLog = false
            };
            string uri = "https://anydomain.com/path";

            // Act
            var (allowed, errorReason, domain) = ProxySecurity.ValidateRequestWithLogging(
                uri, config, _testClientIp, _testAction);

            // Assert
            Assert.True(allowed, "Any domain should be allowed when whitelist is disabled");
            Assert.Null(errorReason);
            Assert.Equal("anydomain.com", domain);
        }

        #endregion

        #region Action Parameter Tests

        /// <summary>
        /// Test that different action values work correctly.
        /// Expected: Different actions should not affect validation logic.
        /// </summary>
        [Theory]
        [InlineData("proxy_request")]
        [InlineData("proxy_redirect")]
        [InlineData("proxy_request_or_link")]
        [InlineData("proxy_fallback_link")]
        public void ProxyRequest_DifferentActions_SameValidation(string action)
        {
            // Arrange
            string uri = "https://api.themoviedb.org/path";

            // Act
            var (allowed, errorReason, domain) = ProxySecurity.ValidateRequestWithLogging(
                uri, _config, _testClientIp, action);

            // Assert
            Assert.True(allowed);
            Assert.Null(errorReason);
        }

        #endregion

        #region Null Config Tests

        /// <summary>
        /// Test that null config uses default configuration.
        /// Expected: Default configuration should be applied.
        /// </summary>
        [Fact]
        public void ProxyRequest_NullConfig_UsesDefaults()
        {
            // Arrange
            string uri = "https://api.themoviedb.org/path";

            // Act
            var (allowed, errorReason, domain) = ProxySecurity.ValidateRequestWithLogging(
                uri, null, _testClientIp, _testAction);

            // Assert
            Assert.True(allowed, "Default whitelist should allow themoviedb.org");
            Assert.Null(errorReason);
        }

        #endregion

        #region Domain Extraction Tests

        /// <summary>
        /// Test that domain is correctly extracted from various URI formats.
        /// Expected: Domain field should contain the correct host.
        /// </summary>
        [Theory]
        [InlineData("https://api.themoviedb.org/path", "api.themoviedb.org")]
        [InlineData("https://image.tmdb.org/t/p/w500/abc.jpg", "image.tmdb.org")]
        [InlineData("https://sub.example.com:8080/path", "sub.example.com")]
        public void ProxyRequest_DomainExtraction_WorksCorrectly(string uri, string expectedDomain)
        {
            // Arrange
            var config = new ProxySecurityConf
            {
                whitelistEnabled = false,
                allowPrivateIps = false,
                allowDirectIp = false,
                enforceHttps = true,
                enableSecurityLog = false
            };

            // Act
            var (allowed, errorReason, domain) = ProxySecurity.ValidateRequestWithLogging(
                uri, config, _testClientIp, _testAction);

            // Assert
            Assert.True(allowed);
            Assert.Equal(expectedDomain, domain);
        }

        #endregion

        #region Edge Cases

        /// <summary>
        /// Test URI with query parameters.
        /// Expected: Query parameters should not affect validation.
        /// </summary>
        [Fact]
        public void ProxyRequest_WithQueryParameters_Succeeds()
        {
            // Arrange
            string uri = "https://api.themoviedb.org/path?param1=value1&param2=value2";

            // Act
            var (allowed, errorReason, domain) = ProxySecurity.ValidateRequestWithLogging(
                uri, _config, _testClientIp, _testAction);

            // Assert
            Assert.True(allowed);
            Assert.Null(errorReason);
        }

        /// <summary>
        /// Test URI with fragment.
        /// Expected: Fragment should not affect validation.
        /// </summary>
        [Fact]
        public void ProxyRequest_WithFragment_Succeeds()
        {
            // Arrange
            string uri = "https://api.themoviedb.org/path#section";

            // Act
            var (allowed, errorReason, domain) = ProxySecurity.ValidateRequestWithLogging(
                uri, _config, _testClientIp, _testAction);

            // Assert
            Assert.True(allowed);
            Assert.Null(errorReason);
        }

        /// <summary>
        /// Test URI with port number.
        /// Expected: Port should not affect domain validation.
        /// </summary>
        [Fact]
        public void ProxyRequest_WithPortNumber_Succeeds()
        {
            // Arrange
            string uri = "https://api.themoviedb.org:443/path";

            // Act
            var (allowed, errorReason, domain) = ProxySecurity.ValidateRequestWithLogging(
                uri, _config, _testClientIp, _testAction);

            // Assert
            Assert.True(allowed);
            Assert.Null(errorReason);
        }

        /// <summary>
        /// Test URI with username and password.
        /// Expected: Auth info should not affect validation.
        /// </summary>
        [Fact]
        public void ProxyRequest_WithUserInfo_Succeeds()
        {
            // Arrange
            string uri = "https://user:pass@api.themoviedb.org/path";

            // Act
            var (allowed, errorReason, domain) = ProxySecurity.ValidateRequestWithLogging(
                uri, _config, _testClientIp, _testAction);

            // Assert
            Assert.True(allowed);
            Assert.Null(errorReason);
        }

        #endregion
    }
}
