using TlsInspector.Core;

namespace TlsInspector.Tests;

public class HostnameMatcherTests
{
    [Theory]
    [InlineData("example.com", "example.com")]
    [InlineData("EXAMPLE.com", "example.com")]
    [InlineData("example.com.", "example.com")]
    [InlineData("*.example.com", "www.example.com")]
    [InlineData("*.example.com", "WWW.example.com")]
    public void Matches_accepts_names_that_cover_the_host(string certificateName, string host) =>
        Assert.True(HostnameMatcher.Matches(certificateName, host));

    [Theory]
    [InlineData("*.example.com", "example.com")]
    [InlineData("*.example.com", "a.b.example.com")]
    [InlineData("*.example.com", "www.example.org")]
    [InlineData("*.com", "example.org")]
    [InlineData("example.com", "www.example.com")]
    [InlineData("", "example.com")]
    [InlineData("example.com", "")]
    public void Matches_rejects_names_that_do_not_cover_the_host(string certificateName, string host) =>
        Assert.False(HostnameMatcher.Matches(certificateName, host));

    [Fact]
    public void MatchesAny_scans_every_name_on_the_certificate() =>
        Assert.True(HostnameMatcher.MatchesAny(["badssl.com", "*.badssl.com"], "expired.badssl.com"));
}
