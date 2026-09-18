using TlsInspector.Core;
using TlsInspector.Core.Demo;

namespace TlsInspector.Tests;

public class CertificateReaderTests
{
    [Fact]
    public void Summarize_reads_the_fields_validation_depends_on()
    {
        var now = DateTimeOffset.UtcNow;
        using var certificate = DemoCertificates.CreateSelfSigned("api.internal.example", ["api.internal.example"], now.AddDays(-1), now.AddDays(45));

        var summary = CertificateReader.Summarize(certificate, index: 0);

        Assert.Equal("api.internal.example", summary.CommonName);
        Assert.True(summary.IsSelfSigned);
        Assert.False(summary.IsExpired);
        Assert.False(summary.IsCertificateAuthority);
        Assert.Equal("RSA", summary.PublicKeyAlgorithm);
        Assert.Equal(2048, summary.PublicKeySizeBits);
        Assert.Contains("api.internal.example", summary.SubjectAlternativeNames);
        Assert.Contains(summary.ExtendedKeyUsages, usage => usage.Contains("Server Authentication", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(64, summary.Sha256Fingerprint.Length);
        Assert.StartsWith("-----BEGIN CERTIFICATE-----", summary.Pem);
        Assert.InRange(summary.DaysUntilExpiry, 44, 45);
    }

    [Fact]
    public void Expired_certificates_are_reported_with_a_negative_remaining_lifetime()
    {
        var now = DateTimeOffset.UtcNow;
        using var certificate = DemoCertificates.CreateSelfSigned("old.example", ["old.example"], now.AddDays(-90), now.AddDays(-10));

        var summary = CertificateReader.Summarize(certificate, index: 0);

        Assert.True(summary.IsExpired);
        Assert.InRange(summary.DaysUntilExpiry, -11, -9);
    }

    [Fact]
    public void A_certificate_authority_is_recognised_as_one()
    {
        using var authority = DemoCertificates.CreateCertificateAuthority("Test Root CA");

        var summary = CertificateReader.Summarize(authority, index: 0);

        Assert.True(summary.IsCertificateAuthority);
        Assert.True(summary.IsSelfSigned);
    }

    [Fact]
    public void UsableNames_prefers_subject_alternative_names_over_the_common_name()
    {
        var now = DateTimeOffset.UtcNow;
        using var certificate = DemoCertificates.CreateSelfSigned(
            "legacy.example", ["actual.example"], now.AddDays(-1), now.AddDays(30), includeLoopbackIp: false);

        var names = CertificateReader.UsableNames(certificate);

        Assert.Equal(["actual.example"], names);
        Assert.False(HostnameMatcher.MatchesAny(names, "legacy.example"));
    }
}
