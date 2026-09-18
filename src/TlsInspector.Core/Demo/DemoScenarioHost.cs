using System.Security.Authentication;

namespace TlsInspector.Core.Demo;

public sealed record DemoScenario
{
    public required string Id { get; init; }
    public required string Title { get; init; }
    public required string Summary { get; init; }
    public required string ExpectedOutcome { get; init; }
    public required string TeachingPoint { get; init; }
    public required string RequestHost { get; init; }
    public required int Port { get; init; }

    /// <summary>PEM of the anchor that would make this endpoint validate, when such an anchor exists.</summary>
    public string? TrustAnchorPem { get; init; }

    public string? TrustAnchorLabel { get; init; }
}

/// <summary>
/// Runs every broken-certificate scenario on loopback so the whole demonstration works with no
/// internet access and no certificates checked into the repository.
/// </summary>
public sealed class DemoScenarioHost : IAsyncDisposable
{
    private readonly List<DemoTlsServer> _servers = [];
    private readonly List<DemoScenario> _scenarios = [];
    private bool _started;

    public IReadOnlyList<DemoScenario> Scenarios => _scenarios;

    public void Start()
    {
        if (_started)
        {
            return;
        }

        _started = true;
        var now = DateTimeOffset.UtcNow;

        AddScenario(
            id: "self-signed",
            title: "Self-signed certificate",
            summary: "A certificate for localhost that signed itself instead of being issued by a CA.",
            expected: "Rejected: UntrustedRoot",
            teachingPoint: "Nothing outside the server vouches for this key, so a client has no reason to believe the identity. "
                + "Trusting the certificate explicitly is the only way to accept it.",
            certificate: DemoCertificates.CreateSelfSigned("localhost", ["localhost"], now.AddDays(-1), now.AddDays(90)),
            anchorFromOwnCertificate: true,
            anchorLabel: "the server's own certificate");

        AddScenario(
            id: "expired",
            title: "Expired certificate",
            summary: "Valid name, valid key, but the validity window closed 30 days ago.",
            expected: "Rejected: NotTimeValid",
            teachingPoint: "Expiry bounds the blast radius of a stolen key and keeps revocation data meaningful, so clients "
                + "treat it as a hard failure even though the cryptography is otherwise intact.",
            certificate: DemoCertificates.CreateSelfSigned("localhost", ["localhost"], now.AddDays(-400), now.AddDays(-30)),
            anchorFromOwnCertificate: true,
            anchorLabel: "the server's own certificate");

        AddScenario(
            id: "not-yet-valid",
            title: "Not valid yet",
            summary: "The certificate's validity period starts ten days from now.",
            expected: "Rejected: NotTimeValid",
            teachingPoint: "Usually a clock skew problem on the issuing host. The same check that catches expiry also catches "
                + "certificates issued into the future.",
            certificate: DemoCertificates.CreateSelfSigned("localhost", ["localhost"], now.AddDays(10), now.AddDays(100)),
            anchorFromOwnCertificate: true,
            anchorLabel: "the server's own certificate");

        AddScenario(
            id: "wrong-host",
            title: "Hostname mismatch",
            summary: "A perfectly well-formed certificate issued for shop.contoso.example, served on localhost.",
            expected: "Rejected: RemoteCertificateNameMismatch",
            teachingPoint: "Trust alone is not enough. Without binding the certificate to the requested name, anyone holding "
                + "any trusted certificate could impersonate any site.",
            certificate: DemoCertificates.CreateSelfSigned(
                "shop.contoso.example", ["shop.contoso.example"], now.AddDays(-1), now.AddDays(90), includeLoopbackIp: false),
            anchorFromOwnCertificate: true,
            anchorLabel: "the server's own certificate (trust fixes the chain, not the name)");

        AddPrivateCaScenario(now);

        AddScenario(
            id: "weak-key",
            title: "1024-bit RSA key",
            summary: "A self-signed certificate whose key is below today's minimum strength.",
            expected: "On Linux the handshake is refused outright; elsewhere it completes with a weak-key warning",
            teachingPoint: "Validation is not only about trust and names. OpenSSL's security level throws out undersized keys "
                + "while the handshake is still being negotiated, so the connection dies before any certificate check runs "
                + "and the error mentions protocol versions rather than the real cause.",
            certificate: DemoCertificates.CreateSelfSigned("localhost", ["localhost"], now.AddDays(-1), now.AddDays(90), keySizeBits: 1024),
            anchorFromOwnCertificate: true,
            anchorLabel: "the server's own certificate");

        AddScenario(
            id: "tls12-only",
            title: "TLS 1.2 only endpoint",
            summary: "A server that refuses to negotiate TLS 1.3, so the client falls back a version.",
            expected: "Rejected: UntrustedRoot, negotiated over TLS 1.2",
            teachingPoint: "Protocol negotiation is separate from certificate validation. Compare the negotiated protocol and "
                + "cipher suite here with a TLS 1.3 endpoint.",
            certificate: DemoCertificates.CreateSelfSigned("localhost", ["localhost"], now.AddDays(-1), now.AddDays(90)),
            protocols: SslProtocols.Tls12,
            anchorFromOwnCertificate: true,
            anchorLabel: "the server's own certificate");
    }

    private void AddPrivateCaScenario(DateTimeOffset now)
    {
        using var authority = DemoCertificates.CreateCertificateAuthority("TLS Inspector Demo Root CA");
        var anchorPem = authority.ExportCertificatePem();
        var leaf = DemoCertificates.IssueFrom(authority, "localhost", ["localhost"], now.AddDays(-1), now.AddDays(90));

        AddScenario(
            id: "private-ca",
            title: "Issued by a private CA",
            summary: "A correctly issued certificate whose root is a private CA nobody else trusts.",
            expected: "Rejected by default, valid once the demo root is trusted",
            teachingPoint: "This is the internal-service case. The fix is to distribute the CA certificate as a trust anchor, "
                + "not to disable validation in the client.",
            certificate: leaf,
            anchorFromOwnCertificate: false,
            anchorPem: anchorPem,
            anchorLabel: "TLS Inspector Demo Root CA");
    }

    private void AddScenario(
        string id,
        string title,
        string summary,
        string expected,
        string teachingPoint,
        System.Security.Cryptography.X509Certificates.X509Certificate2 certificate,
        bool anchorFromOwnCertificate,
        string? anchorLabel = null,
        string? anchorPem = null,
        SslProtocols protocols = SslProtocols.None)
    {
        var pem = anchorFromOwnCertificate ? certificate.ExportCertificatePem() : anchorPem;
        var server = new DemoTlsServer(certificate, protocols);
        server.Start();
        _servers.Add(server);

        _scenarios.Add(new DemoScenario
        {
            Id = id,
            Title = title,
            Summary = summary,
            ExpectedOutcome = expected,
            TeachingPoint = teachingPoint,
            RequestHost = "localhost",
            Port = server.Port,
            TrustAnchorPem = pem,
            TrustAnchorLabel = anchorLabel,
        });
    }

    public DemoScenario? Find(string id) =>
        _scenarios.FirstOrDefault(scenario => string.Equals(scenario.Id, id, StringComparison.OrdinalIgnoreCase));

    public async ValueTask DisposeAsync()
    {
        foreach (var server in _servers)
        {
            await server.DisposeAsync().ConfigureAwait(false);
        }

        _servers.Clear();
        _scenarios.Clear();
    }
}
