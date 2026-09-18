using System.Security.Authentication;

namespace TlsInspector.Core;

public enum FindingSeverity
{
    /// <summary>A validation check that the endpoint passed.</summary>
    Pass,

    /// <summary>Context worth knowing that is neither a pass nor a problem.</summary>
    Info,
    Warning,
    Error,
}

public enum TrustVerdict
{
    Trusted,
    Untrusted,
    Unreachable,
}

/// <summary>A single conclusion drawn from the handshake, written for a human reader.</summary>
public sealed record ValidationFinding(FindingSeverity Severity, string Code, string Title, string Detail);

public sealed record ChainStatusEntry(string Status, string Explanation);

public sealed record CertificateSummary
{
    public required int Index { get; init; }
    public required string Subject { get; init; }
    public required string Issuer { get; init; }
    public string? CommonName { get; init; }
    public string? IssuerCommonName { get; init; }
    public required string SerialNumber { get; init; }
    public required DateTimeOffset NotBefore { get; init; }
    public required DateTimeOffset NotAfter { get; init; }
    public required double DaysUntilExpiry { get; init; }
    public required bool IsExpired { get; init; }
    public required bool IsNotYetValid { get; init; }
    public required string SignatureAlgorithm { get; init; }
    public required string PublicKeyAlgorithm { get; init; }
    public required int PublicKeySizeBits { get; init; }
    public required string Sha256Fingerprint { get; init; }
    public required IReadOnlyList<string> SubjectAlternativeNames { get; init; }
    public required IReadOnlyList<string> KeyUsages { get; init; }
    public required IReadOnlyList<string> ExtendedKeyUsages { get; init; }
    public required bool IsCertificateAuthority { get; init; }
    public required bool IsSelfSigned { get; init; }
    public required IReadOnlyList<ChainStatusEntry> ChainStatus { get; init; }
    public required string Pem { get; init; }
}

public sealed record HandshakeInfo
{
    public required string Protocol { get; init; }
    public required string CipherSuite { get; init; }
    public required string CipherAlgorithm { get; init; }
    public required int CipherStrengthBits { get; init; }
    public required string HashAlgorithm { get; init; }
    public required string KeyExchangeAlgorithm { get; init; }
    public required bool IsEncrypted { get; init; }
    public required bool IsSigned { get; init; }
    public required bool IsMutuallyAuthenticated { get; init; }
    public string? RemoteEndpoint { get; init; }
    public required double HandshakeMilliseconds { get; init; }
}

/// <summary>
/// What a normal client (HttpClient, a browser, curl) sees when it connects with default
/// validation left switched on. This is the outcome the inspector is really trying to explain.
/// </summary>
public sealed record StrictHandshakeOutcome
{
    public required bool Succeeded { get; init; }
    public string? ExceptionType { get; init; }
    public string? Message { get; init; }
}

public sealed record TlsInspectionResult
{
    public required string Host { get; init; }
    public required int Port { get; init; }
    public required string ServerName { get; init; }
    public required DateTimeOffset CheckedAtUtc { get; init; }
    public required double ElapsedMilliseconds { get; init; }
    public required bool Reachable { get; init; }
    public string? ConnectionError { get; init; }
    public required TrustVerdict Verdict { get; init; }
    public required string Headline { get; init; }
    public required bool TrustedByDefault { get; init; }
    public required IReadOnlyList<string> PolicyErrors { get; init; }
    public HandshakeInfo? Handshake { get; init; }
    public required IReadOnlyList<CertificateSummary> Chain { get; init; }
    public required IReadOnlyList<ValidationFinding> Findings { get; init; }
    public StrictHandshakeOutcome? StrictOutcome { get; init; }
    public required bool RevocationChecked { get; init; }
    public required bool CustomTrustApplied { get; init; }
}

public sealed record InspectionOptions
{
    public required string Host { get; init; }
    public int Port { get; init; } = 443;

    /// <summary>SNI value sent to the server. Defaults to <see cref="Host"/>.</summary>
    public string? ServerName { get; init; }

    public int TimeoutMilliseconds { get; init; } = 8000;

    public bool CheckRevocation { get; init; }

    /// <summary>Protocol floor/ceiling for the handshake. <c>null</c> means "let the OS decide".</summary>
    public SslProtocols? EnabledProtocols { get; init; }

    /// <summary>
    /// PEM-encoded certificates to use as the only trust anchors, instead of the machine store.
    /// Mirrors certificate pinning: a private CA can be trusted without trusting the public web PKI.
    /// </summary>
    public string? CustomTrustRootsPem { get; init; }

    public string EffectiveServerName => string.IsNullOrWhiteSpace(ServerName) ? Host : ServerName.Trim();
}
