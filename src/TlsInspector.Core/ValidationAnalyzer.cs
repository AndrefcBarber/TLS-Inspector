using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace TlsInspector.Core;

/// <summary>
/// Explains a completed handshake in terms of the individual checks a TLS client performs:
/// chain of trust, validity window, hostname binding, and the strength of what was negotiated.
/// </summary>
public static class ValidationAnalyzer
{
    private const int MaxRecommendedValidityDays = 398;
    private const int ExpiryWarningDays = 30;

    public static IReadOnlyList<ValidationFinding> Analyze(
        InspectionOptions options,
        X509Certificate2? leaf,
        IReadOnlyList<CertificateSummary> chain,
        SslPolicyErrors policyErrors,
        IReadOnlyList<ChainStatusEntry> chainStatus,
        HandshakeInfo? handshake,
        bool trustedByDefault,
        bool customTrustApplied)
    {
        var findings = new List<ValidationFinding>();

        if (policyErrors.HasFlag(SslPolicyErrors.RemoteCertificateNotAvailable) || leaf is null)
        {
            findings.Add(new ValidationFinding(
                FindingSeverity.Error,
                "no-certificate",
                "The server did not present a certificate",
                "A TLS server must send a certificate the client can bind to the hostname. Without one there is nothing to validate."));
            return findings;
        }

        AddHostnameFindings(options, leaf, policyErrors, findings);
        AddValidityFindings(chain, findings);
        AddChainFindings(chainStatus, chain, customTrustApplied, findings);
        AddCryptoFindings(chain, findings);
        AddProtocolFindings(handshake, findings);

        if (trustedByDefault && findings.All(finding => finding.Severity != FindingSeverity.Error))
        {
            findings.Insert(0, new ValidationFinding(
                FindingSeverity.Pass,
                "trusted",
                "Certificate validation passed",
                customTrustApplied
                    ? "The chain validated against the custom trust anchor you supplied, and the certificate covers this hostname."
                    : "The chain terminates in a trusted root, the certificate is inside its validity window, and it covers this hostname."));
        }

        return findings;
    }

    public static string Headline(TrustVerdict verdict, SslPolicyErrors policyErrors, bool customTrustApplied) => verdict switch
    {
        TrustVerdict.Unreachable => "Could not complete a TLS handshake with this endpoint",
        TrustVerdict.Trusted when customTrustApplied => "Valid against your custom trust anchor",
        TrustVerdict.Trusted => "Valid certificate — a default client would accept this connection",
        _ => policyErrors switch
        {
            _ when policyErrors.HasFlag(SslPolicyErrors.RemoteCertificateNotAvailable) => "No certificate was presented",
            _ when policyErrors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch) &&
                   policyErrors.HasFlag(SslPolicyErrors.RemoteCertificateChainErrors) =>
                "Rejected — the chain is not trusted and the name does not match",
            _ when policyErrors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch) =>
                "Rejected — the certificate does not cover this hostname",
            _ => "Rejected — the certificate chain failed validation",
        },
    };

    private static void AddHostnameFindings(
        InspectionOptions options,
        X509Certificate2 leaf,
        SslPolicyErrors policyErrors,
        List<ValidationFinding> findings)
    {
        var host = options.EffectiveServerName;
        var names = CertificateReader.UsableNames(leaf);
        var hasSan = CertificateReader.ReadSubjectAlternativeNames(leaf).Count > 0;

        if (policyErrors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch) || !HostnameMatcher.MatchesAny(names, host))
        {
            var presented = names.Count == 0 ? "none" : string.Join(", ", names);
            findings.Add(new ValidationFinding(
                FindingSeverity.Error,
                "name-mismatch",
                $"The certificate is not valid for {host}",
                $"Names on the certificate: {presented}. A client must refuse the connection when none of them cover the requested host, "
                + "otherwise anyone holding any valid certificate could impersonate this endpoint. Wildcards such as *.example.com "
                + "match exactly one label, so they cover a.example.com but not b.a.example.com or example.com itself."));
        }
        else
        {
            findings.Add(new ValidationFinding(
                FindingSeverity.Pass,
                "name-match",
                $"Hostname {host} is covered by the certificate",
                $"Matched against: {string.Join(", ", names)}."));
        }

        if (!hasSan)
        {
            findings.Add(new ValidationFinding(
                FindingSeverity.Warning,
                "no-san",
                "No subject alternative name extension",
                "The certificate relies on the legacy common name field. Browsers and .NET ignore the common name for hostname "
                + "matching, so this certificate will be rejected by modern clients even if the common name looks correct."));
        }
    }

    private static void AddValidityFindings(IReadOnlyList<CertificateSummary> chain, List<ValidationFinding> findings)
    {
        var leaf = chain.FirstOrDefault();
        if (leaf is null)
        {
            return;
        }

        if (leaf.IsExpired)
        {
            findings.Add(new ValidationFinding(
                FindingSeverity.Error,
                "expired",
                $"Expired {Math.Abs(leaf.DaysUntilExpiry):N1} days ago",
                $"Validity ended {leaf.NotAfter:u}. Expiry is a hard failure: it bounds how long a stolen key stays useful "
                + "and how long stale revocation information can be trusted."));
        }
        else if (leaf.IsNotYetValid)
        {
            findings.Add(new ValidationFinding(
                FindingSeverity.Error,
                "not-yet-valid",
                "The certificate is not valid yet",
                $"Validity starts {leaf.NotBefore:u}. This usually means the issuing system's clock is wrong."));
        }
        else if (leaf.DaysUntilExpiry <= ExpiryWarningDays)
        {
            findings.Add(new ValidationFinding(
                FindingSeverity.Warning,
                "expiring-soon",
                $"Expires in {leaf.DaysUntilExpiry:N1} days",
                $"Renewal is due before {leaf.NotAfter:u}. Automated renewal should trigger well before this point."));
        }

        var lifetimeDays = (leaf.NotAfter - leaf.NotBefore).TotalDays;
        if (lifetimeDays > MaxRecommendedValidityDays)
        {
            findings.Add(new ValidationFinding(
                FindingSeverity.Warning,
                "long-lifetime",
                $"Validity period spans {lifetimeDays:N0} days",
                $"Public CAs may not issue leaf certificates valid for more than {MaxRecommendedValidityDays} days, and browsers "
                + "reject ones that are. This is normal for an internal or self-signed certificate."));
        }

        foreach (var issuer in chain.Skip(1).Where(entry => entry.IsExpired))
        {
            findings.Add(new ValidationFinding(
                FindingSeverity.Error,
                "issuer-expired",
                $"Issuer expired: {issuer.CommonName ?? issuer.Subject}",
                "An expired certificate anywhere in the chain invalidates everything below it."));
        }
    }

    private static void AddChainFindings(
        IReadOnlyList<ChainStatusEntry> chainStatus,
        IReadOnlyList<CertificateSummary> chain,
        bool customTrustApplied,
        List<ValidationFinding> findings)
    {
        foreach (var status in chainStatus)
        {
            var severity = status.Status is nameof(X509ChainStatusFlags.RevocationStatusUnknown)
                or nameof(X509ChainStatusFlags.OfflineRevocation)
                ? FindingSeverity.Warning
                : FindingSeverity.Error;

            findings.Add(new ValidationFinding(severity, $"chain-{status.Status}", $"Chain error: {status.Status}", status.Explanation));
        }

        var leaf = chain.FirstOrDefault();
        if (leaf is { IsSelfSigned: true })
        {
            findings.Add(new ValidationFinding(
                FindingSeverity.Info,
                "self-signed",
                "The certificate is self-signed",
                "Subject and issuer are identical, so the certificate vouches for itself. It can only be trusted by pinning it "
                + "or by adding it to a trust store explicitly."));
        }

        if (chain.Count == 1 && leaf is { IsSelfSigned: false })
        {
            findings.Add(new ValidationFinding(
                FindingSeverity.Warning,
                "single-certificate",
                "Only one certificate was available for the chain",
                "The server appears to send just the leaf. Clients without a cached copy of the intermediate will fail to build a path."));
        }

        if (customTrustApplied)
        {
            findings.Add(new ValidationFinding(
                FindingSeverity.Info,
                "custom-trust",
                "Validated against a custom trust anchor",
                "The system trust store was bypassed and only the roots you supplied were considered. This is how a service pins "
                + "an internal CA without trusting the public web PKI."));
        }
    }

    private static void AddCryptoFindings(IReadOnlyList<CertificateSummary> chain, List<ValidationFinding> findings)
    {
        foreach (var certificate in chain)
        {
            var label = certificate.CommonName ?? certificate.Subject;

            if (certificate.SignatureAlgorithm.Contains("sha1", StringComparison.OrdinalIgnoreCase) ||
                certificate.SignatureAlgorithm.Contains("md5", StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(new ValidationFinding(
                    FindingSeverity.Warning,
                    "weak-signature",
                    $"Weak signature algorithm on {label}",
                    $"{certificate.SignatureAlgorithm} is considered broken for collision resistance. Chains signed with it are "
                    + "rejected outright by current browsers."));
            }

            if (certificate is { PublicKeyAlgorithm: "RSA", PublicKeySizeBits: < 2048 and > 0 })
            {
                findings.Add(new ValidationFinding(
                    FindingSeverity.Warning,
                    "weak-key",
                    $"{certificate.PublicKeySizeBits}-bit RSA key on {label}",
                    "RSA keys below 2048 bits no longer meet the minimum strength required by the CA/Browser Forum baseline requirements."));
            }
        }
    }

    private static void AddProtocolFindings(HandshakeInfo? handshake, List<ValidationFinding> findings)
    {
        if (handshake is null)
        {
            return;
        }

        var isLegacy = handshake.Protocol is "Tls" or "Tls10" or "Tls11" or "Ssl3" or "Ssl2";
        if (isLegacy)
        {
            findings.Add(new ValidationFinding(
                FindingSeverity.Warning,
                "legacy-protocol",
                $"Negotiated {handshake.Protocol}",
                "Everything below TLS 1.2 is deprecated and disabled by default in current .NET and browser releases."));
            return;
        }

        var cipher = $"Bulk cipher {handshake.CipherAlgorithm} at {handshake.CipherStrengthBits} bits.";
        var detail = handshake.KeyExchangeAlgorithm is "None" or ""
            ? $"{cipher} TLS 1.3 folds key agreement into the handshake itself, so there is no separate key exchange algorithm to report."
            : $"Key exchange {handshake.KeyExchangeAlgorithm}. {cipher}";

        findings.Add(new ValidationFinding(
            FindingSeverity.Pass,
            "protocol",
            $"Negotiated {handshake.Protocol} with {handshake.CipherSuite}",
            detail));
    }

    /// <summary>
    /// A handshake that never completes is still a validation outcome, and the OpenSSL or Schannel
    /// error text on its own rarely says which side gave up or why.
    /// </summary>
    public static IReadOnlyList<ValidationFinding> ExplainConnectionFailure(string error)
    {
        var findings = new List<ValidationFinding>
        {
            new(FindingSeverity.Error, "unreachable", "No TLS session could be established", error),
        };

        void Hint(string code, string title, string detail) => findings.Add(new ValidationFinding(FindingSeverity.Info, code, title, detail));

        if (Contains(error, "alert protocol version", "protocol version", "no protocols available"))
        {
            Hint("hint-protocol",
                "Client and server could not agree on a protocol version",
                "Either the two ends genuinely support different TLS versions, or the local crypto policy refused everything the "
                + "server offered. On Linux, OpenSSL's security level rejects undersized keys and SHA-1 signatures before any "
                + "certificate validation happens, which surfaces as a version alert rather than a certificate error.");
        }

        if (Contains(error, "handshake failure", "no shared cipher", "sslv3 alert"))
        {
            Hint("hint-cipher",
                "No cipher suite was acceptable to both ends",
                "The server's certificate key type or its configured cipher list has no overlap with what this client will accept.");
        }

        if (Contains(error, "no such host", "name or service not known", "nodename nor servname"))
        {
            Hint("hint-dns", "The hostname did not resolve", "DNS returned no address, so no TLS handshake was ever attempted.");
        }

        if (Contains(error, "connection refused"))
        {
            Hint("hint-refused", "Nothing is listening on that port", "The TCP connection was refused before TLS could start.");
        }

        if (Contains(error, "timed out", "timeout", "canceled", "cancelled"))
        {
            Hint("hint-timeout",
                "The connection attempt timed out",
                "A firewall dropping packets, or a port that is filtered rather than closed, both look like this.");
        }

        return findings;
    }

    private static bool Contains(string text, params string[] needles) =>
        needles.Any(needle => text.Contains(needle, StringComparison.OrdinalIgnoreCase));
}
