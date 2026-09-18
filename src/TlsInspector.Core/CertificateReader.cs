using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace TlsInspector.Core;

/// <summary>Turns raw X.509 material into the flattened shape the UI and CLI render.</summary>
public static class CertificateReader
{
    public static CertificateSummary Summarize(
        X509Certificate2 certificate,
        int index,
        IReadOnlyList<ChainStatusEntry>? chainStatus = null)
    {
        var now = DateTimeOffset.UtcNow;
        var notBefore = new DateTimeOffset(certificate.NotBefore.ToUniversalTime(), TimeSpan.Zero);
        var notAfter = new DateTimeOffset(certificate.NotAfter.ToUniversalTime(), TimeSpan.Zero);

        return new CertificateSummary
        {
            Index = index,
            Subject = certificate.Subject,
            Issuer = certificate.Issuer,
            CommonName = NullIfEmpty(certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false)),
            IssuerCommonName = NullIfEmpty(certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: true)),
            SerialNumber = certificate.SerialNumber,
            NotBefore = notBefore,
            NotAfter = notAfter,
            DaysUntilExpiry = Math.Round((notAfter - now).TotalDays, 2),
            IsExpired = notAfter < now,
            IsNotYetValid = notBefore > now,
            SignatureAlgorithm = DescribeOid(certificate.SignatureAlgorithm),
            PublicKeyAlgorithm = DescribePublicKeyAlgorithm(certificate),
            PublicKeySizeBits = GetKeySize(certificate),
            Sha256Fingerprint = FormatFingerprint(certificate.GetCertHash(HashAlgorithmName.SHA256)),
            SubjectAlternativeNames = ReadSubjectAlternativeNames(certificate),
            KeyUsages = ReadKeyUsages(certificate),
            ExtendedKeyUsages = ReadExtendedKeyUsages(certificate),
            IsCertificateAuthority = IsCertificateAuthority(certificate),
            IsSelfSigned = string.Equals(certificate.Subject, certificate.Issuer, StringComparison.Ordinal),
            ChainStatus = chainStatus ?? [],
            Pem = certificate.ExportCertificatePem(),
        };
    }

    public static IReadOnlyList<string> ReadSubjectAlternativeNames(X509Certificate2 certificate)
    {
        var names = new List<string>();
        foreach (var extension in certificate.Extensions)
        {
            if (extension is not X509SubjectAlternativeNameExtension san)
            {
                continue;
            }

            names.AddRange(san.EnumerateDnsNames());
            names.AddRange(san.EnumerateIPAddresses().Select(ip => ip.ToString()));
        }

        return names.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    /// <summary>
    /// The names a client is allowed to match against. Modern clients ignore the common name
    /// entirely once a SAN extension is present, which is exactly the trap this surfaces.
    /// </summary>
    public static IReadOnlyList<string> UsableNames(X509Certificate2 certificate)
    {
        var san = ReadSubjectAlternativeNames(certificate);
        if (san.Count > 0)
        {
            return san;
        }

        var commonName = certificate.GetNameInfo(X509NameType.DnsName, forIssuer: false);
        return string.IsNullOrWhiteSpace(commonName) ? [] : [commonName];
    }

    public static X509Certificate2 Clone(X509Certificate2 certificate) =>
        X509CertificateLoader.LoadCertificate(certificate.RawData);

    public static IReadOnlyList<ChainStatusEntry> DescribeStatus(X509ChainStatus[] statuses) =>
        statuses
            .Where(status => status.Status != X509ChainStatusFlags.NoError)
            .Select(status => new ChainStatusEntry(status.Status.ToString(), ExplainStatus(status)))
            .ToArray();

    public static string ExplainStatus(X509ChainStatus status) => status.Status switch
    {
        X509ChainStatusFlags.UntrustedRoot =>
            "The chain ends at a root certificate that is not in the trust store, so nothing vouches for this identity.",
        X509ChainStatusFlags.PartialChain =>
            "An issuing certificate is missing. The server should send its intermediate certificates alongside the leaf.",
        X509ChainStatusFlags.NotTimeValid =>
            "The certificate is outside its validity window (expired, or not valid yet).",
        X509ChainStatusFlags.NotTimeNested =>
            "A certificate's validity period is not contained within its issuer's validity period.",
        X509ChainStatusFlags.Revoked =>
            "The issuing CA has revoked this certificate. It must not be accepted.",
        X509ChainStatusFlags.RevocationStatusUnknown =>
            "Revocation status could not be determined; the CRL or OCSP responder was unreachable.",
        X509ChainStatusFlags.OfflineRevocation =>
            "The revocation server was offline, so revocation could not be confirmed.",
        X509ChainStatusFlags.NotSignatureValid =>
            "The signature on the certificate does not verify against the issuer's public key.",
        X509ChainStatusFlags.NotValidForUsage =>
            "The certificate's key usage or extended key usage does not permit TLS server authentication.",
        X509ChainStatusFlags.InvalidBasicConstraints =>
            "Basic constraints are invalid; for example a non-CA certificate was used to sign another certificate.",
        X509ChainStatusFlags.InvalidNameConstraints or
        X509ChainStatusFlags.HasNotSupportedNameConstraint or
        X509ChainStatusFlags.HasNotDefinedNameConstraint or
        X509ChainStatusFlags.HasNotPermittedNameConstraint or
        X509ChainStatusFlags.HasExcludedNameConstraint =>
            "The chain violates a name constraint imposed by one of the CAs above it.",
        X509ChainStatusFlags.ExplicitDistrust =>
            "The certificate or one of its issuers is explicitly distrusted on this machine.",
        X509ChainStatusFlags.CtlNotTimeValid or
        X509ChainStatusFlags.CtlNotSignatureValid or
        X509ChainStatusFlags.CtlNotValidForUsage =>
            "A certificate trust list used to validate this chain is itself invalid.",
        X509ChainStatusFlags.Cyclic =>
            "The chain loops back on itself and never reaches a root.",
        _ => string.IsNullOrWhiteSpace(status.StatusInformation)
            ? "The platform reported a chain error of this type."
            : status.StatusInformation.Trim(),
    };

    private static string DescribeOid(Oid oid) =>
        string.IsNullOrWhiteSpace(oid.FriendlyName) ? oid.Value ?? "unknown" : oid.FriendlyName;

    private static string DescribePublicKeyAlgorithm(X509Certificate2 certificate)
    {
        if (certificate.GetRSAPublicKey() is not null)
        {
            return "RSA";
        }

        if (certificate.GetECDsaPublicKey() is not null)
        {
            return "ECDSA";
        }

        return DescribeOid(certificate.PublicKey.Oid);
    }

    private static int GetKeySize(X509Certificate2 certificate)
    {
        using var rsa = certificate.GetRSAPublicKey();
        if (rsa is not null)
        {
            return rsa.KeySize;
        }

        using var ecdsa = certificate.GetECDsaPublicKey();
        return ecdsa?.KeySize ?? 0;
    }

    private static bool IsCertificateAuthority(X509Certificate2 certificate) =>
        certificate.Extensions
            .OfType<X509BasicConstraintsExtension>()
            .Any(extension => extension.CertificateAuthority);

    private static IReadOnlyList<string> ReadKeyUsages(X509Certificate2 certificate) =>
        certificate.Extensions
            .OfType<X509KeyUsageExtension>()
            .Select(extension => extension.KeyUsages.ToString())
            .ToArray();

    private static IReadOnlyList<string> ReadExtendedKeyUsages(X509Certificate2 certificate) =>
        certificate.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .SelectMany(extension => extension.EnhancedKeyUsages.Cast<Oid>())
            .Select(DescribeOid)
            .Distinct(StringComparer.Ordinal)
            .ToArray();

    private static string FormatFingerprint(byte[] hash) => Convert.ToHexString(hash).ToLowerInvariant();

    private static string? NullIfEmpty(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;
}
