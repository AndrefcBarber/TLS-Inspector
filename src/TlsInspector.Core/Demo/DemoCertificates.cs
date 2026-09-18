using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace TlsInspector.Core.Demo;

/// <summary>Builds the throwaway certificates the local scenarios serve. Keys never leave the process.</summary>
public static class DemoCertificates
{
    public static X509Certificate2 CreateSelfSigned(
        string commonName,
        IEnumerable<string> dnsNames,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        int keySizeBits = 2048,
        bool includeLoopbackIp = true)
    {
        using var key = RSA.Create(keySizeBits);
        var request = CreateRequest(key, commonName, dnsNames, includeLoopbackIp, isCertificateAuthority: false);
        using var certificate = request.CreateSelfSigned(notBefore, notAfter);
        return MakeUsableAsServerCertificate(certificate);
    }

    public static X509Certificate2 CreateCertificateAuthority(string commonName, int validityDays = 3650)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            new X500DistinguishedName($"CN={commonName}, O=TLS Inspector Demo"),
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(
            certificateAuthority: true, hasPathLengthConstraint: true, pathLengthConstraint: 1, critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.DigitalSignature, critical: true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

        var now = DateTimeOffset.UtcNow;
        using var certificate = request.CreateSelfSigned(now.AddDays(-30), now.AddDays(validityDays));
        return MakeUsableAsServerCertificate(certificate);
    }

    public static X509Certificate2 IssueFrom(
        X509Certificate2 issuer,
        string commonName,
        IEnumerable<string> dnsNames,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter)
    {
        using var key = RSA.Create(2048);
        var request = CreateRequest(key, commonName, dnsNames, includeLoopbackIp: true, isCertificateAuthority: false);

        var serial = RandomNumberGenerator.GetBytes(16);
        serial[0] &= 0x7F;

        // A child certificate may never outlive the window of the CA that signed it.
        var issuerNotBefore = new DateTimeOffset(issuer.NotBefore.ToUniversalTime(), TimeSpan.Zero);
        var issuerNotAfter = new DateTimeOffset(issuer.NotAfter.ToUniversalTime(), TimeSpan.Zero);
        var effectiveNotBefore = notBefore < issuerNotBefore ? issuerNotBefore : notBefore;
        var effectiveNotAfter = notAfter > issuerNotAfter ? issuerNotAfter : notAfter;

        using var issued = request.Create(issuer, effectiveNotBefore, effectiveNotAfter, serial);
        using var withKey = issued.CopyWithPrivateKey(key);
        return MakeUsableAsServerCertificate(withKey);
    }

    private static CertificateRequest CreateRequest(
        RSA key,
        string commonName,
        IEnumerable<string> dnsNames,
        bool includeLoopbackIp,
        bool isCertificateAuthority)
    {
        var request = new CertificateRequest(
            new X500DistinguishedName($"CN={commonName}, O=TLS Inspector Demo"),
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(
            isCertificateAuthority, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, critical: true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            [new Oid("1.3.6.1.5.5.7.3.1", "Server Authentication")], critical: false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

        var sanBuilder = new SubjectAlternativeNameBuilder();
        var any = false;
        foreach (var name in dnsNames)
        {
            sanBuilder.AddDnsName(name);
            any = true;
        }

        if (includeLoopbackIp)
        {
            sanBuilder.AddIpAddress(IPAddress.Loopback);
            any = true;
        }

        if (any)
        {
            request.CertificateExtensions.Add(sanBuilder.Build());
        }

        return request;
    }

    /// <summary>
    /// Round-trips through PKCS#12 so the private key is attached in the form SslStream expects
    /// on every platform, rather than only where the ephemeral key happens to work.
    /// </summary>
    private static X509Certificate2 MakeUsableAsServerCertificate(X509Certificate2 certificate)
    {
        var password = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
        var pkcs12 = certificate.Export(X509ContentType.Pfx, password);
        return X509CertificateLoader.LoadPkcs12(pkcs12, password, X509KeyStorageFlags.Exportable);
    }
}
