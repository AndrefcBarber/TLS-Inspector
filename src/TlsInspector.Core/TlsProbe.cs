using System.Diagnostics;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace TlsInspector.Core;

/// <summary>
/// Connects to a TLS endpoint twice: once with validation suspended so the certificate can be
/// examined no matter how broken it is, and once with validation left alone so the real client
/// behaviour is recorded rather than guessed at.
/// </summary>
public sealed class TlsProbe
{
    public async Task<TlsInspectionResult> InspectAsync(InspectionOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrWhiteSpace(options.Host))
        {
            throw new ArgumentException("A host is required.", nameof(options));
        }

        var stopwatch = Stopwatch.StartNew();
        var customRoots = LoadCustomRoots(options.CustomTrustRootsPem);

        try
        {
            var observation = await ObserveHandshakeAsync(options, cancellationToken).ConfigureAwait(false);
            using var leaf = observation.Leaf;

            var chainSummaries = observation.Chain;
            var chainStatus = observation.ChainStatus;
            var policyErrors = observation.PolicyErrors;
            var customTrustApplied = false;

            if (customRoots.Count > 0 && observation.RawChain.Count > 0)
            {
                var rebuilt = RebuildWithCustomRoots(observation.RawChain, customRoots, options.CheckRevocation);
                customTrustApplied = true;
                chainStatus = rebuilt.Status;
                chainSummaries = rebuilt.Chain;
                policyErrors = rebuilt.Status.Count == 0
                    ? policyErrors & ~SslPolicyErrors.RemoteCertificateChainErrors
                    : policyErrors | SslPolicyErrors.RemoteCertificateChainErrors;
            }

            var trustedByDefault = policyErrors == SslPolicyErrors.None;
            var verdict = trustedByDefault ? TrustVerdict.Trusted : TrustVerdict.Untrusted;
            var findings = ValidationAnalyzer.Analyze(
                options, leaf, chainSummaries, policyErrors, chainStatus, observation.Handshake, trustedByDefault, customTrustApplied);

            var strictOutcome = await RunStrictHandshakeAsync(options, customRoots, observation.RawChain, cancellationToken)
                .ConfigureAwait(false);

            return new TlsInspectionResult
            {
                Host = options.Host,
                Port = options.Port,
                ServerName = options.EffectiveServerName,
                CheckedAtUtc = DateTimeOffset.UtcNow,
                ElapsedMilliseconds = Math.Round(stopwatch.Elapsed.TotalMilliseconds, 1),
                Reachable = true,
                Verdict = verdict,
                Headline = ValidationAnalyzer.Headline(verdict, policyErrors, customTrustApplied),
                TrustedByDefault = trustedByDefault,
                PolicyErrors = DescribePolicyErrors(policyErrors),
                Handshake = observation.Handshake,
                Chain = chainSummaries,
                Findings = findings,
                StrictOutcome = strictOutcome,
                RevocationChecked = options.CheckRevocation,
                CustomTrustApplied = customTrustApplied,
            };
        }
        catch (Exception exception) when (exception is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            return new TlsInspectionResult
            {
                Host = options.Host,
                Port = options.Port,
                ServerName = options.EffectiveServerName,
                CheckedAtUtc = DateTimeOffset.UtcNow,
                ElapsedMilliseconds = Math.Round(stopwatch.Elapsed.TotalMilliseconds, 1),
                Reachable = false,
                ConnectionError = Describe(exception),
                Verdict = TrustVerdict.Unreachable,
                Headline = ValidationAnalyzer.Headline(TrustVerdict.Unreachable, SslPolicyErrors.None, customTrustApplied: false),
                TrustedByDefault = false,
                PolicyErrors = [],
                Chain = [],
                Findings = ValidationAnalyzer.ExplainConnectionFailure(Describe(exception)),
                RevocationChecked = options.CheckRevocation,
                CustomTrustApplied = false,
            };
        }
        finally
        {
            foreach (var root in customRoots)
            {
                root.Dispose();
            }
        }
    }

    private static async Task<Observation> ObserveHandshakeAsync(InspectionOptions options, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(options.TimeoutMilliseconds);

        using var tcp = new TcpClient();
        await tcp.ConnectAsync(options.Host, options.Port, timeout.Token).ConfigureAwait(false);

        X509Certificate2? leaf = null;
        var rawChain = new List<X509Certificate2>();
        var chainStatus = Array.Empty<ChainStatusEntry>() as IReadOnlyList<ChainStatusEntry>;
        var policyErrors = SslPolicyErrors.None;
        var perCertificateStatus = new Dictionary<int, IReadOnlyList<ChainStatusEntry>>();

        // Returning true unconditionally is the anti-pattern this tool exists to explain. Here it is
        // deliberate and contained: it lets the inspector read a certificate the platform would refuse,
        // and the untouched verdict is measured separately by RunStrictHandshakeAsync.
        bool Capture(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors errors)
        {
            policyErrors = errors;

            if (certificate is X509Certificate2 presented)
            {
                leaf = CertificateReader.Clone(presented);
            }

            if (chain is not null)
            {
                chainStatus = CertificateReader.DescribeStatus(chain.ChainStatus);
                for (var index = 0; index < chain.ChainElements.Count; index++)
                {
                    var element = chain.ChainElements[index];
                    rawChain.Add(CertificateReader.Clone(element.Certificate));
                    perCertificateStatus[index] = CertificateReader.DescribeStatus(element.ChainElementStatus);
                }
            }

            return true;
        }

        var stopwatch = Stopwatch.StartNew();
        await using var stream = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false, Capture);
        await stream.AuthenticateAsClientAsync(
            new SslClientAuthenticationOptions
            {
                TargetHost = options.EffectiveServerName,
                EnabledSslProtocols = options.EnabledProtocols ?? SslProtocols.None,
                CertificateRevocationCheckMode = options.CheckRevocation ? X509RevocationMode.Online : X509RevocationMode.NoCheck,
                RemoteCertificateValidationCallback = Capture,
            },
            timeout.Token).ConfigureAwait(false);
        stopwatch.Stop();

        if (rawChain.Count == 0 && leaf is not null)
        {
            rawChain.Add(CertificateReader.Clone(leaf));
        }

        var summaries = rawChain
            .Select((certificate, index) => CertificateReader.Summarize(
                certificate,
                index,
                perCertificateStatus.TryGetValue(index, out var status) ? status : []))
            .ToArray();

        var handshake = new HandshakeInfo
        {
            Protocol = stream.SslProtocol.ToString(),
            CipherSuite = stream.NegotiatedCipherSuite.ToString(),
            CipherAlgorithm = stream.CipherAlgorithm.ToString(),
            CipherStrengthBits = stream.CipherStrength,
            HashAlgorithm = stream.HashAlgorithm.ToString(),
            KeyExchangeAlgorithm = stream.KeyExchangeAlgorithm.ToString(),
            IsEncrypted = stream.IsEncrypted,
            IsSigned = stream.IsSigned,
            IsMutuallyAuthenticated = stream.IsMutuallyAuthenticated,
            RemoteEndpoint = tcp.Client.RemoteEndPoint?.ToString(),
            HandshakeMilliseconds = Math.Round(stopwatch.Elapsed.TotalMilliseconds, 1),
        };

        return new Observation(leaf, summaries, rawChain, chainStatus, policyErrors, handshake);
    }

    /// <summary>Repeats the handshake with platform validation untouched, recording exactly what a normal client would get.</summary>
    private static async Task<StrictHandshakeOutcome> RunStrictHandshakeAsync(
        InspectionOptions options,
        IReadOnlyList<X509Certificate2> customRoots,
        IReadOnlyList<X509Certificate2> presentedChain,
        CancellationToken cancellationToken)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(options.TimeoutMilliseconds);

            using var tcp = new TcpClient();
            await tcp.ConnectAsync(options.Host, options.Port, timeout.Token).ConfigureAwait(false);

            var clientOptions = new SslClientAuthenticationOptions
            {
                TargetHost = options.EffectiveServerName,
                EnabledSslProtocols = options.EnabledProtocols ?? SslProtocols.None,
                CertificateRevocationCheckMode = options.CheckRevocation ? X509RevocationMode.Online : X509RevocationMode.NoCheck,
            };

            if (customRoots.Count > 0)
            {
                var policy = new X509ChainPolicy
                {
                    TrustMode = X509ChainTrustMode.CustomRootTrust,
                    RevocationMode = options.CheckRevocation ? X509RevocationMode.Online : X509RevocationMode.NoCheck,
                };
                policy.CustomTrustStore.AddRange(customRoots.ToArray());
                policy.ExtraStore.AddRange(presentedChain.ToArray());
                clientOptions.CertificateChainPolicy = policy;
            }

            await using var stream = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false);
            await stream.AuthenticateAsClientAsync(clientOptions, timeout.Token).ConfigureAwait(false);

            return new StrictHandshakeOutcome
            {
                Succeeded = true,
                Message = $"Handshake completed with {stream.SslProtocol}. A default client would send its request over this connection.",
            };
        }
        catch (Exception exception)
        {
            return new StrictHandshakeOutcome
            {
                Succeeded = false,
                ExceptionType = exception.GetType().Name,
                Message = Describe(exception),
            };
        }
    }

    private static (IReadOnlyList<CertificateSummary> Chain, IReadOnlyList<ChainStatusEntry> Status) RebuildWithCustomRoots(
        IReadOnlyList<X509Certificate2> presentedChain,
        IReadOnlyList<X509Certificate2> customRoots,
        bool checkRevocation)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.RevocationMode = checkRevocation ? X509RevocationMode.Online : X509RevocationMode.NoCheck;
        chain.ChainPolicy.CustomTrustStore.AddRange(customRoots.ToArray());
        chain.ChainPolicy.ExtraStore.AddRange(presentedChain.ToArray());
        chain.Build(presentedChain[0]);

        var summaries = chain.ChainElements
            .Select((element, index) => CertificateReader.Summarize(
                element.Certificate, index, CertificateReader.DescribeStatus(element.ChainElementStatus)))
            .ToArray();

        return (summaries.Length > 0
            ? summaries
            : presentedChain.Select((certificate, index) => CertificateReader.Summarize(certificate, index)).ToArray(),
            CertificateReader.DescribeStatus(chain.ChainStatus));
    }

    private static List<X509Certificate2> LoadCustomRoots(string? pem)
    {
        if (string.IsNullOrWhiteSpace(pem))
        {
            return [];
        }

        var collection = new X509Certificate2Collection();
        collection.ImportFromPem(pem);
        return [.. collection];
    }

    private static IReadOnlyList<string> DescribePolicyErrors(SslPolicyErrors errors) =>
        errors == SslPolicyErrors.None
            ? []
            : Enum.GetValues<SslPolicyErrors>()
                .Where(value => value != SslPolicyErrors.None && errors.HasFlag(value))
                .Select(value => value.ToString())
                .ToArray();

    private static string Describe(Exception exception)
    {
        var messages = new List<string>();
        for (var current = exception; current is not null; current = current.InnerException)
        {
            if (!string.IsNullOrWhiteSpace(current.Message) && !messages.Contains(current.Message))
            {
                messages.Add(current.Message.Trim());
            }
        }

        return string.Join(" -> ", messages);
    }

    private sealed record Observation(
        X509Certificate2? Leaf,
        IReadOnlyList<CertificateSummary> Chain,
        IReadOnlyList<X509Certificate2> RawChain,
        IReadOnlyList<ChainStatusEntry> ChainStatus,
        SslPolicyErrors PolicyErrors,
        HandshakeInfo? Handshake);
}
