using System.Security.Authentication;
using System.Text.Json;
using System.Text.Json.Serialization;
using TlsInspector.Core;
using TlsInspector.Core.Demo;

var parsed = CommandLine.Parse(args);
if (parsed is null)
{
    CommandLine.PrintUsage();
    return 64;
}

if (parsed.ShowHelp)
{
    CommandLine.PrintUsage();
    return 0;
}

var probe = new TlsProbe();

if (parsed.Demo)
{
    return await RunDemoAsync(parsed, probe);
}

var options = new InspectionOptions
{
    Host = parsed.Host!,
    Port = parsed.Port,
    ServerName = parsed.ServerName,
    CheckRevocation = parsed.CheckRevocation,
    EnabledProtocols = parsed.Protocols,
    CustomTrustRootsPem = parsed.TrustAnchorPem,
    TimeoutMilliseconds = parsed.TimeoutMilliseconds,
};

var result = await probe.InspectAsync(options);
Render(result, parsed);
return result.Verdict == TrustVerdict.Trusted ? 0 : 1;

async Task<int> RunDemoAsync(CommandLineOptions parsedOptions, TlsProbe tlsProbe)
{
    await using var host = new DemoScenarioHost();
    host.Start();

    var scenarios = parsedOptions.DemoScenarioId is null
        ? host.Scenarios
        : [host.Find(parsedOptions.DemoScenarioId) ?? throw new ArgumentException($"Unknown scenario '{parsedOptions.DemoScenarioId}'.")];

    foreach (var scenario in scenarios)
    {
        Console.WriteLine();
        Output.Rule($"{scenario.Title}  ({scenario.Id})");
        Output.Dim(scenario.Summary);
        Output.Dim($"Serving on {scenario.RequestHost}:{scenario.Port} — expected: {scenario.ExpectedOutcome}");

        var scenarioResult = await tlsProbe.InspectAsync(new InspectionOptions
        {
            Host = scenario.RequestHost,
            Port = scenario.Port,
        });
        Render(scenarioResult, parsedOptions);

        if (scenario.TrustAnchorPem is not null && !parsedOptions.Json)
        {
            Console.WriteLine();
            Output.Dim($"Re-checking with {scenario.TrustAnchorLabel} added as a trust anchor...");
            var trusted = await tlsProbe.InspectAsync(new InspectionOptions
            {
                Host = scenario.RequestHost,
                Port = scenario.Port,
                CustomTrustRootsPem = scenario.TrustAnchorPem,
            });
            Output.Verdict(trusted);
        }

        Console.WriteLine();
        Output.Dim($"Why it matters: {scenario.TeachingPoint}");
    }

    return 0;
}

void Render(TlsInspectionResult inspection, CommandLineOptions parsedOptions)
{
    if (parsedOptions.Json)
    {
        Console.WriteLine(JsonSerializer.Serialize(inspection, JsonOptions.Default));
        return;
    }

    Output.Report(inspection, parsedOptions.ShowPem);
}

internal static class JsonOptions
{
    public static readonly JsonSerializerOptions Default = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() },
    };
}

internal sealed record CommandLineOptions
{
    public string? Host { get; init; }
    public int Port { get; init; } = 443;
    public string? ServerName { get; init; }
    public bool CheckRevocation { get; init; }
    public SslProtocols? Protocols { get; init; }
    public string? TrustAnchorPem { get; init; }
    public int TimeoutMilliseconds { get; init; } = 8000;
    public bool Json { get; init; }
    public bool ShowPem { get; init; }
    public bool Demo { get; init; }
    public string? DemoScenarioId { get; init; }
    public bool ShowHelp { get; init; }
}

internal static class CommandLine
{
    public static CommandLineOptions? Parse(string[] args)
    {
        if (args.Length == 0)
        {
            return null;
        }

        string? host = null;
        var port = 443;
        string? serverName = null;
        var revocation = false;
        SslProtocols? protocols = null;
        string? trustPem = null;
        var timeout = 8000;
        var json = false;
        var pem = false;
        var demo = false;
        string? demoScenario = null;

        for (var index = 0; index < args.Length; index++)
        {
            var argument = args[index];
            switch (argument)
            {
                case "-h" or "--help":
                    return new CommandLineOptions { ShowHelp = true };
                case "--demo":
                    demo = true;
                    if (index + 1 < args.Length && !args[index + 1].StartsWith('-'))
                    {
                        demoScenario = args[++index];
                    }

                    break;
                case "--port" or "-p":
                    if (index + 1 >= args.Length || !int.TryParse(args[++index], out port))
                    {
                        return null;
                    }

                    break;
                case "--sni":
                    if (index + 1 >= args.Length)
                    {
                        return null;
                    }

                    serverName = args[++index];
                    break;
                case "--trust":
                    if (index + 1 >= args.Length)
                    {
                        return null;
                    }

                    trustPem = File.ReadAllText(args[++index]);
                    break;
                case "--protocol":
                    if (index + 1 >= args.Length)
                    {
                        return null;
                    }

                    protocols = args[++index].ToLowerInvariant() switch
                    {
                        "tls12" or "1.2" => SslProtocols.Tls12,
                        "tls13" or "1.3" => SslProtocols.Tls13,
                        "default" or "system" => null,
                        _ => throw new ArgumentException("Supported protocols: tls12, tls13, system."),
                    };
                    break;
                case "--timeout":
                    if (index + 1 >= args.Length || !int.TryParse(args[++index], out timeout))
                    {
                        return null;
                    }

                    break;
                case "--revocation":
                    revocation = true;
                    break;
                case "--json":
                    json = true;
                    break;
                case "--pem":
                    pem = true;
                    break;
                default:
                    if (argument.StartsWith('-'))
                    {
                        return null;
                    }

                    var target = argument;
                    if (target.Contains("://", StringComparison.Ordinal) && Uri.TryCreate(target, UriKind.Absolute, out var uri))
                    {
                        host = uri.Host;
                        port = uri.IsDefaultPort ? 443 : uri.Port;
                    }
                    else if (target.Contains(':') && int.TryParse(target[(target.LastIndexOf(':') + 1)..], out var inlinePort))
                    {
                        host = target[..target.LastIndexOf(':')];
                        port = inlinePort;
                    }
                    else
                    {
                        host = target;
                    }

                    break;
            }
        }

        if (!demo && string.IsNullOrWhiteSpace(host))
        {
            return null;
        }

        return new CommandLineOptions
        {
            Host = host,
            Port = port,
            ServerName = serverName,
            CheckRevocation = revocation,
            Protocols = protocols,
            TrustAnchorPem = trustPem,
            TimeoutMilliseconds = timeout,
            Json = json,
            ShowPem = pem,
            Demo = demo,
            DemoScenarioId = demoScenario,
        };
    }

    public static void PrintUsage()
    {
        Console.WriteLine("""
            tlsinspect — show what TLS certificate validation actually checks

            Usage:
              tlsinspect <host[:port]> [options]
              tlsinspect --demo [scenario-id]

            Options:
              -p, --port <n>       Port to connect to (default 443)
                  --sni <name>     Server name to send, when it differs from the host
                  --trust <file>   PEM file to use as the only trust anchor (certificate pinning)
                  --protocol <v>   tls12 | tls13 | system (default system)
                  --revocation     Check revocation online (CRL/OCSP)
                  --timeout <ms>   Handshake timeout in milliseconds (default 8000)
                  --json           Emit the full result as JSON
                  --pem            Print the PEM of every certificate in the chain
              -h, --help           Show this help

            Examples:
              tlsinspect example.com
              tlsinspect expired.badssl.com
              tlsinspect internal.service:8443 --trust ./corporate-root.pem
              tlsinspect --demo wrong-host
            """);
    }
}

internal static class Output
{
    public static void Report(TlsInspectionResult result, bool showPem)
    {
        Console.WriteLine();
        Verdict(result);
        Console.WriteLine();

        Console.WriteLine($"Target         {result.Host}:{result.Port}  (SNI {result.ServerName})");
        if (result.Handshake is { } handshake)
        {
            Console.WriteLine($"Endpoint       {handshake.RemoteEndpoint}");
            Console.WriteLine($"Protocol       {handshake.Protocol}");
            Console.WriteLine($"Cipher suite   {handshake.CipherSuite}");
            var exchange = handshake.KeyExchangeAlgorithm is "None" or "" ? "folded into the handshake" : handshake.KeyExchangeAlgorithm;
            Console.WriteLine($"Key exchange   {exchange}, {handshake.CipherAlgorithm} at {handshake.CipherStrengthBits} bits");
            Console.WriteLine($"Handshake      {handshake.HandshakeMilliseconds} ms");
        }

        if (result.PolicyErrors.Count > 0)
        {
            Console.WriteLine($"Policy errors  {string.Join(", ", result.PolicyErrors)}");
        }

        if (result.StrictOutcome is { } strict)
        {
            Console.WriteLine();
            Rule("A default client (HttpClient, curl, a browser)");
            if (strict.Succeeded)
            {
                Success($"  {strict.Message}");
            }
            else
            {
                Failure($"  {strict.ExceptionType}: {strict.Message}");
            }
        }

        if (result.Findings.Count > 0)
        {
            Console.WriteLine();
            Rule("Validation checks");
            foreach (var finding in result.Findings)
            {
                var (marker, color) = finding.Severity switch
                {
                    FindingSeverity.Error => ("FAIL", ConsoleColor.Red),
                    FindingSeverity.Warning => ("WARN", ConsoleColor.Yellow),
                    FindingSeverity.Info => ("INFO", ConsoleColor.Cyan),
                    _ => ("PASS", ConsoleColor.Green),
                };

                Write($"  {marker}  ", color);
                Console.WriteLine(finding.Title);
                Dim($"        {finding.Detail}");
            }
        }

        if (result.Chain.Count > 0)
        {
            Console.WriteLine();
            Rule("Certificate chain");
            foreach (var certificate in result.Chain)
            {
                Console.WriteLine($"  [{certificate.Index}] {certificate.Subject}");
                Dim($"       issuer   {certificate.Issuer}");
                Dim($"       valid    {certificate.NotBefore:u} -> {certificate.NotAfter:u} ({certificate.DaysUntilExpiry:N1} days left)");
                Dim($"       key      {certificate.PublicKeyAlgorithm} {certificate.PublicKeySizeBits} bits, signed with {certificate.SignatureAlgorithm}");
                if (certificate.SubjectAlternativeNames.Count > 0)
                {
                    Dim($"       names    {string.Join(", ", certificate.SubjectAlternativeNames)}");
                }

                Dim($"       sha256   {certificate.Sha256Fingerprint}");
                foreach (var status in certificate.ChainStatus)
                {
                    Write($"       status   {status.Status}", ConsoleColor.Yellow);
                    Console.WriteLine();
                }

                if (showPem)
                {
                    Console.WriteLine(certificate.Pem);
                }
            }
        }
    }

    public static void Verdict(TlsInspectionResult result)
    {
        switch (result.Verdict)
        {
            case TrustVerdict.Trusted:
                Success($"PASS  {result.Headline}");
                break;
            case TrustVerdict.Unreachable:
                Failure($"ERROR {result.Headline}: {result.ConnectionError}");
                break;
            default:
                Failure($"FAIL  {result.Headline}");
                break;
        }
    }

    public static void Rule(string title)
    {
        Write(title, ConsoleColor.Cyan);
        Console.WriteLine();
        Dim(new string('-', Math.Min(title.Length, 72)));
    }

    public static void Dim(string text) => WriteLine(text, ConsoleColor.DarkGray);

    private static void Success(string text) => WriteLine(text, ConsoleColor.Green);

    private static void Failure(string text) => WriteLine(text, ConsoleColor.Red);

    private static void Write(string text, ConsoleColor color)
    {
        var previous = Console.ForegroundColor;
        Console.ForegroundColor = color;
        Console.Write(text);
        Console.ForegroundColor = previous;
    }

    private static void WriteLine(string text, ConsoleColor color)
    {
        Write(text, color);
        Console.WriteLine();
    }
}
