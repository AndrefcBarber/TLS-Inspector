using System.Security.Authentication;
using System.Text.Json.Serialization;
using TlsInspector.Core;
using TlsInspector.Core.Demo;
using TlsInspector.Web;

var builder = WebApplication.CreateBuilder(args);

builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase;
    options.SerializerOptions.Converters.Add(new JsonStringEnumConverter());
});

builder.Services.AddSingleton<TlsProbe>();
builder.Services.AddSingleton<DemoScenarioHost>(_ =>
{
    var host = new DemoScenarioHost();
    host.Start();
    return host;
});

var app = builder.Build();

app.UseDefaultFiles();
app.UseStaticFiles();

// Warm the loopback scenarios at startup so the first request does not pay for key generation.
app.Services.GetRequiredService<DemoScenarioHost>();

app.MapGet("/api/scenarios", (DemoScenarioHost scenarios) =>
    scenarios.Scenarios.Select(scenario => new
    {
        scenario.Id,
        scenario.Title,
        scenario.Summary,
        scenario.ExpectedOutcome,
        scenario.TeachingPoint,
        scenario.RequestHost,
        scenario.Port,
        HasTrustAnchor = scenario.TrustAnchorPem is not null,
        scenario.TrustAnchorLabel,
    }));

app.MapGet("/api/presets", () => PublicEndpoints.All);

app.MapPost("/api/inspect", async (
    InspectRequest request,
    TlsProbe probe,
    DemoScenarioHost scenarios,
    CancellationToken cancellationToken) =>
{
    var scenario = request.ScenarioId is null ? null : scenarios.Find(request.ScenarioId);
    if (request.ScenarioId is not null && scenario is null)
    {
        return Results.BadRequest(new { error = $"Unknown scenario '{request.ScenarioId}'." });
    }

    var host = scenario?.RequestHost ?? request.Host?.Trim();
    var port = scenario?.Port ?? request.Port ?? 443;

    if (string.IsNullOrWhiteSpace(host))
    {
        return Results.BadRequest(new { error = "A hostname is required." });
    }

    if (port is < 1 or > 65535)
    {
        return Results.BadRequest(new { error = "Port must be between 1 and 65535." });
    }

    var trustAnchor = request.UseTrustAnchor && scenario is not null
        ? scenario.TrustAnchorPem
        : NullIfBlank(request.TrustAnchorPem);

    var protocols = request.Protocol?.ToLowerInvariant() switch
    {
        "tls12" => SslProtocols.Tls12,
        "tls13" => SslProtocols.Tls13,
        _ => (SslProtocols?)null,
    };

    var result = await probe.InspectAsync(
        new InspectionOptions
        {
            Host = host,
            Port = port,
            ServerName = NullIfBlank(request.ServerName),
            CheckRevocation = request.CheckRevocation,
            EnabledProtocols = protocols,
            CustomTrustRootsPem = trustAnchor,
            TimeoutMilliseconds = 10000,
        },
        cancellationToken);

    return Results.Ok(result);
});

app.Run();

static string? NullIfBlank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;

namespace TlsInspector.Web
{
    /// <summary>Inspection request coming from the browser. Everything except the host is optional.</summary>
    public sealed record InspectRequest(
        string? Host,
        int? Port,
        string? ServerName,
        bool CheckRevocation,
        string? Protocol,
        string? TrustAnchorPem,
        string? ScenarioId,
        bool UseTrustAnchor);

    /// <summary>Well-known public endpoints that make good live examples.</summary>
    public static class PublicEndpoints
    {
        public static readonly object[] All =
        [
            new { Host = "example.com", Label = "example.com", Note = "A healthy certificate from a public CA" },
            new { Host = "expired.badssl.com", Label = "expired.badssl.com", Note = "Certificate whose validity window closed years ago" },
            new { Host = "wrong.host.badssl.com", Label = "wrong.host.badssl.com", Note = "Valid certificate for a different hostname" },
            new { Host = "self-signed.badssl.com", Label = "self-signed.badssl.com", Note = "Signed by itself, trusted by nobody" },
            new { Host = "untrusted-root.badssl.com", Label = "untrusted-root.badssl.com", Note = "Chains to a root outside the trust store" },
            new { Host = "revoked.badssl.com", Label = "revoked.badssl.com", Note = "Revoked by its CA — enable revocation checking to see it" },
            new { Host = "tls-v1-2.badssl.com", Port = 1012, Label = "tls-v1-2.badssl.com:1012", Note = "Speaks TLS 1.2 only" },
        ];
    }
}
