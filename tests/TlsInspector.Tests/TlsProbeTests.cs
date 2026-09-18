using System.Net;
using System.Net.Sockets;
using TlsInspector.Core;

namespace TlsInspector.Tests;

public class TlsProbeTests(DemoScenarioFixture fixture) : IClassFixture<DemoScenarioFixture>
{
    private readonly TlsProbe _probe = new();

    private Task<TlsInspectionResult> InspectScenarioAsync(string id, bool trustAnchor = false)
    {
        var scenario = fixture.Scenario(id);
        return _probe.InspectAsync(new InspectionOptions
        {
            Host = scenario.RequestHost,
            Port = scenario.Port,
            CustomTrustRootsPem = trustAnchor ? scenario.TrustAnchorPem : null,
        });
    }

    [Fact]
    public async Task Self_signed_certificate_is_rejected_as_an_untrusted_root()
    {
        var result = await InspectScenarioAsync("self-signed");

        Assert.True(result.Reachable);
        Assert.Equal(TrustVerdict.Untrusted, result.Verdict);
        Assert.Contains("RemoteCertificateChainErrors", result.PolicyErrors);
        Assert.Contains(result.Findings, finding => finding.Code == "chain-UntrustedRoot");
        Assert.Contains(result.Findings, finding => finding.Code == "self-signed");
        Assert.False(result.StrictOutcome!.Succeeded);
    }

    [Fact]
    public async Task Expired_certificate_reports_the_validity_window_as_the_cause()
    {
        var result = await InspectScenarioAsync("expired");

        Assert.Equal(TrustVerdict.Untrusted, result.Verdict);
        Assert.Contains(result.Findings, finding => finding.Code == "expired" && finding.Severity == FindingSeverity.Error);
        Assert.Contains(result.Findings, finding => finding.Code == "chain-NotTimeValid");
        Assert.True(result.Chain[0].IsExpired);
        Assert.True(result.Chain[0].DaysUntilExpiry < 0);
    }

    [Fact]
    public async Task Certificate_dated_into_the_future_is_rejected()
    {
        var result = await InspectScenarioAsync("not-yet-valid");

        Assert.Equal(TrustVerdict.Untrusted, result.Verdict);
        Assert.Contains(result.Findings, finding => finding.Code == "not-yet-valid");
        Assert.True(result.Chain[0].IsNotYetValid);
    }

    [Fact]
    public async Task Certificate_for_another_hostname_fails_the_name_check()
    {
        var result = await InspectScenarioAsync("wrong-host");

        Assert.Equal(TrustVerdict.Untrusted, result.Verdict);
        Assert.Contains("RemoteCertificateNameMismatch", result.PolicyErrors);
        Assert.Contains(result.Findings, finding => finding.Code == "name-mismatch");
        Assert.DoesNotContain("localhost", result.Chain[0].SubjectAlternativeNames);
    }

    [Fact]
    public async Task Trusting_the_anchor_does_not_rescue_a_hostname_mismatch()
    {
        var result = await InspectScenarioAsync("wrong-host", trustAnchor: true);

        Assert.True(result.CustomTrustApplied);
        Assert.Equal(TrustVerdict.Untrusted, result.Verdict);
        Assert.Contains(result.Findings, finding => finding.Code == "name-mismatch");
    }

    [Fact]
    public async Task Trusting_the_anchor_does_not_rescue_an_expired_certificate()
    {
        var result = await InspectScenarioAsync("expired", trustAnchor: true);

        Assert.True(result.CustomTrustApplied);
        Assert.Equal(TrustVerdict.Untrusted, result.Verdict);
    }

    [Fact]
    public async Task Private_ca_endpoint_is_rejected_by_default()
    {
        var result = await InspectScenarioAsync("private-ca");

        Assert.Equal(TrustVerdict.Untrusted, result.Verdict);
        Assert.False(result.CustomTrustApplied);
        Assert.Contains(result.Findings, finding => finding.Severity == FindingSeverity.Error);
        Assert.NotEqual(result.Chain[0].Subject, result.Chain[0].Issuer);
    }

    [Fact]
    public async Task Private_ca_endpoint_validates_once_its_root_is_supplied_as_a_trust_anchor()
    {
        var result = await InspectScenarioAsync("private-ca", trustAnchor: true);

        Assert.True(result.CustomTrustApplied);
        Assert.Equal(TrustVerdict.Trusted, result.Verdict);
        Assert.True(result.TrustedByDefault);
        Assert.True(result.StrictOutcome!.Succeeded);
        Assert.Contains(result.Findings, finding => finding.Code == "trusted");
        Assert.DoesNotContain(result.Findings, finding => finding.Severity == FindingSeverity.Error);
    }

    [Fact]
    public async Task Protocol_restricted_endpoint_negotiates_the_version_it_allows()
    {
        var result = await InspectScenarioAsync("tls12-only");

        Assert.Equal("Tls12", result.Handshake!.Protocol);
        Assert.NotEqual(0, result.Handshake.CipherStrengthBits);
        Assert.True(result.Handshake.IsEncrypted);
    }

    [Fact]
    public async Task Requesting_an_incompatible_protocol_fails_before_any_certificate_is_seen()
    {
        var scenario = fixture.Scenario("tls12-only");

        var result = await _probe.InspectAsync(new InspectionOptions
        {
            Host = scenario.RequestHost,
            Port = scenario.Port,
            EnabledProtocols = System.Security.Authentication.SslProtocols.Tls13,
        });

        Assert.Equal(TrustVerdict.Unreachable, result.Verdict);
        Assert.False(result.Reachable);
        Assert.Empty(result.Chain);
        Assert.Contains(result.Findings, finding => finding.Code == "unreachable");
    }

    [Fact]
    public async Task A_closed_port_is_reported_as_unreachable_with_an_explanation()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();

        var result = await _probe.InspectAsync(new InspectionOptions { Host = "127.0.0.1", Port = port, TimeoutMilliseconds = 2000 });

        Assert.Equal(TrustVerdict.Unreachable, result.Verdict);
        Assert.NotNull(result.ConnectionError);
        Assert.Contains(result.Findings, finding => finding.Code.StartsWith("hint-", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Every_scenario_reports_a_verdict_and_never_throws()
    {
        foreach (var scenario in fixture.Host.Scenarios)
        {
            var result = await _probe.InspectAsync(new InspectionOptions { Host = scenario.RequestHost, Port = scenario.Port });

            Assert.NotEmpty(result.Findings);
            Assert.NotEqual(TrustVerdict.Trusted, result.Verdict);
            Assert.False(string.IsNullOrWhiteSpace(result.Headline));
        }
    }
}
