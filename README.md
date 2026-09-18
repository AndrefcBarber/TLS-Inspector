# TLS Inspector

A C# application that shows what TLS certificate validation actually checks, and what happens when
each of those checks fails.

Point it at any TLS endpoint and it reports the negotiated session, the full certificate chain, and
every validation decision in plain language: whether the chain reaches a trusted root, whether the
certificate is inside its validity window, whether it covers the hostname you asked for, and whether
the cryptography still meets current expectations.

## The idea

Every inspection performs **two handshakes** against the target.

1. The first suspends certificate validation, so even a hopelessly broken certificate can be read
   and explained rather than disappearing behind an exception.
2. The second leaves validation completely untouched, so the report contains the real
   `AuthenticationException` a `HttpClient`, `curl`, or a browser would hit — measured, not guessed.

That second handshake is the point. A tool that only ever bypasses validation can tell you what a
certificate says, but not whether anything would accept it.

## What's in the repo

| Project | What it is |
| --- | --- |
| `src/TlsInspector.Core` | The library: probing, chain analysis, findings, and the loopback demo servers |
| `src/TlsInspector.Web` | ASP.NET Core minimal API plus a single-page UI |
| `src/TlsInspector.Cli` | `tlsinspect`, the same report in a terminal |
| `tests/TlsInspector.Tests` | xUnit tests that assert each failure mode against live loopback servers |

Requires the [.NET 9 SDK](https://dotnet.microsoft.com/download). No other dependencies, no npm, and
no certificates checked into the repository.

## Run the web app

```bash
dotnet run --project src/TlsInspector.Web
```

Then open <http://localhost:43127>. The port is set in `src/TlsInspector.Web/appsettings.json`.

The sidebar offers three ways in: type any host and port, click a live endpoint (`example.com`,
`expired.badssl.com`, and friends), or run one of the local scenarios described below.

## Run the CLI

```bash
dotnet run --project src/TlsInspector.Cli -- example.com
dotnet run --project src/TlsInspector.Cli -- expired.badssl.com
dotnet run --project src/TlsInspector.Cli -- internal.service:8443 --trust ./corporate-root.pem
dotnet run --project src/TlsInspector.Cli -- --demo            # every local scenario
dotnet run --project src/TlsInspector.Cli -- --demo wrong-host # just one
```

It exits `0` when the endpoint validates and `1` when it does not, so it works as a check in a
deployment pipeline or a cron job watching for expiry.

| Option | Meaning |
| --- | --- |
| `-p, --port <n>` | Port to connect to (default 443) |
| `--sni <name>` | Send a server name different from the host you connect to |
| `--trust <file>` | Use this PEM as the only trust anchor, instead of the system trust store |
| `--protocol <v>` | `tls12`, `tls13`, or `system` |
| `--revocation` | Check revocation online via CRL/OCSP |
| `--timeout <ms>` | Handshake timeout (default 8000) |
| `--json` | Emit the whole report as JSON |
| `--pem` | Print the PEM of every certificate in the chain |

## Local scenarios

The app starts seven TLS servers on loopback, each presenting a certificate that is broken in one
specific way. Keys are generated in memory at startup, so the whole demonstration works offline.

| Scenario | What it shows |
| --- | --- |
| `self-signed` | A certificate that vouches for itself — `UntrustedRoot` |
| `expired` | Correct in every other respect, but the validity window closed |
| `not-yet-valid` | Dated into the future, the usual symptom of clock skew |
| `wrong-host` | A well-formed certificate for a different hostname |
| `private-ca` | Correctly issued by a CA nobody else trusts |
| `weak-key` | A 1024-bit RSA key, refused by OpenSSL's security level before validation even runs |
| `tls12-only` | Protocol negotiation, which is separate from certificate validation |

Scenarios that have a trust anchor can be re-run with that anchor supplied. `private-ca` flips from
rejected to valid, which is the correct way to handle an internal CA. `expired` and `wrong-host`
stay rejected, because trusting an issuer does not excuse a dead certificate or the wrong name.

## HTTP API

The UI is a thin layer over three endpoints.

```
GET  /api/scenarios          # the loopback scenarios and the ports they listen on
GET  /api/presets            # suggested public endpoints
POST /api/inspect            # run an inspection
```

```bash
curl -s localhost:43127/api/inspect \
  -H 'Content-Type: application/json' \
  -d '{"host":"expired.badssl.com","port":443}'
```

The request body accepts `host`, `port`, `serverName`, `checkRevocation`, `protocol`
(`system` / `tls12` / `tls13`), `trustAnchorPem`, and — for the loopback servers — `scenarioId`
together with `useTrustAnchor`.

## Using the library directly

```csharp
using TlsInspector.Core;

var result = await new TlsProbe().InspectAsync(new InspectionOptions
{
    Host = "example.com",
    Port = 443,
});

Console.WriteLine(result.Headline);
foreach (var finding in result.Findings)
{
    Console.WriteLine($"{finding.Severity,-7} {finding.Title}");
}
```

`InspectionOptions.CustomTrustRootsPem` replaces the system trust store with the anchors you supply,
which is how you validate against a private CA without weakening validation everywhere else.

## A warning about the code you are reading

`TlsProbe` installs a `RemoteCertificateValidationCallback` that returns `true` unconditionally.
That is the single most common way TLS gets broken in production code, and it is deliberate here:
it is the only way to read a certificate the platform would otherwise refuse, and the honest verdict
is measured separately by a second handshake with validation left alone.

In application code, never do this. When a private CA is involved, add it as a trust anchor — the
`--trust` option and `CustomTrustRootsPem` show exactly how — rather than accepting everything.

Because `POST /api/inspect` opens a connection to whatever host you give it, run this app locally
rather than exposing it on a network where that would be an unwanted outbound proxy.
