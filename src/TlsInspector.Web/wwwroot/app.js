const form = document.getElementById("inspect-form");
const submitButton = document.getElementById("submit-button");
const emptyState = document.getElementById("empty-state");
const loadingState = document.getElementById("loading-state");
const loadingTarget = document.getElementById("loading-target");
const errorState = document.getElementById("error-state");
const errorMessage = document.getElementById("error-message");
const resultPanel = document.getElementById("result");
const presetsContainer = document.getElementById("presets");
const scenariosContainer = document.getElementById("scenarios");

let scenarios = [];
let inFlight = false;

const escapeHtml = (value) =>
  String(value ?? "").replace(/[&<>"']/g, (character) => `&${{ "&": "amp", "<": "lt", ">": "gt", '"': "quot", "'": "#39" }[character]};`);

const formatDate = (value) => {
  if (!value) return "unknown";
  const date = new Date(value);
  return date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
};

const formatDays = (days) => {
  if (days === null || days === undefined) return "";
  const rounded = Math.abs(days) >= 10 ? Math.round(days) : Math.round(days * 10) / 10;
  return days < 0 ? `expired ${Math.abs(rounded).toLocaleString()} days ago` : `${rounded.toLocaleString()} days left`;
};

async function loadSidebar() {
  try {
    const [presets, scenarioList] = await Promise.all([
      fetch("/api/presets").then((response) => response.json()),
      fetch("/api/scenarios").then((response) => response.json()),
    ]);

    presetsContainer.innerHTML = presets
      .map(
        (preset) =>
          `<button class="chip" type="button" role="listitem" title="${escapeHtml(preset.note)}" data-host="${escapeHtml(
            preset.host,
          )}" data-port="${preset.port ?? 443}">${escapeHtml(preset.label)}</button>`,
      )
      .join("");

    scenarios = scenarioList;
    scenariosContainer.innerHTML = scenarioList
      .map(
        (scenario) => `
        <div class="scenario">
          <h3>${escapeHtml(scenario.title)}</h3>
          <p>${escapeHtml(scenario.summary)}</p>
          <span class="expected">Expected: ${escapeHtml(scenario.expectedOutcome)}</span>
          <div class="scenario-actions">
            <button class="ghost-button" type="button" data-scenario="${escapeHtml(scenario.id)}">Inspect</button>
            ${
              scenario.hasTrustAnchor
                ? `<button class="ghost-button" type="button" data-scenario="${escapeHtml(
                    scenario.id,
                  )}" data-anchor="true">Inspect trusting ${escapeHtml(scenario.trustAnchorLabel ?? "its anchor")}</button>`
                : ""
            }
          </div>
        </div>`,
      )
      .join("");
  } catch (error) {
    presetsContainer.innerHTML = `<p class="hint">Could not load examples: ${escapeHtml(error.message)}</p>`;
  }
}

function setBusy(busy, targetLabel) {
  inFlight = busy;
  submitButton.disabled = busy;
  submitButton.querySelector(".button-label").textContent = busy ? "Inspecting…" : "Run validation";
  loadingTarget.textContent = targetLabel ?? "the endpoint";
  loadingState.hidden = !busy;
  if (busy) {
    emptyState.hidden = true;
    errorState.hidden = true;
    resultPanel.hidden = true;
  }
}

function showError(message) {
  errorMessage.textContent = message;
  errorState.hidden = false;
  resultPanel.hidden = true;
  emptyState.hidden = true;
}

function rememberInUrl(payload) {
  const params = new URLSearchParams();
  if (payload.scenarioId) {
    params.set("scenario", payload.scenarioId);
    if (payload.useTrustAnchor) params.set("trust", "1");
  } else {
    params.set("host", payload.host);
    if (payload.port && payload.port !== 443) params.set("port", payload.port);
    if (payload.protocol && payload.protocol !== "system") params.set("protocol", payload.protocol);
    if (payload.checkRevocation) params.set("revocation", "1");
  }

  history.replaceState(null, "", `?${params}`);
}

async function inspect(payload, label, scenario) {
  if (inFlight) return;
  rememberInUrl(payload);
  setBusy(true, label);

  try {
    const response = await fetch("/api/inspect", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    const body = await response.json();
    if (!response.ok) {
      showError(body.error ?? "The inspector rejected that request.");
      return;
    }

    renderResult(body, scenario);
  } catch (error) {
    showError(`The inspector could not be reached: ${error.message}`);
  } finally {
    setBusy(false);
  }
}

function renderResult(result, scenario) {
  const verdictClass = result.verdict === "Trusted" ? "pass" : result.verdict === "Unreachable" ? "unknown" : "fail";
  const verdictIcon = result.verdict === "Trusted" ? "&check;" : result.verdict === "Unreachable" ? "!" : "&times;";

  const sections = [
    renderVerdict(result, verdictClass, verdictIcon),
    scenario ? renderTeaching(scenario) : "",
    result.handshake ? renderHandshake(result) : "",
    result.strictOutcome ? renderStrict(result.strictOutcome) : "",
    result.findings?.length ? renderFindings(result.findings) : "",
    result.chain?.length ? renderChain(result.chain) : "",
    renderRaw(result),
  ];

  resultPanel.innerHTML = sections.filter(Boolean).join("");
  resultPanel.hidden = false;
  emptyState.hidden = true;
  errorState.hidden = true;
  // On narrow screens the results sit below the whole sidebar, so bring them into view properly.
  const stacked = window.matchMedia("(max-width: 980px)").matches;
  resultPanel.scrollIntoView({ behavior: "smooth", block: stacked ? "start" : "nearest" });
}

function renderVerdict(result, verdictClass, verdictIcon) {
  const anchorNote = result.customTrustApplied ? " Validated against the trust anchor you supplied." : "";
  return `
    <div class="verdict ${verdictClass}">
      <div class="verdict-icon">${verdictIcon}</div>
      <div>
        <h2>${escapeHtml(result.headline)}</h2>
        <p>
          <span class="target">${escapeHtml(result.host)}:${result.port}</span>
          ${result.serverName !== result.host ? ` &middot; SNI ${escapeHtml(result.serverName)}` : ""}
          &middot; checked ${formatDate(result.checkedAtUtc)} &middot; ${result.elapsedMilliseconds} ms${escapeHtml(anchorNote)}
        </p>
        ${
          result.policyErrors?.length
            ? `<p>SslPolicyErrors: <code>${escapeHtml(result.policyErrors.join(", "))}</code></p>`
            : ""
        }
      </div>
    </div>`;
}

function renderTeaching(scenario) {
  return `
    <div class="section">
      <h3>Scenario</h3>
      <p class="teaching"><strong>${escapeHtml(scenario.title)}.</strong> ${escapeHtml(scenario.teachingPoint)}</p>
    </div>`;
}

function renderHandshake(result) {
  const handshake = result.handshake;
  const exchange = !handshake.keyExchangeAlgorithm || handshake.keyExchangeAlgorithm === "None"
    ? "folded into the handshake (TLS 1.3)"
    : handshake.keyExchangeAlgorithm;

  const facts = [
    ["Protocol", handshake.protocol],
    ["Cipher suite", handshake.cipherSuite],
    ["Key exchange", exchange],
    ["Bulk cipher", `${handshake.cipherAlgorithm} · ${handshake.cipherStrengthBits} bits`],
    ["Endpoint", handshake.remoteEndpoint ?? "unknown"],
    ["Handshake time", `${handshake.handshakeMilliseconds} ms`],
    ["Revocation checked", result.revocationChecked ? "yes (CRL/OCSP)" : "no"],
    ["Chain length", `${result.chain.length} certificate${result.chain.length === 1 ? "" : "s"}`],
  ];

  return `
    <div class="section">
      <h3>Negotiated session</h3>
      <dl class="facts">
        ${facts
          .map(([term, value]) => `<div class="fact"><dt>${escapeHtml(term)}</dt><dd>${escapeHtml(value)}</dd></div>`)
          .join("")}
      </dl>
    </div>`;
}

function renderStrict(strict) {
  return `
    <div class="section">
      <h3>What a default client sees</h3>
      <div class="strict ${strict.succeeded ? "pass" : "fail"}">
        <div>
          <span class="label">${strict.succeeded ? "Connection accepted" : `${escapeHtml(strict.exceptionType ?? "Rejected")} thrown`}</span>
          <p>${escapeHtml(strict.message ?? "")}</p>
        </div>
      </div>
    </div>`;
}

function renderFindings(findings) {
  return `
    <div class="section">
      <h3>Validation checks</h3>
      <div class="findings">
        ${findings
          .map((finding) => {
            const severity = finding.severity.toLowerCase();
            const label = { pass: "PASS", info: "INFO", warning: "WARN", error: "FAIL" }[severity] ?? "INFO";
            return `
              <div class="finding">
                <span class="badge ${severity}">${label}</span>
                <div>
                  <h4>${escapeHtml(finding.title)}</h4>
                  <p>${escapeHtml(finding.detail)}</p>
                </div>
              </div>`;
          })
          .join("")}
      </div>
    </div>`;
}

function renderChain(chain) {
  return `
    <div class="section">
      <h3>Certificate chain</h3>
      <div class="chain">
        ${chain
          .map((certificate, index) => {
            const role = index === 0 ? "leaf" : certificate.isCertificateAuthority ? "certificate authority" : "intermediate";
            const facts = [
              ["Subject", certificate.subject],
              ["Issuer", certificate.issuer],
              ["Valid from", formatDate(certificate.notBefore)],
              ["Valid until", `${formatDate(certificate.notAfter)} (${formatDays(certificate.daysUntilExpiry)})`],
              ["Public key", `${certificate.publicKeyAlgorithm} ${certificate.publicKeySizeBits} bits`],
              ["Signature", certificate.signatureAlgorithm],
              ["Serial", certificate.serialNumber],
              ["SHA-256", certificate.sha256Fingerprint],
            ];

            if (certificate.subjectAlternativeNames?.length) {
              facts.push(["Subject alternative names", certificate.subjectAlternativeNames.join(", ")]);
            }
            if (certificate.extendedKeyUsages?.length) {
              facts.push(["Extended key usage", certificate.extendedKeyUsages.join(", ")]);
            }

            return `
              <details class="cert" ${index === 0 ? "open" : ""}>
                <summary>
                  <span class="cert-depth">${index}</span>
                  <span class="cert-name">${escapeHtml(certificate.commonName ?? certificate.subject)}</span>
                  <span class="cert-role">${escapeHtml(role)}${certificate.isSelfSigned ? " · self-signed" : ""}</span>
                </summary>
                <div class="cert-body">
                  ${certificate.chainStatus
                    ?.map((status) => `<span class="status-flag" title="${escapeHtml(status.explanation)}">${escapeHtml(status.status)}</span>`)
                    .join("") ?? ""}
                  <dl>
                    ${facts
                      .map(([term, value]) => `<div class="fact"><dt>${escapeHtml(term)}</dt><dd>${escapeHtml(value)}</dd></div>`)
                      .join("")}
                  </dl>
                  <details class="pem-toggle">
                    <summary>PEM</summary>
                    <pre>${escapeHtml(certificate.pem)}</pre>
                  </details>
                </div>
              </details>`;
          })
          .join("")}
      </div>
    </div>`;
}

function renderRaw(result) {
  return `
    <div class="section">
      <h3>Raw result</h3>
      <details class="pem-toggle">
        <summary>The same report as JSON, exactly what <code>POST /api/inspect</code> returns</summary>
        <pre>${escapeHtml(JSON.stringify(result, null, 2))}</pre>
      </details>
    </div>`;
}

form.addEventListener("submit", (event) => {
  event.preventDefault();
  const host = document.getElementById("host").value.trim();
  if (!host) {
    showError("Enter a hostname to inspect.");
    return;
  }

  const port = Number(document.getElementById("port").value) || 443;
  inspect(
    {
      host,
      port,
      serverName: document.getElementById("sni").value.trim() || null,
      checkRevocation: document.getElementById("revocation").checked,
      protocol: document.getElementById("protocol").value,
      trustAnchorPem: document.getElementById("anchor").value.trim() || null,
    },
    `${host}:${port}`,
  );
});

presetsContainer.addEventListener("click", (event) => {
  const chip = event.target.closest("button[data-host]");
  if (!chip) return;

  document.getElementById("host").value = chip.dataset.host;
  document.getElementById("port").value = chip.dataset.port;
  form.requestSubmit();
});

scenariosContainer.addEventListener("click", (event) => {
  const button = event.target.closest("button[data-scenario]");
  if (!button) return;

  const scenario = scenarios.find((entry) => entry.id === button.dataset.scenario);
  if (!scenario) return;

  inspect(
    { scenarioId: scenario.id, useTrustAnchor: button.dataset.anchor === "true" },
    `${scenario.title.toLowerCase()} on localhost:${scenario.port}`,
    scenario,
  );
});

/** Restores an inspection from the query string, so a result can be linked to or reloaded. */
function runFromUrl() {
  const params = new URLSearchParams(location.search);
  const scenarioId = params.get("scenario");

  if (scenarioId) {
    const scenario = scenarios.find((entry) => entry.id === scenarioId);
    if (!scenario) return;

    inspect(
      { scenarioId, useTrustAnchor: params.get("trust") === "1" },
      `${scenario.title.toLowerCase()} on localhost:${scenario.port}`,
      scenario,
    );
    return;
  }

  const host = params.get("host");
  if (!host) return;

  document.getElementById("host").value = host;
  document.getElementById("port").value = params.get("port") ?? 443;
  document.getElementById("protocol").value = params.get("protocol") ?? "system";
  document.getElementById("revocation").checked = params.get("revocation") === "1";
  form.requestSubmit();
}

loadSidebar().then(runFromUrl);
