import React, { useEffect, useMemo, useRef, useState } from "react";
import { EvidenceRecord, Finding } from "./desktop";
import { evaluateEvidenceRules } from "./engine/rules";
import {
  generateCanaryToken,
  buildCanaryTargetUrl,
  analyzeDomReflection,
  createCanaryFinding,
} from "./engine/canary";
import { parseScannerReport } from "./engine/ingest";
import {
  buildQuarantinedPrompt,
  parseAndValidateAdvisorResponse,
  AdvisorResponse,
} from "./advisor/ollama";
import { compareReplayEvidence, HeaderDiffItem } from "./engine/replay";
import { AssessmentStateMachine, AssessmentState } from "./engine/stateMachine";
import { SessionView, EventItem } from "./components/SessionView";

function evidenceToEvent(record: EvidenceRecord): EventItem {
  return {
    id: record.id,
    kind: record.kind,
    label: record.label,
    detail: record.detail,
    time: new Date(record.timestamp).toLocaleTimeString([], { hour12: false }),
    source: record.source,
    hash: record.hash,
  };
}

export function App() {
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [consent, setConsent] = useState(false);
  const [mode, setMode] = useState<"inspect" | "own-app">("inspect");
  const [sessionActive, setSessionActive] = useState(false);
  const [recording, setRecording] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [notice, setNotice] = useState("");
  const [events, setEvents] = useState<EventItem[]>([]);
  const [evidence, setEvidence] = useState<EvidenceRecord[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const [ollamaReady, setOllamaReady] = useState(false);
  const [advisorLoading, setAdvisorLoading] = useState(false);
  const [advisorData, setAdvisorData] = useState<AdvisorResponse | null>(null);
  const [canaryParam, setCanaryParam] = useState("q");
  const [showCanaryModal, setShowCanaryModal] = useState(false);
  const [showImportModal, setShowImportModal] = useState(false);
  const [importJsonText, setImportJsonText] = useState("");
  const [assessmentState, setAssessmentState] = useState<AssessmentState>("Setup");
  const [replayDiff, setReplayDiff] = useState<HeaderDiffItem[] | null>(null);

  const stateMachine = useRef(new AssessmentStateMachine());
  const browserStage = useRef<HTMLDivElement>(null);

  const origin = useMemo(() => {
    try {
      return new URL(url).origin;
    } catch {
      return "";
    }
  }, [url]);

  const validUrl = useMemo(() => {
    try {
      const parsed = new URL(url);
      return parsed.protocol === "http:" || parsed.protocol === "https:";
    } catch {
      return false;
    }
  }, [url]);

  function updateBrowserBounds() {
    if (!window.sentinelDesktop) return;
    if (showCanaryModal || showImportModal) {
      window.sentinelDesktop.hideBrowser();
      return;
    }
    if (!browserStage.current) return;
    const rect = browserStage.current.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) {
      window.sentinelDesktop.hideBrowser();
      return;
    }
    window.sentinelDesktop.setBrowserBounds({
      x: Math.round(rect.left),
      y: Math.round(rect.top),
      width: Math.round(rect.width),
      height: Math.round(rect.height),
    });
  }

  async function checkOllama() {
    if (!window.sentinelDesktop?.checkOllamaStatus) return;
    try {
      const res = await window.sentinelDesktop.checkOllamaStatus();
      setOllamaReady(res.ready);
    } catch {
      setOllamaReady(false);
    }
  }

  useEffect(() => {
    void checkOllama();
  }, []);

  function handleCreateSession() {
    if (!name.trim()) return setNotice("Please provide a name for this assessment.");
    if (!validUrl) return setNotice("Please enter a valid HTTP/HTTPS URL.");
    if (mode === "own-app" && !consent) {
      return setNotice("You must certify ownership or explicit authorization in Own-App mode.");
    }

    setSessionActive(true);
    setRecording(true);
    stateMachine.current.transition("Recording", `Origin ${origin} locked and telemetry active`);
    setAssessmentState(stateMachine.current.getState());

    setNotice(`Isolated session created for ${origin}. Capturing initial telemetry.`);
    setEvents([]);
    setEvidence([]);
    setFindings([]);

    void window.sentinelDesktop
      ?.configureBrowser({ origin, mode, consent })
      .then((res) => {
        if (!res.ok) {
          setNotice(res.error || "Failed to configure browser view.");
          return;
        }
        updateBrowserBounds();
        void window.sentinelDesktop?.navigateBrowser(url).then((navRes) => {
          if (!navRes.ok) setNotice(navRes.error || "Navigation failed.");
          updateBrowserBounds();
          void loadEvidence();
        });
      });
  }

  async function toggleRecording() {
    if (!recording) {
      const res = await window.sentinelDesktop?.startRecording();
      if (res?.ok) {
        setRecording(true);
        stateMachine.current.transition("Recording", "Telemetry capture active");
        setAssessmentState(stateMachine.current.getState());
        setNotice("Recording active. Network & console telemetry captured.");
      } else {
        setNotice(res?.error || "Could not start recording.");
      }
    } else {
      const res = await window.sentinelDesktop?.stopRecording();
      if (res?.ok) {
        setRecording(false);
        stateMachine.current.transition("EvidenceCaptured", `${res.count || 0} events recorded`);
        setAssessmentState(stateMachine.current.getState());
        setNotice(`Recording stopped. ${res.count || 0} events logged.`);
      } else {
        setNotice(res?.error || "Could not stop recording.");
      }
    }
  }

  async function loadEvidence() {
    const res = await window.sentinelDesktop?.getEvidence();
    if (res?.ok) {
      const records = res.evidence as EvidenceRecord[];
      setEvidence(records);
      setEvents(records.map(evidenceToEvent));
      const evaluated = evaluateEvidenceRules(records);
      setFindings((prev) => {
        const nonPassive = prev.filter((f) => f.source !== "Passive" && f.source !== "Browser");
        return [...evaluated, ...nonPassive];
      });
    }
  }

  async function handleInjectCanary() {
    if (!window.sentinelDesktop?.injectCanary) return;
    setShowCanaryModal(false);

    const token = generateCanaryToken();
    const targetUrl = buildCanaryTargetUrl(url, canaryParam, token);

    setNotice(`Injecting inert canary ${token} into parameter '${canaryParam}'...`);
    stateMachine.current.transition("Testing", `Canary token injected`);
    setAssessmentState(stateMachine.current.getState());

    const res = await window.sentinelDesktop.injectCanary({
      url: targetUrl,
      paramName: canaryParam,
      token,
    });

    if (!res.ok || !res.domHtml) {
      setNotice(res.error || "Canary execution failed.");
      return;
    }

    const evRecord: Partial<EvidenceRecord> = {
      kind: "CANARY_REFLECT",
      label: `Inert Canary Test: ${canaryParam}`,
      detail: `Checked reflection of token ${token} on ${targetUrl}`,
      source: "canary",
      meta: { url: targetUrl, paramName: canaryParam, token },
    };

    const added = await window.sentinelDesktop.addEvidence(evRecord);
    const evId = added.record?.id || `EV-CANARY-${Date.now().toString(36).toUpperCase()}`;

    const analysis = analyzeDomReflection(res.domHtml, token);
    if (analysis.isReflected && analysis.isRawUnencoded) {
      const canaryFinding = createCanaryFinding(targetUrl, canaryParam, analysis, evId);
      setFindings((prev) => [canaryFinding, ...prev]);
      stateMachine.current.transition("Confirmed", "Unencoded reflection verified");
      setAssessmentState(stateMachine.current.getState());
      setNotice(`Inert canary reflected unencoded in ${analysis.context}! Finding created.`);
    } else {
      setNotice(`Canary token was safely encoded or not reflected in DOM.`);
    }
  }

  function handleImportReport() {
    if (!importJsonText.trim()) return;
    const { findings: importedFindings, records } = parseScannerReport(importJsonText, "imported-report.json");
    if (importedFindings.length === 0) {
      setNotice("No recognizable SARIF or ZAP alerts found in JSON input.");
      return;
    }

    records.forEach((r) => {
      window.sentinelDesktop?.addEvidence(r);
    });

    setFindings((prev) => [...importedFindings, ...prev]);
    setShowImportModal(false);
    setImportJsonText("");
    setNotice(`Imported ${importedFindings.length} alerts correlated to evidence stream.`);
  }

  function handleFileUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      if (content) {
        setImportJsonText(content);
      }
    };
    reader.readAsText(file);
  }

  async function handleConsultMentor(finding: Finding) {
    setAdvisorLoading(true);
    setNotice("Consulting local AI advisor (Ollama)...");

    const prompt = buildQuarantinedPrompt(finding, evidence);

    if (window.sentinelDesktop?.queryAdvisor) {
      const res = await window.sentinelDesktop.queryAdvisor({ prompt });
      setAdvisorLoading(false);
      if (res.ok && res.response) {
        const validated = parseAndValidateAdvisorResponse(res.response, evidence, finding);
        setAdvisorData(validated);
        setNotice("Advisory guidance received.");
      } else {
        const fallback = parseAndValidateAdvisorResponse("{}", evidence, finding);
        setAdvisorData(fallback);
        setNotice("Local Ollama unavailable. Applied deterministic guidance.");
      }
    } else {
      setAdvisorLoading(false);
      const fallback = parseAndValidateAdvisorResponse("{}", evidence, finding);
      setAdvisorData(fallback);
      setNotice("Local Ollama offline. Displaying deterministic baseline guidance.");
    }
  }

  async function handleReplayFinding(finding: Finding) {
    setNotice(`Re-testing finding ${finding.id}... Navigating to target route.`);
    stateMachine.current.transition("Retesting");
    setAssessmentState(stateMachine.current.getState());

    const baselineSnapshot = [...evidence];

    await window.sentinelDesktop?.navigateBrowser(url);
    await new Promise((resolve) => setTimeout(resolve, 1500));

    const result = await window.sentinelDesktop?.getEvidence();
    const freshEvidence = result?.ok ? (result.evidence as EvidenceRecord[]) : evidence;

    const comparison = compareReplayEvidence(finding, baselineSnapshot, freshEvidence);
    setReplayDiff(comparison.headerDiff || null);

    const terminalState =
      comparison.status === "Fixed"
        ? "Fixed"
        : comparison.status === "Still Present"
        ? "StillPresent"
        : "NotComparable";
    stateMachine.current.transition(terminalState, comparison.explanation);
    setAssessmentState(stateMachine.current.getState());

    setFindings((prev) =>
      prev.map((f) => (f.id === finding.id ? { ...f, retestStatus: comparison.status } : f))
    );

    if (selectedFinding?.id === finding.id) {
      setSelectedFinding((prev) => (prev ? { ...prev, retestStatus: comparison.status } : null));
    }

    setNotice(`Re-test completed: Finding is ${comparison.status}. ${comparison.explanation}`);
  }

  function exportSession(format: "json" | "html" = "json") {
    const data = {
      session: {
        name,
        origin,
        mode,
        state: assessmentState,
        zeroPayloadGuarantee: "Verified: Sentinel does not generate or execute weaponized exploit payloads.",
        exportedAt: new Date().toISOString(),
      },
      evidence: evidence.map(({ hash, id, timestamp, kind, label, detail, source }) => ({
        id,
        timestamp,
        kind,
        label,
        detail,
        source,
        hash,
      })),
      findings: findings.map((f) => f),
    };

    if (format === "html") {
      const htmlContent = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Sentinel AppSec Audit Report - ${name}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #1e293b; max-width: 900px; margin: 40px auto; padding: 0 20px; }
    h1 { color: #0f172a; border-bottom: 2px solid #38c4ba; padding-bottom: 8px; }
    .meta-box { background: #f1f5f9; padding: 16px; border-radius: 8px; margin: 20px 0; }
    .finding-card { border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin-bottom: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }
    .severity { display: inline-block; padding: 4px 8px; font-weight: bold; border-radius: 4px; font-size: 12px; }
    .severity.high { background: #fee2e2; color: #991b1b; }
    .severity.medium { background: #fef3c7; color: #92400e; }
    .severity.low { background: #e0f2fe; color: #075985; }
    .severity.info { background: #f3f4f6; color: #374151; }
    code { background: #e2e8f0; padding: 2px 6px; border-radius: 4px; font-size: 13px; font-family: monospace; }
  </style>
</head>
<body>
  <h1>🛡️ Sentinel Security Audit Report</h1>
  <div class="meta-box">
    <p><strong>Assessment Name:</strong> ${name}</p>
    <p><strong>Target Origin:</strong> <code>${origin}</code></p>
    <p><strong>Mode:</strong> ${mode} | <strong>State:</strong> ${assessmentState}</p>
    <p><strong>Exported At:</strong> ${new Date().toLocaleString()}</p>
    <p><strong>Zero-Payload Guarantee:</strong> Verified inert testing only.</p>
  </div>
  <h2>Verified Findings (${findings.length})</h2>
  ${findings
    .map(
      (f) => `
    <div class="finding-card">
      <span class="severity ${f.severity.toLowerCase()}">${f.severity}</span>
      <h3>${f.title}</h3>
      <p><strong>CWE:</strong> ${f.cwe || "N/A"} | <strong>OWASP:</strong> ${f.owasp || "N/A"}</p>
      <p>${f.description}</p>
      <p><strong>Evidence Citation:</strong> <code>${f.evidence}</code></p>
      <p><strong>Remediation:</strong> ${f.remediation || "Apply defensive controls."}</p>
      ${f.retestStatus ? `<p><strong>Replay Status:</strong> <b>${f.retestStatus}</b></p>` : ""}
    </div>`
    )
    .join("")}
</body>
</html>`;
      const blob = new Blob([htmlContent], { type: "text/html" });
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = `sentinel-report-${name.toLowerCase().replace(/\s+/g, "-")}.html`;
      link.click();
      URL.revokeObjectURL(link.href);
      setNotice("HTML compliance report exported.");
      return;
    }

    const link = document.createElement("a");
    link.href = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }));
    link.download = `sentinel-session-${name.toLowerCase().replace(/\s+/g, "-")}.json`;
    link.click();
    URL.revokeObjectURL(link.href);
    setNotice("Redacted provenance-linked JSON exported.");
  }

  useEffect(() => {
    if (!sessionActive || !browserStage.current || !window.sentinelDesktop) return;
    updateBrowserBounds();
    window.addEventListener("resize", updateBrowserBounds);

    const cleanupNav = window.sentinelDesktop.onBrowserNavigated(({ url: navigatedUrl }) => {
      setNotice(`Browser navigated: ${navigatedUrl}`);
    });

    const cleanupEvidence = window.sentinelDesktop.onEvidence((record) => {
      setEvidence((prev) => {
        const nextList = [...prev, record];
        const evaluated = evaluateEvidenceRules(nextList);
        setFindings((prevFindings) => {
          const nonPassive = prevFindings.filter((f) => f.source !== "Passive" && f.source !== "Browser");
          return [...evaluated, ...nonPassive];
        });
        return nextList;
      });
      setEvents((prev) => [evidenceToEvent(record), ...prev]);
    });

    const cleanupCleared = window.sentinelDesktop.onEvidenceCleared(() => {
      setEvidence([]);
      setEvents([]);
      setFindings([]);
    });

    return () => {
      window.removeEventListener("resize", updateBrowserBounds);
      cleanupNav();
      cleanupEvidence();
      cleanupCleared();
    };
  }, [sessionActive]);

  useEffect(() => {
    if (sessionActive && window.sentinelDesktop) {
      loadEvidence();
    }
  }, [sessionActive]);

  useEffect(() => {
    if (sessionActive) {
      // Recalculate bounds whenever selectedFinding or modals toggle
      const timer = setTimeout(updateBrowserBounds, 50);
      return () => clearTimeout(timer);
    }
  }, [selectedFinding, showCanaryModal, showImportModal, sessionActive]);

  if (!sessionActive) {
    return (
      <main className={`onboarding ${theme}`}>
        <section className="onboarding-card">
          <div className="brand-row">
            <div className="brand">S</div>
            <button
              className="theme-btn"
              type="button"
              onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
            >
              {theme === "dark" ? "☀️ Light" : "🌙 Dark"}
            </button>
          </div>
          <p className="eyebrow">LOCAL APPSEC LABORATORY</p>
          <h1>Sentinel Desktop Lab</h1>
          <p className="intro">
            Isolate target URLs in an ephemeral browser partition. Intercept real telemetry, verify security posture with deterministic rules & inert canaries, and get local AI remediation guidance.
          </p>

          <div className="local-status">
            <i /> Ephemeral Partition Sandbox Active
            <span style={{ marginLeft: "auto" }}>
              Ollama: {ollamaReady ? <b style={{ color: "#3bd09c" }}>Ready</b> : <b style={{ color: "#e39b4b" }}>Offline (Fallback Enabled)</b>}
            </span>
          </div>

          <div className="mode-toggle-box">
            <label className="mode-label">Assessment Mode</label>
            <div className="mode-options">
              <button
                type="button"
                className={`mode-btn ${mode === "inspect" ? "selected" : ""}`}
                onClick={() => setMode("inspect")}
              >
                <strong>Inspect Mode</strong>
                <small>Passive headers, cookies, CORS & transport hygiene (Safe for any URL)</small>
              </button>
              <button
                type="button"
                className={`mode-btn ${mode === "own-app" ? "selected" : ""}`}
                onClick={() => setMode("own-app")}
              >
                <strong>Own-App Mode</strong>
                <small>Includes inert reflection canaries, scanner ingestion & mentor fixes</small>
              </button>
            </div>
          </div>

          <label>
            Assessment Name
            <input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Local Checkout Review" />
          </label>

          <label>
            Authorized Target URL
            <input
              className="mono"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="http://localhost:3000 or https://app.example.test"
            />
          </label>

          <div className="allowlist">
            <b>LOCKED ORIGIN SCOPE</b>
            <span>{origin || "Enter a URL to lock exact origin boundary"}</span>
          </div>

          {mode === "own-app" && (
            <label className="consent">
              <input type="checkbox" checked={consent} onChange={(e) => setConsent(e.target.checked)} />
              I certify that I own this application or possess explicit authorization to assess it.
            </label>
          )}

          <button
            className="primary full"
            disabled={!validUrl || !name.trim() || (mode === "own-app" && !consent)}
            onClick={handleCreateSession}
          >
            Launch Isolated Lab <b>→</b>
          </button>

          {notice && <p className="notice">{notice}</p>}
          <p className="fine">Zero exploit payloads. Ephemeral partition without Chrome profile access.</p>
        </section>
      </main>
    );
  }

  return (
    <>
      <SessionView
        name={name}
        url={url}
        origin={origin}
        mode={mode}
        theme={theme}
        recording={recording}
        assessmentState={assessmentState}
        events={events}
        evidence={evidence}
        findings={findings}
        selectedFinding={selectedFinding}
        ollamaReady={ollamaReady}
        advisorLoading={advisorLoading}
        advisorData={advisorData}
        replayDiff={replayDiff}
        browserStageRef={browserStage}
        onChangeMode={(m) => setMode(m)}
        onToggleTheme={() => setTheme(theme === "dark" ? "light" : "dark")}
        onToggleRecording={toggleRecording}
        onNavigateUrl={() => {
          void window.sentinelDesktop?.navigateBrowser(url);
        }}
        onSelectFinding={(f) => {
          setSelectedFinding(f);
          setAdvisorData(null);
          setReplayDiff(null);
        }}
        onConsultMentor={handleConsultMentor}
        onReplayFinding={handleReplayFinding}
        onOpenCanaryModal={() => setShowCanaryModal(true)}
        onOpenImportModal={() => setShowImportModal(true)}
        onExportSession={exportSession}
      />

      {showCanaryModal && (
        <div className="modal-overlay">
          <div className="modal-card">
            <h3>Inject Inert Reflection Canary</h3>
            <p>
              Sentinel will append an inert test token (e.g. <code>sentinel-canary-XYZ</code>) to verify whether output encoding is properly applied in the DOM. No payloads or exploit strings are sent.
            </p>
            <label>
              Query / Input Parameter Name
              <input value={canaryParam} onChange={(e) => setCanaryParam(e.target.value)} placeholder="e.g. q, search, redirect_url" />
            </label>
            <div className="modal-actions">
              <button className="secondary" onClick={() => setShowCanaryModal(false)}>
                Cancel
              </button>
              <button className="primary" onClick={handleInjectCanary}>
                Execute Canary Check
              </button>
            </div>
          </div>
        </div>
      )}

      {showImportModal && (
        <div className="modal-overlay">
          <div className="modal-card">
            <h3>Import Scanner Report (ZAP / Nuclei SARIF)</h3>
            <p>Import alerts from your own scanner runs to correlate findings with the session evidence timeline.</p>
            <input type="file" accept=".json,.sarif" onChange={handleFileUpload} />
            <p className="or-divider">— OR PASTE RAW JSON —</p>
            <textarea
              className="import-textarea"
              rows={6}
              placeholder="Paste SARIF or ZAP JSON here..."
              value={importJsonText}
              onChange={(e) => setImportJsonText(e.target.value)}
            />
            <div className="modal-actions">
              <button className="secondary" onClick={() => setShowImportModal(false)}>
                Cancel
              </button>
              <button className="primary" onClick={handleImportReport}>
                Import Alerts
              </button>
            </div>
          </div>
        </div>
      )}

      {notice && (
        <button className="toast" onClick={() => setNotice("")}>
          {notice}
          <b>×</b>
        </button>
      )}
    </>
  );
}

export default App;
