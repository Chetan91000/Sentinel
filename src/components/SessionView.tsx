import React, { useState, useMemo } from "react";
import { EvidenceRecord, Finding } from "../desktop";
import { AdvisorResponse } from "../advisor/ollama";
import { HeaderDiffItem } from "../engine/replay";
import { AssessmentState } from "../engine/stateMachine";
import "./SessionView.css";

export interface EventItem {
  id: string;
  kind: string;
  label: string;
  detail: string;
  time: string;
  source: string;
  hash?: string;
}

export interface SessionViewProps {
  name: string;
  url: string;
  origin: string;
  mode: "inspect" | "own-app";
  theme: "dark" | "light";
  recording: boolean;
  assessmentState: AssessmentState;
  events: EventItem[];
  evidence: EvidenceRecord[];
  findings: Finding[];
  selectedFinding: Finding | null;
  ollamaReady: boolean;
  advisorLoading: boolean;
  advisorData: AdvisorResponse | null;
  replayDiff: HeaderDiffItem[] | null;
  browserStageRef: React.RefObject<HTMLDivElement | null>;
  onChangeMode?: (mode: "inspect" | "own-app") => void;
  onToggleTheme: () => void;
  onToggleRecording: () => void;
  onNavigateUrl: () => void;
  onSelectFinding: (finding: Finding | null) => void;
  onConsultMentor: (finding: Finding) => void;
  onReplayFinding: (finding: Finding) => void;
  onOpenCanaryModal: () => void;
  onOpenImportModal: () => void;
  onExportSession: (format: "json" | "html") => void;
}

function parseEventDetails(e: EventItem, evidenceMap: Map<string, EvidenceRecord>) {
  const ev = evidenceMap.get(e.id);
  const meta = ev?.meta as Record<string, unknown> | undefined;

  let method = "GET";
  let methodClass = "sv-method--get";
  let statusCode = "--";
  let statusClass = "sv-status--2xx";
  let displayUrl = e.label;

  if (meta?.method && typeof meta.method === "string") {
    method = meta.method.toUpperCase();
  } else if (e.detail.startsWith("GET ")) {
    method = "GET";
  } else if (e.detail.startsWith("POST ")) {
    method = "POST";
  } else if (e.detail.startsWith("PUT ")) {
    method = "PUT";
  } else if (e.detail.startsWith("DELETE ")) {
    method = "DELETE";
  } else if (e.kind === "CONSOLE") {
    method = "LOG";
  } else if (e.kind === "CANARY_REFLECT") {
    method = "TEST";
  } else if (e.kind === "SCANNER_ALERT") {
    method = "ALERT";
  } else if (e.kind === "COOKIE") {
    method = "SET";
  }

  const mLower = method.toLowerCase();
  if (mLower === "get") methodClass = "sv-method--get";
  else if (mLower === "post") methodClass = "sv-method--post";
  else if (mLower === "put") methodClass = "sv-method--put";
  else if (mLower === "delete") methodClass = "sv-method--delete";
  else methodClass = "sv-method--get";

  if (meta?.statusCode && typeof meta.statusCode === "number") {
    statusCode = String(meta.statusCode);
    if (meta.statusCode >= 200 && meta.statusCode < 300) statusClass = "sv-status--2xx";
    else if (meta.statusCode >= 300 && meta.statusCode < 400) statusClass = "sv-status--3xx";
    else if (meta.statusCode >= 400 && meta.statusCode < 500) statusClass = "sv-status--4xx";
    else if (meta.statusCode >= 500) statusClass = "sv-status--5xx";
  } else if (e.kind === "RES" || e.kind === "RES_DONE") {
    statusCode = "200";
    statusClass = "sv-status--2xx";
  }

  try {
    if (e.label.startsWith("http://") || e.label.startsWith("https://")) {
      const parsed = new URL(e.label);
      displayUrl = (parsed.pathname || "/") + parsed.search;
    }
  } catch {
    displayUrl = e.label;
  }

  return { method, methodClass, statusCode, statusClass, displayUrl };
}

export function SessionView({
  name,
  url,
  origin,
  mode,
  theme,
  recording,
  assessmentState,
  events,
  evidence,
  findings,
  selectedFinding,
  ollamaReady,
  advisorLoading,
  advisorData,
  replayDiff,
  browserStageRef,
  onChangeMode,
  onToggleTheme,
  onToggleRecording,
  onNavigateUrl,
  onSelectFinding,
  onConsultMentor,
  onReplayFinding,
  onOpenCanaryModal,
  onOpenImportModal,
  onExportSession,
}: SessionViewProps) {
  const [activeTab, setActiveTab] = useState<"impact" | "evidence" | "remediation">("impact");
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);
  const [isRetesting, setIsRetesting] = useState(false);
  const [filterQuery, setFilterQuery] = useState("");
  const [telemetryFilter, setTelemetryFilter] = useState<"all" | "network" | "cookies" | "console" | "canary" | "scanner">("all");

  const evidenceMap = useMemo(() => {
    const map = new Map<string, EvidenceRecord>();
    evidence.forEach((rec) => map.set(rec.id, rec));
    return map;
  }, [evidence]);

  const matchedEvidence = useMemo(() => {
    if (!selectedFinding) return null;
    return evidenceMap.get(selectedFinding.evidence) || null;
  }, [selectedFinding, evidenceMap]);

  const filteredEvents = useMemo(() => {
    return events.filter((e) => {
      if (telemetryFilter === "network" && !["REQ", "RES", "RES_DONE", "ERR"].includes(e.kind)) return false;
      if (telemetryFilter === "cookies" && !["RES", "COOKIE"].includes(e.kind)) return false;
      if (telemetryFilter === "console" && e.kind !== "CONSOLE") return false;
      if (telemetryFilter === "canary" && e.kind !== "CANARY_REFLECT") return false;
      if (telemetryFilter === "scanner" && e.kind !== "SCANNER_ALERT") return false;

      if (filterQuery.trim()) {
        const q = filterQuery.toLowerCase();
        return (
          e.label.toLowerCase().includes(q) ||
          e.detail.toLowerCase().includes(q) ||
          e.id.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [events, telemetryFilter, filterQuery]);

  async function handleRetest() {
    if (!selectedFinding) return;
    setIsRetesting(true);
    try {
      await onReplayFinding(selectedFinding);
    } finally {
      setIsRetesting(false);
    }
  }

  let retestStateClass = "";
  let retestButtonText = "Re-test Finding (Replay) ↻";
  if (isRetesting) {
    retestButtonText = "Running Re-test…";
  } else if (selectedFinding?.retestStatus === "Fixed") {
    retestStateClass = "passed";
    retestButtonText = "✔ Re-test Passed (Fixed)";
  } else if (selectedFinding?.retestStatus === "Still Present") {
    retestStateClass = "failed";
    retestButtonText = "✖ Still Failing (Present)";
  } else if (selectedFinding?.retestStatus === "Not Comparable") {
    retestButtonText = "Re-test Inconclusive ↻";
  }

  return (
    <div className={`sv-root ${theme}`}>
      {/* Top Bar */}
      <header className="sv-topbar">
        <div className="sv-brand">
          <div className="sv-logo">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" fill="rgba(34, 211, 238, 0.15)" stroke="#22d3ee" />
            </svg>
          </div>
          <span className="sv-brand-name">SENTINEL</span>
          <span className="sv-brand-tag">{mode === "own-app" ? "Own App" : "Inspect"}</span>
          <span style={{ fontSize: "11px", color: "var(--sv-text-2)", marginLeft: "4px" }}>
            {name ? `· ${name}` : ""} ({assessmentState})
          </span>
        </div>

        <div className="sv-mode-toggle">
          <button
            type="button"
            className={`sv-mode-btn ${mode === "inspect" ? "is-active" : ""}`}
            onClick={() => onChangeMode && onChangeMode("inspect")}
          >
            Inspect
          </button>
          <button
            type="button"
            className={`sv-mode-btn ${mode === "own-app" ? "is-active" : ""}`}
            onClick={() => onChangeMode && onChangeMode("own-app")}
          >
            Own App
          </button>
        </div>

        <div className="sv-status">
          {mode === "own-app" && (
            <>
              <button
                type="button"
                className="sv-stop-btn is-ghost"
                style={{ fontSize: "11px", padding: "4px 10px" }}
                onClick={onOpenCanaryModal}
              >
                + Canary
              </button>
              <button
                type="button"
                className="sv-stop-btn is-ghost"
                style={{ fontSize: "11px", padding: "4px 10px" }}
                onClick={onOpenImportModal}
              >
                Import
              </button>
            </>
          )}
          <button
            type="button"
            className="sv-stop-btn is-ghost"
            style={{ fontSize: "11px", padding: "4px 10px" }}
            onClick={() => onExportSession("html")}
          >
            Export
          </button>
          <button
            type="button"
            className="sv-stop-btn is-ghost"
            style={{ fontSize: "11px", padding: "4px 10px" }}
            onClick={onToggleTheme}
            title="Toggle theme"
          >
            {theme === "dark" ? "☀️" : "🌙"}
          </button>
          <span className={`sv-indicator ${recording ? "is-live" : "is-stopped"}`} />
          <span className="sv-status-text">{recording ? "LIVE CAPTURE" : "STOPPED"}</span>
          <button
            type="button"
            className={`sv-stop-btn ${recording ? "is-danger" : "is-ghost"}`}
            onClick={onToggleRecording}
          >
            {recording ? "Stop Recording" : "Start Recording"}
          </button>
        </div>
      </header>

      {/* Main Body */}
      <div className="sv-body">
        {/* Left Column: Event Feed Sidebar */}
        <aside className="sv-feed">
          <div className="sv-feed-head">
            <h2>Live Telemetry</h2>
            <span className="sv-feed-count">{filteredEvents.length} events</span>
          </div>

          <div style={{ padding: "0 10px 8px 10px" }}>
            <input
              type="text"
              placeholder="Filter URL, label, ID..."
              value={filterQuery}
              onChange={(e) => setFilterQuery(e.target.value)}
              style={{
                width: "100%",
                padding: "6px 8px",
                fontSize: "11px",
                background: "rgba(10, 16, 28, 0.7)",
                border: "1px solid var(--sv-glass-brd)",
                borderRadius: "6px",
                color: "var(--sv-text-0)",
                outline: "none",
                fontFamily: "var(--sv-mono)",
              }}
            />
          </div>

          <ul className="sv-feed-list">
            {filteredEvents.map((e) => {
              const { method, methodClass, statusCode, statusClass, displayUrl } = parseEventDetails(
                e,
                evidenceMap
              );
              const isSelected = selectedEventId === e.id;
              return (
                <li key={e.id}>
                  <button
                    type="button"
                    className={`sv-feed-row ${isSelected ? "is-selected" : ""}`}
                    onClick={() => {
                      setSelectedEventId(isSelected ? null : e.id);
                      const matchingFinding = findings.find((f) => f.evidence === e.id);
                      if (matchingFinding) {
                        onSelectFinding(matchingFinding);
                        setActiveTab("evidence");
                      }
                    }}
                  >
                    <span className={`sv-method ${methodClass}`}>{method}</span>
                    <span className="sv-url" title={e.label}>
                      {displayUrl}
                    </span>
                    <span className={`sv-status ${statusClass}`}>{statusCode}</span>
                    <span className="sv-time">{e.time}</span>
                  </button>
                </li>
              );
            })}

            {filteredEvents.length === 0 && (
              <li className="sv-empty" style={{ padding: "40px 10px" }}>
                No events match query.
              </li>
            )}
          </ul>
        </aside>

        {/* Center/Right Main Area */}
        <main className="sv-main" style={{ display: "grid", gridTemplateRows: "minmax(220px, 1fr) auto 1fr", gap: "12px", overflowY: "auto" }}>
          {/* Section 1: Embedded Sandboxed Chromium Viewport */}
          <section className="sv-viewport-section" style={{ display: "flex", flexDirection: "column", minHeight: "220px" }}>
            <div
              className="sv-browser-bar"
              style={{
                display: "flex",
                alignItems: "center",
                gap: "8px",
                padding: "6px 12px",
                background: "var(--sv-glass)",
                border: "1px solid var(--sv-glass-brd)",
                borderRadius: "8px 8px 0 0",
                fontSize: "12px",
              }}
            >
              <button
                type="button"
                onClick={onNavigateUrl}
                title="Reload Target"
                style={{
                  background: "transparent",
                  border: "1px solid var(--sv-glass-brd)",
                  borderRadius: "4px",
                  color: "var(--sv-text-0)",
                  cursor: "pointer",
                  padding: "2px 8px",
                }}
              >
                ↻
              </button>
              <span style={{ color: "var(--sv-accent)", fontWeight: 700, fontSize: "11px" }}>🔒 LOCKED:</span>
              <code style={{ flex: 1, color: "var(--sv-text-0)", fontFamily: "var(--sv-mono)", fontSize: "11px" }}>
                {url || origin}
              </code>
              <span style={{ fontSize: "10px", color: "var(--sv-text-2)", textTransform: "uppercase" }}>
                {mode === "own-app" ? "Owned Lab" : "Inspect Mode"}
              </span>
            </div>

            {/* Native Chromium WebContentsView Mount Anchor Container */}
            <div
              ref={browserStageRef}
              className="sv-browser-stage"
              style={{
                flex: 1,
                minHeight: "180px",
                background: "rgba(5, 8, 14, 0.9)",
                border: "1px solid var(--sv-glass-brd)",
                borderTop: "none",
                borderRadius: "0 0 8px 8px",
                display: "flex",
                flexDirection: "column",
                alignItems: "center",
                justifyContent: "center",
                position: "relative",
                overflow: "hidden",
              }}
            >
              <div style={{ textAlign: "center", padding: "16px", color: "var(--sv-text-2)", pointerEvents: "none" }}>
                <div style={{ fontSize: "12px", fontWeight: 700, color: "var(--sv-text-1)", marginBottom: "4px" }}>
                  EPHEMERAL CHROMIUM VIEWPORT
                </div>
                <div style={{ fontSize: "11px" }}>
                  Active Electron sandbox rendered at this container's native OS coordinates.
                </div>
              </div>
            </div>
          </section>

          {/* Section 2: Findings Queue */}
          <section>
            <div className="sv-section-head">
              <h2>Active Findings</h2>
              <span className="sv-findings-sub">
                ({findings.length} detected on {origin || "locked origin"})
              </span>
            </div>

            <ul className="sv-findings-list">
              {findings.map((f) => {
                const isSelected = selectedFinding?.id === f.id;
                const sevClass =
                  f.severity === "High"
                    ? "sv-sev--high"
                    : f.severity === "Medium"
                    ? "sv-sev--medium"
                    : "sv-sev--low";
                return (
                  <li key={f.id}>
                    <button
                      type="button"
                      className={`sv-finding-card ${isSelected ? "is-selected" : ""}`}
                      onClick={() => {
                        onSelectFinding(f);
                        setActiveTab("impact");
                      }}
                    >
                      <span className={`sv-sev ${sevClass}`}>{f.severity.toUpperCase()}</span>
                      <span className="sv-finding-title">{f.title}</span>
                      <span className="sv-finding-req">
                        {f.evidence}
                        {f.retestStatus && (
                          <b
                            style={{
                              marginLeft: 6,
                              color: f.retestStatus === "Fixed" ? "var(--sv-green)" : "var(--sv-red)",
                            }}
                          >
                            [{f.retestStatus}]
                          </b>
                        )}
                      </span>
                    </button>
                  </li>
                );
              })}

              {findings.length === 0 && (
                <div
                  className="sv-finding-card"
                  style={{
                    gridColumn: "1 / -1",
                    justifyContent: "center",
                    padding: "20px",
                    color: "var(--sv-text-2)",
                  }}
                >
                  No security weaknesses detected yet. Interact with the target to stream telemetry.
                </div>
              )}
            </ul>
          </section>

          {/* Section 3: 3-Tab Inspector & Remediation */}
          <section className="sv-inspector" style={{ minHeight: "220px" }}>
            {selectedFinding ? (
              <>
                <div className="sv-tabs" style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                  <div style={{ display: "flex", gap: "2px" }}>
                    <button
                      type="button"
                      className={`sv-tab ${activeTab === "impact" ? "is-active" : ""}`}
                      onClick={() => setActiveTab("impact")}
                    >
                      Why this matters
                    </button>
                    <button
                      type="button"
                      className={`sv-tab ${activeTab === "evidence" ? "is-active" : ""}`}
                      onClick={() => setActiveTab("evidence")}
                    >
                      Evidence Citation
                    </button>
                    <button
                      type="button"
                      className={`sv-tab ${activeTab === "remediation" ? "is-active" : ""}`}
                      onClick={() => setActiveTab("remediation")}
                    >
                      Remediation Patch
                    </button>
                  </div>

                  <button
                    type="button"
                    className="sv-stop-btn is-ghost"
                    style={{
                      fontSize: "12px",
                      padding: "5px 12px",
                      background: "rgba(56, 189, 248, 0.12)",
                      border: "1px solid var(--sv-accent)",
                      color: "var(--sv-accent)",
                      fontWeight: 700,
                      borderRadius: "6px",
                      cursor: "pointer",
                      display: "flex",
                      alignItems: "center",
                      gap: "6px",
                    }}
                    disabled={advisorLoading}
                    onClick={() => {
                      setActiveTab("remediation");
                      onConsultMentor(selectedFinding);
                    }}
                  >
                    {advisorLoading ? (
                      "Querying Local AI..."
                    ) : (
                      <>
                        <span>⚡</span>
                        <span>{ollamaReady ? "Consult AI Mentor" : "Consult AI (Deterministic Fallback)"}</span>
                      </>
                    )}
                  </button>
                </div>

                <div className="sv-panel">
                  {activeTab === "impact" && (
                    <>
                      <h3 className="sv-block-title">{selectedFinding.title}</h3>
                      <p className="sv-prose">{selectedFinding.description}</p>
                      <div
                        style={{
                          marginTop: 14,
                          display: "flex",
                          gap: "8px",
                          flexWrap: "wrap",
                        }}
                      >
                        {selectedFinding.owasp && (
                          <span className="sv-brand-tag">OWASP: {selectedFinding.owasp}</span>
                        )}
                        {selectedFinding.cwe && (
                          <span className="sv-brand-tag">CWE: {selectedFinding.cwe}</span>
                        )}
                        <span className="sv-brand-tag">Source: {selectedFinding.source}</span>
                      </div>
                    </>
                  )}

                  {activeTab === "evidence" && (
                    <>
                      <h3 className="sv-block-title">Evidence Record: {selectedFinding.evidence}</h3>
                      {matchedEvidence ? (
                        <pre className="sv-code">
                          {JSON.stringify(
                            {
                              id: matchedEvidence.id,
                              timestamp: matchedEvidence.timestamp,
                              kind: matchedEvidence.kind,
                              label: matchedEvidence.label,
                              detail: matchedEvidence.detail,
                              source: matchedEvidence.source,
                              hash: matchedEvidence.hash,
                              meta: matchedEvidence.meta,
                            },
                            null,
                            2
                          )}
                        </pre>
                      ) : (
                        <p className="sv-prose">
                          Immutable Evidence ID Citation: <code>{selectedFinding.evidence}</code>
                        </p>
                      )}
                    </>
                  )}

                  {activeTab === "remediation" && (
                    <>
                      <div
                        style={{
                          display: "flex",
                          justifyContent: "space-between",
                          alignItems: "center",
                          marginBottom: "10px",
                        }}
                      >
                        <h3 className="sv-block-title" style={{ margin: 0 }}>
                          Defensive Remediation
                        </h3>
                        <button
                          type="button"
                          className="sv-stop-btn is-ghost"
                          style={{ fontSize: "11px", padding: "4px 10px" }}
                          disabled={advisorLoading}
                          onClick={() => onConsultMentor(selectedFinding)}
                        >
                          {advisorLoading
                            ? "Querying Local AI..."
                            : ollamaReady
                            ? "Consult AI Mentor ⚡"
                            : "Consult AI (Deterministic Fallback) ⚡"}
                        </button>
                      </div>

                      {advisorData ? (
                        <div>
                          <p className="sv-prose" style={{ marginBottom: 12 }}>
                            {advisorData.whyItMatters}
                          </p>
                          {advisorData.codePatches.map((patch, idx) => (
                            <div key={idx} style={{ marginBottom: 12 }}>
                              <div
                                style={{
                                  fontSize: "12px",
                                  fontWeight: 700,
                                  color: "var(--sv-accent)",
                                  marginBottom: 4,
                                }}
                              >
                                {patch.framework}: {patch.description}
                              </div>
                              <pre className="sv-code">{patch.code}</pre>
                            </div>
                          ))}
                        </div>
                      ) : selectedFinding.codePatch && selectedFinding.codePatch.length > 0 ? (
                        <div>
                          <p className="sv-prose" style={{ marginBottom: 12 }}>
                            {selectedFinding.remediation}
                          </p>
                          {selectedFinding.codePatch.map((patch, idx) => (
                            <div key={idx} style={{ marginBottom: 12 }}>
                              <div
                                style={{
                                  fontSize: "12px",
                                  fontWeight: 700,
                                  color: "var(--sv-accent)",
                                  marginBottom: 4,
                                }}
                              >
                                {patch.framework}
                              </div>
                              <pre className="sv-code">{patch.code}</pre>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <pre className="sv-code">
                          {selectedFinding.remediation ||
                            "Apply defensive controls in response headers and output encoding."}
                        </pre>
                      )}

                      {replayDiff && replayDiff.length > 0 && (
                        <div style={{ marginTop: 14 }}>
                          <h4 className="sv-block-title" style={{ fontSize: "12px" }}>
                            Header Replay Diff
                          </h4>
                          <pre className="sv-code">{JSON.stringify(replayDiff, null, 2)}</pre>
                        </div>
                      )}
                    </>
                  )}
                </div>

                <div className="sv-actions" style={{ display: "flex", gap: "10px" }}>
                  <button
                    type="button"
                    className="sv-stop-btn is-ghost"
                    style={{
                      padding: "8px 16px",
                      fontSize: "13px",
                      fontWeight: 700,
                      background: "rgba(56, 189, 248, 0.12)",
                      border: "1px solid var(--sv-accent)",
                      color: "var(--sv-accent)",
                      borderRadius: "6px",
                      cursor: "pointer",
                      display: "flex",
                      alignItems: "center",
                      gap: "6px",
                    }}
                    disabled={advisorLoading}
                    onClick={() => {
                      setActiveTab("remediation");
                      onConsultMentor(selectedFinding);
                    }}
                  >
                    {advisorLoading ? "Querying Local AI..." : "⚡ Consult AI Mentor"}
                  </button>

                  <button
                    type="button"
                    className={`sv-retest ${retestStateClass}`}
                    disabled={isRetesting}
                    onClick={handleRetest}
                  >
                    {retestButtonText}
                  </button>
                </div>
              </>
            ) : (
              <div className="sv-empty">Select a finding above to inspect details and remediation.</div>
            )}
          </section>
        </main>
      </div>
    </div>
  );
}
