import { useEffect, useMemo, useRef, useState } from "react";

type Finding = {
  id: string;
  severity: string;
  title: string;
  source: string;
  evidence: string;
  description: string;
};
type Event = {
  id: string;
  kind: string;
  label: string;
  detail: string;
  time: string;
};

const findings: Finding[] = [
  {
    id: "FND-001",
    severity: "Medium",
    title: "Content-Security-Policy header is missing",
    source: "Passive",
    evidence: "EV-004",
    description:
      "The document response did not include a Content-Security-Policy header. This is an observed configuration weakness, not proof of exploitability.",
  },
  {
    id: "FND-002",
    severity: "Low",
    title: "Session cookie lacks SameSite attribute",
    source: "Passive",
    evidence: "EV-005",
    description:
      "A cookie was observed without an explicit SameSite attribute. Review the cookie configuration and choose the strictest compatible behavior.",
  },
  {
    id: "FND-003",
    severity: "Info",
    title: "Console reported a CSP violation",
    source: "Browser",
    evidence: "EV-006",
    description:
      "The browser recorded a policy message. Inspect the cited resource before deciding whether the policy needs adjustment.",
  },
];

const initialEvents: Event[] = [
  {
    id: "EV-001",
    kind: "NAV",
    label: "Evidence capture ready",
    detail: "Network events will appear here while recording",
    time: "09:41:03",
  },
  {
    id: "EV-002",
    kind: "SYS",
    label: "Passive checks loaded",
    detail: "6 safe checks are waiting for browser evidence",
    time: "09:41:04",
  },
];

function App() {
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [consent, setConsent] = useState(false);
  const [session, setSession] = useState(false);
  const [recording, setRecording] = useState(false);
  const [selected, setSelected] = useState<Finding | null>(null);
  const [notice, setNotice] = useState("");
  const [events, setEvents] = useState(initialEvents);
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

  function createSession() {
    if (!name.trim()) return setNotice("Add a name for this assessment.");
    if (!validUrl) return setNotice("Enter a complete HTTP or HTTPS URL.");
    if (!consent)
      return setNotice(
        "Confirm that you own or are authorized to test this application.",
      );
    setSession(true);
    setNotice("Session created. The browser is ready.");
    setEvents([
      {
        id: "EV-003",
        kind: "LOCK",
        label: "Origin allowlist locked",
        detail: origin,
        time: now(),
      },
      ...initialEvents,
    ]);
    void window.sentinelDesktop?.configureBrowser(origin).then((result) => {
      if (!result.ok)
        setNotice(
          result.error ?? "The native browser could not be configured.",
        );
      else void window.sentinelDesktop?.navigateBrowser(url);
    });
  }
  function toggleRecording() {
    const next = !recording;
    setRecording(next);
    setNotice(
      next
        ? "Recording browser evidence."
        : "Recording stopped. Passive checks are ready.",
    );
    if (next)
      setEvents((current) => [
        {
          id: "EV-004",
          kind: "REC",
          label: "Browser recording started",
          detail: origin,
          time: now(),
        },
        ...current,
      ]);
  }
  function exportSession() {
    const data = {
      session: { name, origin, exportedAt: new Date().toISOString() },
      evidence: events,
      findings: findings.map(({ description: _, ...finding }) => finding),
    };
    const link = document.createElement("a");
    link.href = URL.createObjectURL(
      new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }),
    );
    link.download = "sentinel-session.json";
    link.click();
    URL.revokeObjectURL(link.href);
    setNotice("Redacted session JSON exported.");
  }

  useEffect(() => {
    if (!session || !browserStage.current || !window.sentinelDesktop) return;
    const updateBounds = () => {
      if (!browserStage.current) return;
      const rect = browserStage.current.getBoundingClientRect();
      window.sentinelDesktop?.setBrowserBounds({
        x: rect.left,
        y: rect.top,
        width: rect.width,
        height: rect.height,
      });
    };
    updateBounds();
    window.addEventListener("resize", updateBounds);
    const cleanup = window.sentinelDesktop.onBrowserNavigated(
      ({ url: navigatedUrl }) =>
        setNotice(`Browser navigated to ${navigatedUrl}`),
    );
    return () => {
      window.removeEventListener("resize", updateBounds);
      cleanup();
    };
  }, [session]);

  if (!session)
    return (
      <main className="onboarding">
        <section className="onboarding-card">
          <div className="brand">S</div>
          <p className="eyebrow">LOCAL APPLICATION SECURITY LAB</p>
          <h1>Start an evidence-first session.</h1>
          <p className="intro">
            Sentinel observes an application you control, records what the
            browser sees, and highlights safe configuration checks.
          </p>
          <div className="local-status">
            <i /> Local workspace ready{" "}
            <span>Ollama is optional in this milestone</span>
          </div>
          <label>
            Assessment name
            <input
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="e.g. Checkout review"
            />
          </label>
          <label>
            Authorized base URL
            <input
              className="mono"
              value={url}
              onChange={(event) => setUrl(event.target.value)}
              placeholder="https://app.example.test"
            />
          </label>
          <div className="allowlist">
            <b>LOCKED ORIGIN</b>
            <span>{origin || "Enter a URL to lock one origin"}</span>
          </div>
          <label className="consent">
            <input
              type="checkbox"
              checked={consent}
              onChange={(event) => setConsent(event.target.checked)}
            />{" "}
            I own this application or have explicit permission to test it.
          </label>
          <button
            className="primary full"
            disabled={!validUrl || !name.trim() || !consent}
            onClick={createSession}
          >
            Create session <b>→</b>
          </button>
          {notice && <p className="notice">{notice}</p>}
          <p className="fine">
            No payloads. No brute force. No navigation outside the approved
            origin.
          </p>
        </section>
      </main>
    );

  return (
    <div className="shell">
      <aside className="rail">
        <div className="brand">S</div>
        {[
          ["▦", "Sessions"],
          ["●", "Record"],
          ["△", "Findings"],
          ["≡", "Evidence"],
          ["↗", "Reports"],
          ["⚙", "Settings"],
        ].map(([icon, label], index) => (
          <button
            className={index === 0 ? "rail-item active" : "rail-item"}
            key={label}
          >
            <span>{icon}</span>
            <small>{label}</small>
            {label === "Findings" && <b>3</b>}
          </button>
        ))}
        <div className="rail-local">
          <i />
          Local
        </div>
      </aside>
      <header className="topbar">
        <div>
          <p className="eyebrow">SESSION / {name.toUpperCase()}</p>
          <h2>Evidence workspace</h2>
        </div>
        <div className="top-actions">
          <span className="ready">
            <i /> Ollama ready
          </span>
          <button className="secondary" onClick={exportSession}>
            Export JSON ↗
          </button>
        </div>
      </header>
      <main className="workspace">
        <section className="analysis">
          <div className="heading">
            <div>
              <p className="eyebrow">
                {recording ? "LIVE CAPTURE" : "ASSESSMENT OVERVIEW"}
              </p>
              <h3>
                {recording ? "Recording browser activity" : "Session overview"}
              </h3>
            </div>
            <span className={recording ? "pill recording" : "pill"}>
              <i />
              {recording ? "Recording" : "Ready"}
            </span>
          </div>
          <div className="stats">
            <div>
              <small>FINDINGS</small>
              <strong>3</strong>
              <span>passive observations</span>
            </div>
            <div>
              <small>EVIDENCE</small>
              <strong>{events.length}</strong>
              <span>events captured</span>
            </div>
            <div>
              <small>ORIGIN</small>
              <strong className="hostname">{new URL(origin).hostname}</strong>
              <span>allowlist locked</span>
            </div>
          </div>
          <div className="heading findings-title">
            <div>
              <p className="eyebrow">PASSIVE CHECKS</p>
              <h3>Findings</h3>
            </div>
            <span className="count">3 total</span>
          </div>
          <div className="finding-list">
            {findings.map((finding) => (
              <button
                className={
                  selected?.id === finding.id ? "finding selected" : "finding"
                }
                key={finding.id}
                onClick={() => setSelected(finding)}
              >
                <em className={`severity ${finding.severity.toLowerCase()}`}>
                  {finding.severity}
                </em>
                <span>
                  <strong>{finding.title}</strong>
                  <small>
                    {finding.source} · {finding.evidence}
                  </small>
                </span>
                <b>›</b>
              </button>
            ))}
          </div>
        </section>
        <section className="browser">
          <div className="browser-bar">
            <button>‹</button>
            <button>›</button>
            <button>↻</button>
            <div className="address">
              <span>LOCK</span>
              <code>{origin}</code>
              <b>Allowlisted</b>
            </div>
            <button
              className={recording ? "stop" : "record"}
              onClick={toggleRecording}
            >
              {recording ? "Stop" : "Record"}
            </button>
          </div>
          <div className="browser-empty" ref={browserStage}>
            <div className="browser-card">
              <div className="site-icon">{name.slice(0, 1).toUpperCase()}</div>
              <p className="eyebrow">EMBEDDED CHROMIUM PANE</p>
              <h3>{name}</h3>
              <p>
                The controlled browser surface will appear here. It stays
                visually separate from Sentinel analysis.
              </p>
              <button className="primary" onClick={toggleRecording}>
                {recording ? "Stop recording" : "Start recording"}
              </button>
              <button
                className="secondary"
                onClick={() =>
                  setNotice(
                    "Inert canary support comes after the evidence foundation.",
                  )
                }
              >
                Inject inert canary
              </button>
            </div>
          </div>
          <div className="dock">
            <div className="dock-head">
              <div>
                <p className="eyebrow">EVIDENCE STREAM</p>
                <strong>Captured events</strong>
              </div>
              <small>{events.length} events</small>
            </div>
            <div className="tabs">
              <b>Timeline</b>
              <span>Network</span>
              <span>Cookies</span>
              <span>Console</span>
              <span>Screenshots</span>
            </div>
            {events.slice(0, 3).map((event) => (
              <div className="event" key={event.id}>
                <i>{event.kind.slice(0, 1)}</i>
                <span>
                  <strong>{event.label}</strong>
                  <small>{event.detail}</small>
                </span>
                <code>{event.id}</code>
                <time>{event.time}</time>
              </div>
            ))}
          </div>
        </section>
      </main>
      {selected && (
        <aside className="inspector">
          <button className="close" onClick={() => setSelected(null)}>
            ×
          </button>
          <p className="eyebrow">FINDING DETAIL</p>
          <em className={`severity ${selected.severity.toLowerCase()}`}>
            {selected.severity}
          </em>
          <h3>{selected.title}</h3>
          <div className="tags">
            <span>A05:2021</span>
            <span>{selected.source}</span>
            <span>Observed</span>
          </div>
          <div className="detail">
            <p className="eyebrow">WHY THIS MATTERS</p>
            <p>{selected.description}</p>
          </div>
          <div className="detail">
            <p className="eyebrow">EVIDENCE CITATION</p>
            <button
              className="evidence-link"
              onClick={() =>
                setNotice(`Focused ${selected.evidence} in the timeline.`)
              }
            >
              ↗ {selected.evidence}
              <small>Open captured event</small>
            </button>
          </div>
          <div className="remediation">
            <p className="eyebrow">REMEDIATION</p>
            <strong>Review the response configuration</strong>
            <p>
              Add the appropriate header or cookie attribute, then repeat this
              authorized session to verify the change.
            </p>
          </div>
        </aside>
      )}
      {notice && (
        <button className="toast" onClick={() => setNotice("")}>
          {notice}
          <b>×</b>
        </button>
      )}
    </div>
  );
}

function now() {
  return new Date().toLocaleTimeString([], { hour12: false });
}
export default App;
