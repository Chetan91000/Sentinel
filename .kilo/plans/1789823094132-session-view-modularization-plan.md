# Sentinel: SessionView Modularization & Integration Plan

## 1. Goal
Extract and modularize Sentinel's active workspace session into a standalone component (`src/components/SessionView.tsx` & `src/components/SessionView.css`). Connect the dummy `SessionView` template to Sentinel's live Electron telemetry stream, deterministic finding evaluation queue, local AI advisor, inert canary triggers, and replay re-test engine while preserving the embedded sandboxed Chromium viewport.

---

## 2. Architecture & Component Contract

```
┌────────────────────────────────────────────────────────────────────────┐
│ App.tsx (Root Controller & Sandbox Lifecycle Manager)                  │
├────────────────────────────────────────────────────────────────────────┤
│ - Onboarding / Scope Lock setup                                        │
│ - Ephemeral partition WebContentsView bounds management                │
│ - IPC Listeners (onEvidence, onBrowserNavigated, checkOllamaStatus)    │
│ - Global State (events, evidence, findings, recording, assessmentState)│
└───────────────────┬────────────────────────────────────────────────────┘
                    │
                    ▼ (passes live state & action callbacks)
┌────────────────────────────────────────────────────────────────────────┐
│ SessionView.tsx (Modularized Workspace View)                           │
├────────────────────────────────────────────────────────────────────────┤
│ Top Bar: Brand, Mode Switcher (Inspect / Own-App), Live Telemetry Pill │
├───────────────────────────────┬────────────────────────────────────────┤
│ Left Column:                  │ Right Main Area:                       │
│ - Live Network & Telemetry    │ - Embedded Chromium Viewport           │
│   Event Feed (Method, URL,    │ - Active Findings Queue (Severity,     │
│   Status, Timestamp, Kind)    │   CWE, OWASP Category, Title)          │
│ - Filter query search         │ - Detail Inspector with Tabs:          │
│                               │   • Tab 1: Why this matters (Impact)   │
│                               │   • Tab 2: Evidence Citation           │
│                               │   • Tab 3: Remediation Patch (Ollama)  │
│                               │   • Re-test / Replay Action Button     │
└───────────────────────────────┴────────────────────────────────────────┘
```

---

## 3. Implementation Steps

### Step 1: Create `src/components/SessionView.tsx`
- Define strong TypeScript `SessionViewProps` interface referencing `EvidenceRecord`, `Finding`, and `AdvisorResponse`.
- Map live telemetry events (`REQ`, `RES`, `COOKIE`, `CONSOLE`, `CANARY_REFLECT`, `SCANNER_ALERT`) into the event feed rows.
- Map analyzed findings queue with severity badges (`High`, `Medium`, `Low`, `Info`).
- Implement 3-tab Detail Inspector:
  1. **Why this matters**: Technical explanation of the weakness.
  2. **Evidence Citation**: Immutable evidence record details, ID, timestamp, and SHA-256 hash.
  3. **Remediation Patch**: Framework-specific patches (Express, Next.js, FastAPI, Django) from Ollama / deterministic fallback.
- Wire the **Re-test (Replay)** button to `handleReplayFinding` showing live retest states (`Running…`, `✔ Re-test Passed (Fixed)`, `✖ Still Failing`).
- Anchor the `browserStageRef` div container so the native Electron `WebContentsView` aligns accurately with the React UI layout.

### Step 2: Create `src/components/SessionView.css`
- Apply the `.sv-*` design system using Sentinel's dark/light design tokens (`--canvas`, `--panel`, `--border`, `--accent`, `--danger`, `--warning`, `--success`).
- Provide CSS grid layout for the Topbar, Event Feed sidebar, Chromium viewport, Findings queue, and Detail Inspector panel.
- Style method tags (`GET`, `POST`, `PUT`, `DELETE`), severity badges, status indicators, and tabs.

### Step 3: Update `src/App.tsx`
- Replace inline session rendering in `App.tsx` with `<SessionView {...props} />`.
- Retain the onboarding modal, modal dialogs (Inert Canary, Scanner Ingest), and Electron IPC event bindings in `App.tsx`.

### Step 4: Verification & Build
- Run `npx tsx tests/engine.test.ts` to verify core security rules, canaries, and replay comparator.
- Run `npm run build` (`tsc -b && vite build`) to ensure 100% clean compilation and zero type errors.

---

## 4. Verification Checklist
- [ ] `SessionView.tsx` compiles with zero TypeScript errors.
- [ ] Network events logged during recording update the live feed in real-time.
- [ ] Clicking an event or finding focuses the matching item and opens the Detail Inspector.
- [ ] Consulting AI Mentor queries Ollama and renders framework patches.
- [ ] Re-testing a finding triggers replay comparison and updates status badge.
- [ ] Native Electron browser viewport renders within the layout bounds.
