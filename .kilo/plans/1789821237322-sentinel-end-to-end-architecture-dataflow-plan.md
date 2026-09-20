# Sentinel: End-to-End Architecture, Data Flow, Security & Implementation Plan

## 1. System Goal & Core Philosophy
Sentinel is an evidence-first, local browser security laboratory for web applications the user is authorized to test. It rejects the "autonomous pentest agent / payload factory" model in favor of verifiable AppSec:
1. **Hardened Browser Isolation**: Ephemeral session partition preventing risk to local Chrome profiles, passwords, or machine credentials.
2. **Deterministic Telemetry Interception**: Zero-drift network and DOM capture via Electron `WebContentsView` and CDP.
3. **Immutable Evidence Store**: SHA-256 hashed, append-only JSONL record store with automated redaction of sensitive credentials/tokens.
4. **Deterministic Rule, Canary & Ingestion Engine**:
   - Passive header/cookie/CORS hygiene checks.
   - Non-destructive inert reflection canaries (`sentinel-canary-<uuid>`) proving output encoding bugs without exploit payloads.
   - User-controlled scanner ingestion (ZAP / Nuclei SARIF/JSON) correlated against session timelines.
5. **Grounded Local AI Advisor**: Local Ollama model generating framework-specific remediation patches and explanations citing exact `evidence_id`s, isolated from prompt-injection risks.
6. **Replay & Verification**: Deterministic comparison of baseline vs post-remediation observations (`Fixed`, `StillPresent`, `NotComparable`).

---

## 2. Architectural Decision: Electron vs. Tauri

| Criterion | Electron (`electron-vite` + React) | Tauri (Rust + WebView2 / WRY) | Decision Rationale |
|---|---|---|---|
| **Browser View & CDP Control** | Native `WebContentsView` + direct Chrome DevTools Protocol (`webContents.debugger`) | WebView2 lacks cross-platform CDP parity; requires launching external Playwright/Chromium | **Electron Wins**: Allows embedding the live lab browser and capturing full network/DOM events in-process without multi-process divergence. |
| **Runtime & Language Cohesion** | Single TypeScript stack across UI, IPC, telemetry, normalizer, and Ollama HTTP client | Mixed Rust backend + JS frontend + separate browser process | **Electron Wins**: Eliminates FFI serialization overhead and speeds development of complex security pipelines. |
| **Isolation & Security Boundary** | Ephemeral partitioned session (`session.fromPartition('in-memory-lab')`), `sandbox: true`, disabled Node integration | OS webview isolation | **Electron Wins with Hardening**: Ephemeral partition guarantees cookies/cache are discarded on close with zero host Chrome leakage. |
| **Footprint & Memory** | Higher binary size (~85MB) and RAM consumption | Lower binary size (~15MB) | Acceptable tradeoff for a dedicated desktop developer tool requiring deep Chromium instrumentation. |

---

## 3. Process & Network Architecture

```
+-----------------------------------------------------------------------------------------------------------------+
| USER MACHINE (Windows / OS)                                                                                     |
|                                                                                                                 |
|  +-----------------------------------------------------------------------------------------------------------+  |
|  | Electron Host (Main Process - Node.js privileged)                                                         |  |
|  |                                                                                                           |  |
|  |  +---------------------------+       Typed IPC Channel        +----------------------------------------+  |  |
|  |  | React UI Renderer         | <============================> | Electron IPC Handler                   |  |  |
|  |  | (Sandboxed, No Node,      |                                | - origin validation                    |  |  |
|  |  |  Context Isolated)        |                                | - scope lock                           |  |  |
|  |  +---------------------------+                                +----------------------------------------+  |  |
|  |                                                                                   |                       |  |
|  |                                                                                   v                       |  |
|  |                                                                 +--------------------------------------+  |  |
|  |                                                                 | Assessment State Machine             |  |  |
|  |                                                                 | & Controller                         |  |  |
|  |                                                                 +--------------------------------------+  |  |
|  |                                                                                   |                       |  |
|  |                                +--------------------------------------------------+                       |  |
|  |                                |                                                  |                       |  |
|  |                                v                                                  v                       |  |
|  |  +-------------------------------------------------------------+  +------------------------------------+  |  |
|  |  | Ephemeral Partitioned Session:                              |  | Evidence, Rule & Ingest Engine:    |  |  |
|  |  | `session.fromPartition('in-memory-lab', { cache: false })`  |  |                                    |  |  |
|  |  |   - Blocked: file://, native downloads, popups, permissions |  | 1. Redaction Pipeline (regex masks)|  |  |
|  |  |                                                             |  | 2. Append-Only Evidence Store      |  |  |
|  |  |  [ WebContentsView (Controlled Browser Viewport) ]          |  |    (SHA-256 hashed records)        |  |  |
|  |  |             | (Outbound HTTP/S)                             |  | 3. Deterministic Rules (CSP/Cookies|  |  |
|  |  |             v                                               |  | 4. Inert Canary Reflection Engine  |  |  |
|  |  |      Target Web App (Locked Origin Only)                    |  | 5. Scanner Ingest (SARIF / JSON)   |  |  |
|  |  |             |                                               |  | 6. Replay Comparator (Diff state)  |  |  |
|  |  |             v (Inbound Responses / DOM Events)              |  +------------------------------------+  |  |
|  |  |  [ CDP Network / Console / WebRequest Listeners ]           |                  |                       |  |
|  |  +-------------------------------------------------------------+                  |                       |  |
|  |                                |                                                  |                       |  |
|  |                                +-----------------> Telemetry Stream --------------+                       |  |
|  |                                                                                   |                       |  |
|  |                                                                                   v                       |  |
|  |                                                                   +------------------------------------+  |  |
|  |                                                                   | Local AI Advisor (Ollama Bridge)   |  |  |
|  |                                                                   | - http://127.0.0.1:11434           |  |  |
|  |                                                                   | - XML Quarantined Prompt Template  |  |  |
|  |                                                                   | - Evidence Citation Enforcer       |  |  |
|  |                                                                   +------------------------------------+  |  |
|  +-----------------------------------------------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------------------------------------------+
```

---

## 4. End-to-End Data Flow

### Step 1: Session Initialization & Scope Locking
1. User provides Target URL (e.g. `http://localhost:3000`), Assessment Name, and Mode (`Inspect` or `Own-App`).
2. Renderer executes validation (`new URL(url)`) and sends IPC `browser:configure`:
   ```typescript
   interface ConfigurePayload {
     origin: string;
     mode: "inspect" | "own-app";
     consent: boolean;
   }
   ```
3. Main process verifies protocol (`http:`, `https:`), stores `allowedOrigin`, and creates `WebContentsView` with `partition: 'in-memory-lab'`.
4. Main blocks external popups (`setWindowOpenHandler` returns `{ action: 'deny' }`) and external navigation (`will-navigate` blocks unlisted origins).

### Step 2: Traffic Capture & Observation Normalization
1. **Network Interception**:
   - `onBeforeRequest` & `onBeforeSendHeaders`: records method, URL, timestamp, resource type.
   - `onHeadersReceived` & `onCompleted`: records HTTP status code, response headers, content length.
2. **CDP Interception**:
   - `Page.enable`, `Network.enable`, `Runtime.enable`.
   - `Runtime.consoleAPICalled`: captures browser console warnings, errors, exceptions.
   - `DOM.getDocument` / `Page.lifecycleEvent`: tracks navigation state and DOM rendering completion.
3. **Redaction Filter**:
   - `Authorization`, `Proxy-Authorization`, `X-Api-Key` values -> `[REDACTED]`.
   - `Set-Cookie` / `Cookie` session values -> `name=REDACTED; attrs...`.
   - Query strings and JSON payloads matching `password|secret|token|apikey` -> masked.
4. **Evidence Store Record**:
   ```typescript
   interface EvidenceRecord {
     id: string; // EV-<timestamp>-<hash>
     timestamp: string;
     kind: "NAV" | "REQ" | "RES" | "COOKIE" | "CONSOLE" | "CANARY_REFLECT" | "SCANNER_ALERT";
     label: string;
     detail: string;
     source: "browser" | "network" | "canary" | "scanner" | "system";
     hash: string; // SHA-256 of normalized payload
     meta?: Record<string, unknown>;
   }
   ```

### Step 3: Deterministic Rule, Canary & Scanner Ingestion
1. **Passive Rules (No payloads, instant evaluation)**:
   - **CSP Rule**: If `content-security-policy` header is missing in HTML response -> Medium finding.
   - **Cookie Rule**: For each `Set-Cookie`, if missing `SameSite`, `HttpOnly`, or `Secure` (over HTTPS) -> Low finding.
   - **HSTS Rule**: If HTTPS response lacks `Strict-Transport-Security` -> Low finding.
   - **MIME Sniffing**: If missing `X-Content-Type-Options: nosniff` -> Info finding.
   - **Clickjacking**: If missing `X-Frame-Options` or CSP `frame-ancestors` -> Low finding.
   - **CORS Rule**: If `Access-Control-Allow-Origin: *` is returned with `Access-Control-Allow-Credentials: true` -> Medium finding.
2. **Inert Reflection Canary (`Own-App` mode only)**:
   - Injects unique inert token: `__sentinel_canary=<uuid>` into query parameters or inputs.
   - Reads response DOM via CDP. If raw `<uuid>` is unencoded in HTML body or script blocks -> Confirmed Output Encoding finding with request/response evidence IDs.
3. **Scanner Report Ingestion (`Own-App` mode only)**:
   - Allows importing user-run ZAP JSON or Nuclei SARIF scan results.
   - Correlates imported alert URLs against the recorded evidence timeline and attaches `SCANNER_ALERT` evidence records.

### Step 4: Local AI Advisor (Ollama Remediation Engine)
1. Triggered on demand when user inspects a finding.
2. Backend constructs prompt with strict XML delimiters:
   ```markdown
   You are an AppSec review mentor. Analyze the following verified finding.
   
   <finding_metadata>
   Title: {{title}}
   Severity: {{severity}}
   CWE: {{cwe}}
   </finding_metadata>
   
   <quarantined_evidence>
   {{evidence_records_json}}
   </quarantined_evidence>
   
   Respond in strict JSON:
   {
     "explanation": "concise explanation referencing evidence IDs",
     "cited_evidence_ids": ["EV-..."],
     "framework_fixes": [
       { "framework": "Express.js", "code": "..." },
       { "framework": "Next.js", "code": "..." }
     ]
   }
   ```
3. Backend validates that `cited_evidence_ids` match stored records; if invalid or ungrounded, flags response with `Unverified / Ungrounded` badge.

### Step 5: Replay & Remediation Re-Testing
1. User modifies their application code and clicks **Re-test**.
2. Sentinel restarts recording, navigates to the exact recorded URL, and evaluates the same rule.
3. **Replay Comparator**:
   - Compares new observation against baseline evidence ID.
   - If the vulnerability signature is no longer observed -> Marks finding as **Fixed**.
   - If the issue persists -> Marks finding as **Still Present**.
   - If the route returns 404/500 or redirect changed -> Marks as **Not Comparable**.

---

## 5. Security & Isolation Controls

| Threat Vector | Sentinel Mitigation |
|---|---|
| Malicious / untrusted target page | `WebContentsView` runs with `sandbox: true`, `contextIsolation: true`, `nodeIntegration: false`, zero access to Electron APIs. |
| Host credential / cookie theft | Isolated session partition `session.fromPartition('in-memory-lab')` with no access to system Chrome profile. |
| Native file system access / drive-by downloads | Native download requests intercepted and cancelled; `file://` navigations blocked. |
| Prompt injection from target DOM | Target text quarantined inside XML tags with clear instruction hierarchy; Ollama never given execution tools. |
| Exploit weaponization | Product policy forbids generating or sending active exploit payloads; only uses passive telemetry and inert canaries. |

---

## 6. Codebase File Modifications & Creation Plan

### 1. `electron/main.cjs`
- Replace `session.defaultSession` with `session.fromPartition('in-memory-lab', { cache: false })`.
- Add `session.setPermissionRequestHandler((_wc, _perm, cb) => cb(false))` and `setWindowOpenHandler` denial.
- Attach CDP debugger via `browserView.webContents.debugger.attach('1.3')` for console and DOM events.
- Implement new IPC handlers: `canary:inject`, `scanner:import`, `advisor:query`, `replay:run`.

### 2. `electron/preload.cjs` & `src/desktop.d.ts`
- Expose new typed APIs on `window.sentinelDesktop`: `injectCanary`, `importScannerReport`, `queryAdvisor`, `runReplay`.

### 3. `src/engine/rules.ts`
- Implement pure deterministic functions: `evaluateHeaders(resHeaders)`, `evaluateCookies(cookies)`, `evaluateCors(headers)`.

### 4. `src/engine/canary.ts`
- Implement `generateCanary()`, `buildCanaryUrl(baseUrl, paramName, token)`, `detectReflection(domHtml, token)`.

### 5. `src/engine/ingest.ts`
- Implement SARIF v2.1.0 parser (`runs[].results[]`) and ZAP JSON parser (`site[].alerts[]`) into `EvidenceRecord[]`.

### 6. `src/advisor/ollama.ts`
- Implement client for `http://127.0.0.1:11434/api/generate` with prompt isolation and strict JSON schema parser.

### 7. `src/engine/replay.ts`
- Implement diff comparator taking baseline `EvidenceRecord` vs re-test `EvidenceRecord` and returning `Fixed | StillPresent | NotComparable`.

### 8. `src/App.tsx` & `src/styles.css`
- Update React UI with:
  - Mode Switcher (`Inspect` vs `Own-App`).
  - Inert Canary Trigger button on active route.
  - Scanner Report Import dialog.
  - Finding Detail Inspector with "Why this matters", "Evidence Citation", "Remediation Patch", and "Replay / Re-test" button.

---

## 7. Verification & Test Plan
- [ ] **Session Isolation Verification**: Confirm cookies set inside Sentinel do not exist in host Chrome profile and vice versa.
- [ ] **Scope Enforcer Test**: Trigger navigation to external URLs (e.g. `https://google.com`); verify navigation is prevented.
- [ ] **Passive Rule Verification**: Run test suite against mock headers with missing CSP/SameSite; verify findings generated with exact evidence IDs.
- [ ] **Inert Canary Test**: Inject canary into test query parameter; verify reflection detection without executable payload strings.
- [ ] **Scanner Ingest Test**: Import sample ZAP/Nuclei SARIF file; verify alerts correlate to matching route evidence records.
- [ ] **Redaction Verification**: Verify `Authorization: Bearer test` and `set-cookie` values are masked in `evidence.json`.
- [ ] **Replay Comparator Test**: Simulate pre-fix and post-fix runs; verify state accurately transitions from `StillPresent` to `Fixed`.
- [ ] **Typecheck & Build**: Run `npm run build` (`tsc -b && vite build`) to ensure 100% clean typecheck and bundling.
