# Sentinel Playbooks

## Playbook 01: Hardened Isolation & Observation Telemetry
- **Goal**: Run target URLs in an ephemeral, memory-only Chromium partition.
- **Rules**:
  - `session.fromPartition('in-memory-lab', { cache: false })`
  - Deny all system permission requests (geolocation, camera, microphone, notifications).
  - Deny popup creation (`setWindowOpenHandler` -> `deny`).
  - Block out-of-scope navigation at `will-navigate` boundary.
  - Intercept CDP `Network`, `Runtime`, `Page` events and normalize into redacted `EvidenceRecord`s.

## Playbook 02: Deterministic Passive Security Rules
- **Goal**: Detect configuration weaknesses with zero false positives without generating exploits.
- **Rules**:
  - **CSP**: Flag missing `Content-Security-Policy`.
  - **Cookies**: Flag missing `HttpOnly`, `Secure` (over HTTPS), or `SameSite`.
  - **Transport**: Flag missing `Strict-Transport-Security` and mixed content.
  - **CORS**: Flag `Access-Control-Allow-Origin: *` when credentials are enabled.
  - **MIME**: Flag missing `X-Content-Type-Options: nosniff`.

## Playbook 03: Inert Canary Output Encoding Verification
- **Goal**: Prove reflection and output encoding failures on owned origins safely.
- **Rules**:
  - Token format: `__sentinel_canary=<uuid>`.
  - Inject into URL query params and observed form inputs.
  - Read rendered DOM via CDP; if token appears unescaped in HTML context or script tag, record verified finding citing request/response evidence IDs.
  - No active script payloads or execution strings.

## Playbook 04: Scanner Report Ingestion (ZAP / Nuclei)
- **Goal**: Ingest user-run SARIF or ZAP JSON reports without running attack tools inside Sentinel.
- **Rules**:
  - Parse rule IDs, CWEs, URIs, and risk levels.
  - Correlate finding URIs with the live session evidence timeline.
  - Attach evidence reference IDs for downstream mentor advising.

## Playbook 05: Grounded Local AI Advisor & Remediation
- **Goal**: Provide AppSec mentor explanations and framework-specific defensive fixes.
- **Rules**:
  - Connect to local Ollama (`http://127.0.0.1:11434`).
  - Quarantine untrusted target DOM/headers inside strict XML tags.
  - Require structured JSON output containing `cited_evidence_ids`.
  - Flag any output missing matching evidence IDs as `Unverified / Ungrounded`.

## Playbook 06: Deterministic Replay & Remediation Verification
- **Goal**: Re-execute assessment after code fix to prove remediation status.
- **Rules**:
  - Re-run target route under identical conditions.
  - Evaluate against baseline evidence.
  - Output: `Fixed` (weakness absent), `StillPresent` (weakness still observed), or `NotComparable` (prerequisites/status drifted).
