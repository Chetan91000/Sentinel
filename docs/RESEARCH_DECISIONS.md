# Sentinel Research Decisions

## Purpose

This document records how Sentinel research informed the design, where the evidence is strong, and where an engineering decision remains an assumption. The named research directions in the architect notes are not treated as proof of production reliability or direct transfer to Electron.

## Evidence Categories

- Published finding: directly reported by a source.
- Interpretation: reasonable reading of the source.
- Engineering inference: practical implication for Sentinel.
- Product decision: chosen behavior or scope.
- Assumption: unresolved claim requiring validation.

## Decisions

### Deterministic execution and verification

Decision: Security-critical browser actions, observations, and finding verification remain deterministic.

Research basis: Interactive agent research emphasizes grounding in real tool feedback; autonomous-agent results do not establish that model output is reliable evidence.

Engineering reasoning: A model can misread target content, lose state, or hallucinate a conclusion. Deterministic evidence and explicit predicates are auditable and testable.

Product reasoning: Users need to inspect why a result was reported and reproduce it.

Tradeoff: Sentinel has less autonomy and narrower initial coverage.

### Explicit application state

Decision: Browser, authentication, API, and workflow state are represented explicitly where a workflow depends on them.

Research basis: State-aware security testing and multi-step interaction are recurring themes in the cited work, including NAUTILUS and browser-oriented agent research.

Engineering reasoning: URL or model context alone cannot establish application state. State snapshots and drift checks make failures visible.

Product reasoning: Users need to know whether a test ran in the intended context.

Tradeoff: State capture is difficult and replay may often be non-comparable.

### Vulnerability-specific checks

Decision: Use bounded checks with per-check evidence and verification contracts before creating a dynamic vulnerability router.

Research basis: AWE and related work motivate specialized workflows, but do not prove that broad routing improves Sentinel's accuracy.

Engineering reasoning: One complete deterministic check is easier to test than a general router selecting many uncertain modules.

Product reasoning: A smaller number of trustworthy results is more useful than a large noisy queue.

Tradeoff: Slower coverage growth and more explicit check design.

### Composable TestIntent model

Decision: Store reusable test intent and composable primitives rather than a large library of pre-written test cases.

Research basis: NAUTILUS demonstrates the importance of relationships and multi-operation sequences for API vulnerabilities; AWE supports vulnerability-specific pipelines. PentestGPT and AutoPT indicate that decomposition and explicit workflow control are needed when long-horizon execution becomes unreliable.

Engineering reasoning: A TestIntent can express target, context, state, action, mutation, observation, assertion, and evidence requirements without granting the model arbitrary execution. The composer and policy validator produce a bounded test instance.

Product reasoning: The same user-facing investigation concept can adapt to different routes, resources, and identities while preserving a consistent evidence view.

Tradeoff: The primitive contracts are harder to define initially and do not eliminate the need for vulnerability-specific verification logic.

Status: Strong engineering direction, not a claim that the model will represent every vulnerability class without extension.

### State-machine-controlled orchestration

Decision: Make assessment state and scheduling explicit; do not rely on model context to maintain the scenario.

Research basis: PentestGPT reports context and scenario-management limitations; AutoPT places the model inside a penetration-testing state machine; EnIGMA highlights failures when agents describe observations without real tool interaction.

Engineering reasoning: Explicit transitions make invalid actions, missing state, stalled workflows, and inconclusive results testable.

Product reasoning: Users can see what Sentinel is doing and why a test is waiting, blocked, or incomplete.

Tradeoff: More orchestration code and state modeling, with a risk of ceremony if the state machine grows beyond real workflow needs.

### Playwright as a deterministic adapter

Decision: Evaluate Playwright for isolated fixture workflows, deterministic browser automation, tracing, and observation capture. Retain Electron as the visible product shell and do not add FastAPI solely to host Playwright.

Research basis: Playwright provides practical browser-context, network, console, storage, and tracing capabilities. This supports the research requirement that agents and tests ground claims in real tool observations.

Engineering reasoning: Playwright may provide a more testable automation boundary than relying only on the embedded view, but supporting both browser paths creates synchronization and capability differences that must be measured.

Product reasoning: The user needs a visible browser workflow, while fixture automation improves reproducibility and evaluation.

Tradeoff: Two browser execution paths can diverge. The MVP should select one path per workflow and label the execution context.

### Structured memory and reflection

Decision: Preserve structured run history and evidence references, but defer open-ended conversational memory and reflection loops.

Research basis: Reflexion suggests potential gains from feedback and reflection, while incorrect feedback can reinforce incorrect assumptions.

Engineering reasoning: Evidence-backed history is inspectable; unrestricted memory can carry stale or false conclusions into later runs.

Product reasoning: Users need a clear audit trail rather than hidden model memory.

Tradeoff: Less adaptive behavior.

### Local AI

Decision: AI is optional and advisory. The MVP must work without it.

Research basis: Agent papers show useful reasoning in controlled settings, but local-model latency, tool-call reliability, prompt injection resistance, and transfer to Electron remain unresolved.

Engineering reasoning: Security workflows must not depend on model availability or correctness.

Product reasoning: Local AI can later improve explanation and prioritization without controlling findings.

Tradeoff: Less automation and personalization initially.

### RAG and vector search

Decision: Defer full RAG frameworks and dedicated vector databases. Start with curated guidance and metadata or full-text retrieval if needed.

Research basis: Retrieval may improve context, but the repository lacks an evaluated corpus, retrieval benchmark, or evidence that semantic search improves target verification.

Engineering reasoning: RAG adds ingestion, provenance, prompt-injection, packaging, and maintenance costs.

Product reasoning: A small cited guidance set is easier to trust and understand.

Tradeoff: Less flexible knowledge discovery.

### Local modular architecture

Decision: Keep the MVP in one local modular process with typed IPC and clear module boundaries.

Research basis: The cited work does not justify distributed infrastructure for a single-user desktop tool.

Engineering reasoning: Services, queues, and databases add failure and deployment surfaces before the core evidence loop is proven.

Product reasoning: Lower installation friction and better privacy fit the local product promise.

Tradeoff: Less isolation and parallelism.

## Claims Requiring Verification

The following must be tested rather than assumed:

- Browser instrumentation can capture the required events reliably in Electron.
- State snapshots are sufficient to detect replay drift.
- Specialized checks reduce false positives enough to justify maintenance cost.
- Local models improve user comprehension without unacceptable latency or data exposure.
- RAG improves remediation usefulness compared with curated guidance.
- Reflection improves outcomes rather than reinforcing bad evidence.
- Research results transfer across models, applications, vulnerability classes, and local execution.
- A composable TestIntent model reduces duplication without hiding important vulnerability-specific semantics.
- Playwright-backed execution provides better reproducibility than the current Electron-only path for the selected vertical slice.

## Research Questions

1. Which Electron instrumentation layer provides stable request, response, header, cookie, console, and navigation observations?
2. What minimum evidence verifies the first selected check?
3. How often are replays non-comparable because of server-side state?
4. What false-positive and false-negative rates result from the first checks?
5. What model size and runtime provide useful advisory output on supported hardware?
6. Does AI reduce user investigation time without reducing evidence comprehension?
7. Does full-text retrieval perform adequately before embeddings are justified?
8. Which security workflows benefit from active tests without unacceptable side effects?
9. Can a TestIntent be validated and composed safely for reflected XSS and authorization workflows?
10. Do Electron and Playwright produce equivalent evidence for the same supported workflow?
11. Does AI-assisted TestIntent selection improve coverage or test efficiency over deterministic selection?

## Decision Rule

A new dependency, agent, pipeline, model capability, or infrastructure layer is justified only when a measured experiment shows improvement in verified security outcomes, evidence quality, reproducibility, user comprehension, or maintainability that outweighs its added complexity.
