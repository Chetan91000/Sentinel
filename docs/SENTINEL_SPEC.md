# Sentinel Specification

Status: Agreed design specification

## Purpose

Sentinel is a local, evidence-first browser security laboratory for applications the user owns or is authorized to test. It helps a user observe an application, investigate bounded security signals, verify findings, and replay comparable checks after remediation.

Sentinel is not an autonomous pentesting agent, a generic chatbot, or a broad vulnerability scanner.

## Core Principles

- Deterministic observations and verification are the source of truth for security findings.
- The LLM is advisory only: planning, prioritization, explanation, and remediation guidance.
- The approved origin and test scope are explicit and enforced at the desktop boundary.
- A discovery signal is not a confirmed vulnerability.
- Evidence is provenance-linked, redacted, append-only, and inspectable.
- Active or state-changing tests require explicit user approval.
- Replay reports non-comparable results when application state or environment assumptions differ.
- The MVP remains local, modular, and in-process.
- The security engine is composable: it stores test intent and primitives rather than thousands of fixed test cases.

## Product Journey

Assessment -> Discovery -> Investigation -> Verification -> Evidence -> Remediation -> Re-test -> Report

## System Boundaries

The system contains these logical components:

1. React user interface: assessment setup, browser status, evidence, findings, replay, and reports.
2. Validated Electron IPC: the only renderer-to-main command boundary.
3. Assessment controller: lifecycle, authorization state, workflow coordination, cancellation, and failure recovery.
4. Assessment engine: state machine, scheduler, and workflow orchestration.
5. Security engine: composable test primitives, TestIntent validation, strategies, and verifiers.
6. Deterministic tool layer: visible browser control, Playwright or equivalent automation, HTTP actions, parsers, and instrumentation.
7. Observation normalizer: converts tool observations into typed events.
8. Evidence core: persists redacted observations and immutable metadata.
9. Replay comparator: repeats comparable checks and compares normalized observations.
10. Optional local AI advisor: consumes redacted evidence and cannot execute tools or change finding status.

These are modules in the MVP, not distributed services.

## Security Workflow

Every security workflow defines:

- Preconditions and authorization assumptions
- Required browser, application, and authentication state
- Discovery signals
- Ordered test actions and stop conditions
- Tools and permission boundaries
- Required observations
- Evidence and redaction requirements
- Deterministic verification criteria
- False-positive conditions
- Failure and cleanup behavior
- Replay inputs and comparability rules

The workflow is:

1. Lock the approved origin.
2. Discover targets and application state.
3. Form or receive a bounded TestIntent.
4. Validate the intent against scope, policy, and required state.
5. Compose a concrete test from strategy, target, context, state, mutation, and verification.
6. Capture a baseline and execute the bounded test.
7. Capture observations with correlation and state references.
8. Apply the verifier.
9. Classify the result as confirmed, rejected, inconclusive, or manual review.
10. Preserve evidence and limitations.
11. Replay only when required inputs and state assumptions are available.

## State Outcomes

The product must distinguish at least:

- Setup
- Scope locked
- Recording
- Signal detected
- Test review
- Testing
- Evidence captured
- Verifying
- Confirmed
- Rejected
- Inconclusive
- Manual review
- Replay ready
- Retesting
- Fixed
- Still present
- Not comparable
- Cancelled
- Failed

The LLM cannot directly cause a transition to Confirmed, bypass scope, or execute an unrestricted action.

## Composable Test Model

The security engine is built from these primitives:

- Target
- Context
- State
- Action
- Observation
- Mutation
- Assertion
- Evidence

A TestIntent describes what is worth investigating without prescribing arbitrary execution. It contains a vulnerability class, target, required identities or context, state requirements, permitted mutation, and verification intent. Policy validation and the deterministic test composer convert it into a bounded test instance.

## Evidence Contract

Each evidence record includes, where applicable:

- Evidence ID
- Assessment and workflow IDs
- Timestamp
- Approved origin and scope
- Event type and source layer
- Correlation ID
- State snapshot reference
- Baseline or test classification
- Redaction status
- Integrity hash
- Artifact reference
- Collection limitations

Evidence must be stored separately from explanations. Findings reference evidence IDs. Sensitive request bodies, cookies, tokens, and credentials are not captured or exported by default.

## MVP Requirement

The MVP must complete one end-to-end deterministic workflow, preferably a reflected-XSS fixture or another bounded check for which browser observation and verification are reliable:

1. Lock an authorized origin.
2. Capture one real browser observation.
3. Persist a redacted, provenance-linked event.
4. Compose one deterministic test from a fixed TestIntent and primitive workflow.
5. Verify it with an explicit predicate.
6. Display the evidence and limitations.
7. Repeat the check.
8. Compare the results.
9. Export a truthful report.

The MVP must work with AI disabled.

If reflected XSS requires instrumentation that cannot be made reliable in the supported browser path, use a passive header or cookie check as the first vertical slice. The choice must be made by evidence, not assumed feature breadth.

## Explicit Non-Goals

The MVP must not include:

- Autonomous multi-agent pentesting
- LLM-confirmed findings
- Broad exploit generation
- Brute force or indiscriminate scanning
- Cloud AI by default
- A dedicated vector database
- A full RAG framework
- PostgreSQL, Redis, Kafka, or Kubernetes
- Generic chatbot-first interaction
- Unrestricted long-term memory
- Remote telemetry by default
- Full attack-surface graphing before evidence capture works
- Remediation claims without re-testing

## Acceptance Criteria

- Every displayed finding references captured evidence.
- No static target finding is shown without a matching observation.
- Renderer input is revalidated in the main process.
- Scope violations are blocked or visibly marked unsupported.
- Active tests require explicit approval.
- Verification distinguishes confirmed, rejected, inconclusive, and manual review.
- Replay reports non-comparable when state assumptions differ.
- Secrets are excluded from logs and exports by default.
- A user can complete the MVP workflow without a local model.
- The first workflow has fixture-based measurements for false positives, false negatives, latency, and replay fidelity.
