# Sentinel Product

## Product Promise

Sentinel helps an authorized user investigate a web application and produce security evidence they can inspect, reproduce, and challenge.

It is an evidence-first security laboratory, not a generic chatbot, autonomous hacker, or broad scanner.

## Target User

The primary user is a developer, application owner, or security learner assessing an application they own or are explicitly authorized to test. They need more context and reproducibility than a scanner report provides, but do not want opaque or uncontrolled automation.

## Core Problem

Scanners often produce noisy findings without application context. Autonomous agents may take opaque actions that are difficult to constrain or reproduce. Sentinel connects browser behavior, application state, deterministic checks, evidence, verification, remediation, and re-testing in one local workflow.

## User Journey

### 1. Assessment

The user enters an assessment name and authorized base URL, confirms the authorization assertion, and locks the scope. Sentinel continuously displays the approved origin and scope limitations.

### 2. Discovery

The user browses the application normally. Sentinel records supported navigations and browser observations and presents an activity timeline.

### 3. Investigation

Deterministic checks create unverified signals such as a missing security header or cookie attribute. Each signal links to its source observation and states what it does not prove.

### 4. Test Review

Before an active or state-changing check, Sentinel shows required state, planned actions, possible side effects, evidence to collect, and cancellation behavior. The user approves or declines.

### 5. Verification

Sentinel compares baseline and test evidence using a deterministic predicate. The result is confirmed, rejected, inconclusive, or manual review.

### 6. Remediation

The finding explains the observation, impact, limitations, evidence, and qualified remediation guidance. Generated text cannot change the verification status.

### 7. Re-test

The user starts a comparable replay after remediation. Sentinel reports fixed, still present, changed, or not comparable.

### 8. Report

The export includes assessment scope, evidence references, findings, verification status, limitations, and replay results. Sensitive values are redacted by policy.

## Major Screens

- Assessment setup and scope lock
- Evidence workspace with browser status and timeline
- Investigation queue of unverified signals
- Test review and approval
- Finding detail with baseline/test evidence
- Replay and re-test comparison
- Report and export

## Differentiation

Compared with a normal vulnerability scanner, Sentinel emphasizes browser context, state, evidence provenance, explicit verification, replay, remediation validation, local privacy, and human control.

Compared with an autonomous pentesting agent, Sentinel uses bounded workflows, deterministic execution, explicit approval, evidence-backed findings, and reproducibility. It does not optimize for maximum autonomy.

## Test Model

Sentinel should not expose a library of thousands of pre-written tests. The security engine represents a bounded **TestIntent** using reusable primitives:

- Target
- Context
- State
- Action
- Observation
- Mutation
- Assertion
- Evidence

For example, an authorization intent can express: authenticate as owner, create a resource, authenticate as another identity, access the resource, and assert that access is denied. The engine composes the concrete workflow only after scope and safety validation.

## MVP

The MVP is one complete deterministic workflow:

- Scope lock
- Real browser observation
- Redacted evidence event
- One composable TestIntent and deterministic check
- Explicit verifier
- Evidence-linked result
- Repeatable comparison
- Truthful export

The MVP works with AI disabled and does not show static findings that lack target evidence.

The preferred research vertical slice is reflected-XSS detection against an intentionally vulnerable local fixture because it exercises input discovery, browser interaction, DOM or browser verification, evidence, and replay. If instrumentation cannot be made reliable, the MVP should use a passive header or cookie workflow instead.

## Later Features

After the deterministic slice is measured:

- Additional passive checks
- State snapshots
- One bounded active test
- Authentication-aware user-controlled workflows
- Limited replay
- Local AI explanations using redacted evidence
- Curated local security guidance
- Fixture vulnerable applications
- Specialized vulnerability pipelines
- Composable multi-step authorization and API workflows
- API and multi-step workflows
- Local embeddings or vector retrieval only if evaluated
- Remediation tracking and richer reporting

## Product Non-Goals

- Generic chatbot-first UX
- Unrestricted autonomous testing
- Automatic exploit generation
- Brute force or indiscriminate scanning
- Unverified remediation claims
- Hidden cross-origin testing
- Cloud AI by default
- Decorative dashboards without a testing decision behind them

## Product Success

A user should be able to answer:

- What application and scope was assessed?
- What did Sentinel actually observe?
- Which signals remain unverified?
- What evidence supports the finding?
- What did the verifier prove or fail to prove?
- Can the result be repeated?
- Did remediation change the verified behavior?

If the interface cannot answer these questions, it is not yet delivering the core product value.
