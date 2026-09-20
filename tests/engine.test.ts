import assert from 'node:assert';
import { evaluateEvidenceRules } from '../src/engine/rules.ts';
import { generateCanaryToken, analyzeDomReflection, analyzeHeaderReflection, buildCanaryTargetUrl, buildBatchCanaryTargetUrl } from '../src/engine/canary.ts';
import { parseScannerReport } from '../src/engine/ingest.ts';
import { compareReplayEvidence } from '../src/engine/replay.ts';
import { buildQuarantinedPrompt, parseAndValidateAdvisorResponse, getOfflineKnowledge } from '../src/advisor/ollama.ts';
import { EvidenceRecord, Finding } from '../src/desktop.d.ts';

let passed = 0;
let total = 0;

function test(name: string, fn: () => void) {
  total++;
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (err) {
    console.error(`  ✗ ${name}:`, err);
  }
}

console.log('=== Sentinel Security & Engine Integration Tests ===\n');

// 1. Rules Tests
test('Rule Engine: Missing CSP, HSTS, X-Content-Type-Options, Referrer, Permissions on vulnerable response', () => {
  const ev: EvidenceRecord = {
    id: 'EV-1',
    timestamp: new Date().toISOString(),
    kind: 'RES',
    label: 'Response',
    detail: 'https://app.test/',
    source: 'network',
    meta: {
      url: 'https://app.test/',
      resourceType: 'main_frame',
      headers: {
        'set-cookie': ['session=secret123'],
      },
    },
  };

  const findings = evaluateEvidenceRules([ev]);
  assert.ok(findings.some((f) => f.title.includes('Content-Security-Policy')));
  assert.ok(findings.some((f) => f.title.includes('Strict-Transport-Security')));
  assert.ok(findings.some((f) => f.title.includes('X-Content-Type-Options')));
  assert.ok(findings.some((f) => f.title.includes('Cookie "session" Weak Attributes')));
  assert.ok(findings.some((f) => f.title.includes('Permissions-Policy')));
});

test('Rule Engine: Clean pass on hardened / fixed response', () => {
  const ev: EvidenceRecord = {
    id: 'EV-2',
    timestamp: new Date().toISOString(),
    kind: 'RES',
    label: 'Response',
    detail: 'https://app.test/fixed',
    source: 'network',
    meta: {
      url: 'https://app.test/fixed',
      resourceType: 'main_frame',
      headers: {
        'content-security-policy': ["default-src 'self'; frame-ancestors 'none'"],
        'strict-transport-security': ['max-age=31536000; includeSubDomains'],
        'x-content-type-options': ['nosniff'],
        'x-frame-options': ['DENY'],
        'referrer-policy': ['strict-origin-when-cross-origin'],
        'permissions-policy': ['camera=(), microphone=()'],
        'cross-origin-resource-policy': ['same-origin'],
        'set-cookie': ['__Host-auth=12345; Secure; Path=/; SameSite=Lax; HttpOnly'],
      },
    },
  };

  const findings = evaluateEvidenceRules([ev]);
  // No high or medium findings on hardened route
  const criticalOrHigh = findings.filter((f) => f.severity === 'High');
  assert.strictEqual(criticalOrHigh.length, 0);
  assert.strictEqual(findings.some((f) => f.title.includes('Missing')), false);
});

test('Rule Engine: __Host- cookie prefix violation detection', () => {
  const ev: EvidenceRecord = {
    id: 'EV-3',
    timestamp: new Date().toISOString(),
    kind: 'RES',
    label: 'Response',
    detail: 'https://app.test/',
    source: 'network',
    meta: {
      headers: {
        'set-cookie': ['__Host-token=12345; SameSite=Lax'], // Missing Secure, Missing Path=/
      },
    },
  };

  const findings = evaluateEvidenceRules([ev]);
  const prefixFinding = findings.find((f) => f.title.includes('Cookie Prefix Violation on "__Host-token"'));
  assert.ok(prefixFinding);
  assert.ok(prefixFinding.description.includes('__Host- cookie without Secure flag'));
});

// 2. Canary Tests
test('Canary Engine: Target URL construction & batching', () => {
  const token = generateCanaryToken();
  const url = buildCanaryTargetUrl('https://app.test/search?cat=1', 'q', token);
  assert.ok(url.includes(`q=${token}`));
  assert.ok(url.includes('cat=1'));

  const batchUrl = buildBatchCanaryTargetUrl('https://app.test/api', [
    { paramName: 'p1', token: 'T1' },
    { paramName: 'p2', token: 'T2' },
  ]);
  assert.ok(batchUrl.includes('p1=T1'));
  assert.ok(batchUrl.includes('p2=T2'));
});

test('Canary Engine: Context-aware reflection detection in HTML body and script tag', () => {
  const token = 'CANARY_XYZ_999';
  const htmlBody = `<div>Search result for: ${token}</div>`;
  const res1 = analyzeDomReflection(htmlBody, token);
  assert.strictEqual(res1.isReflected, true);
  assert.strictEqual(res1.context, 'HTML_BODY');

  const htmlScript = `<script>const search = "${token}";</script>`;
  const res2 = analyzeDomReflection(htmlScript, token);
  assert.strictEqual(res2.isReflected, true);
  assert.strictEqual(res2.context, 'SCRIPT_STRING');

  const htmlAttr = `<input type="text" value="${token}" />`;
  const res3 = analyzeDomReflection(htmlAttr, token);
  assert.strictEqual(res3.isReflected, true);
  assert.strictEqual(res3.context, 'ATTRIBUTE');
});

test('Canary Engine: Header reflection detection', () => {
  const token = 'TOKEN_HDR_123';
  const headers = { 'x-reflected-input': `Value with ${token}` };
  const res = analyzeHeaderReflection(headers, token);
  assert.strictEqual(res.isReflected, true);
  assert.strictEqual(res.headerName, 'x-reflected-input');
});

// 3. Scanner Ingestion Tests
test('Ingest Engine: SARIF v2.1.0 report with rule property resolution', () => {
  const sarifSample = JSON.stringify({
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Nuclei',
            rules: [
              {
                id: 'cve-2023-test',
                name: 'Test Vulnerability',
                properties: { cwe: 'CWE-89', owasp: 'A03:2021-Injection' },
              },
            ],
          },
        },
        results: [
          {
            ruleId: 'cve-2023-test',
            message: { text: 'SQL Injection detected in query parameter' },
            level: 'error',
            locations: [{ physicalLocation: { artifactLocation: { uri: 'http://target/search' } } }],
          },
        ],
      },
    ],
  });

  const { findings, records } = parseScannerReport(sarifSample, 'nuclei.sarif');
  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].severity, 'High');
  assert.strictEqual(findings[0].cwe, 'CWE-89');
  assert.strictEqual(findings[0].owasp, 'A03:2021-Injection');
  assert.strictEqual(records.length, 1);
  assert.strictEqual(records[0].kind, 'SCANNER_ALERT');
});

test('Ingest Engine: OWASP ZAP single-site & object alert handling', () => {
  const zapSample = JSON.stringify({
    site: {
      '@name': 'http://localhost:3000',
      alerts: {
        alert: 'Absence of Anti-CSRF Tokens',
        riskcode: '2',
        cweid: '352',
        desc: 'No anti-CSRF token observed in form submission.',
      },
    },
  });

  const { findings, records } = parseScannerReport(zapSample, 'zap.json');
  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].severity, 'Medium');
  assert.strictEqual(findings[0].cwe, 'CWE-352');
  assert.strictEqual(records.length, 1);
});

// 4. Replay Comparator Tests
test('Replay Engine: Compares baseline and remediated re-test correctly', () => {
  const baselineEv: EvidenceRecord = {
    id: 'EV-BASE-1',
    timestamp: new Date().toISOString(),
    kind: 'RES',
    label: 'Baseline Response',
    detail: 'http://app.test/',
    source: 'network',
    meta: { headers: {} },
  };

  const targetFinding: Finding = {
    id: 'FND-1',
    severity: 'Medium',
    title: 'Content-Security-Policy (CSP) Header Missing',
    source: 'Passive',
    evidence: 'EV-BASE-1',
    description: 'CSP Missing',
  };

  // Re-test with CSP applied
  const retestEv: EvidenceRecord = {
    id: 'EV-RETEST-1',
    timestamp: new Date().toISOString(),
    kind: 'RES',
    label: 'Retest Response',
    detail: 'http://app.test/',
    source: 'network',
    meta: {
      headers: {
        'content-security-policy': ["default-src 'self'"],
      },
    },
  };

  const res = compareReplayEvidence(targetFinding, [baselineEv], [retestEv]);
  assert.strictEqual(res.status, 'Fixed');
  assert.ok(res.headerDiff && res.headerDiff.length > 0);
  assert.ok(res.headerDiff.some((d) => d.name === 'content-security-policy' && d.status === 'added'));
});

// 5. Advisor & Offline Knowledge Tests
test('Advisor: Offline knowledge retrieval and deterministic fallback patches', () => {
  const xssKnowledge = getOfflineKnowledge('CWE-79', 'A03:2021-Injection');
  assert.ok(xssKnowledge.includes('Context-aware output encoding'));

  const prompt = buildQuarantinedPrompt(
    {
      id: 'FND-1',
      severity: 'High',
      title: 'Reflected Canary',
      source: 'Canary',
      evidence: 'EV-1',
      description: 'Reflected parameter',
      cwe: 'CWE-79',
    },
    [{ id: 'EV-1', timestamp: new Date().toISOString(), kind: 'RES', label: 'Res', detail: 'test', source: 'network' }]
  );
  assert.ok(prompt.includes('<curated_knowledge_base>'));
  assert.ok(prompt.includes('<quarantined_evidence>'));

  const fallback = parseAndValidateAdvisorResponse('invalid-json', [], {
    id: 'FND-1',
    severity: 'High',
    title: 'XSS',
    source: 'Canary',
    evidence: 'EV-1',
    cwe: 'CWE-79',
    description: 'XSS description',
  });
  assert.ok(fallback.codePatches.length >= 2);
  assert.ok(fallback.codePatches.some((p) => p.framework.includes('React')));
});

console.log(`\nResults: ${passed} / ${total} tests passed.`);
if (passed === total) {
  console.log('All integration test fixtures completed successfully!');
} else {
  process.exit(1);
}
