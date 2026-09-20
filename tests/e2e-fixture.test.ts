import http from 'node:http';
import assert from 'node:assert';
import { createFixtureServer } from '../electron/fixtureServer.cjs';
import { evaluateEvidenceRules } from '../src/engine/rules.ts';
import { generateCanaryToken, analyzeDomReflection, buildCanaryTargetUrl } from '../src/engine/canary.ts';
import { compareReplayEvidence } from '../src/engine/replay.ts';
import { EvidenceRecord, Finding } from '../src/desktop.d.ts';

const PORT = 4567;
const BASE_URL = `http://127.0.0.1:${PORT}`;

function fetchUrl(url: string): Promise<{ statusCode: number; headers: http.IncomingHttpHeaders; body: string }> {
  return new Promise((resolve, reject) => {
    http.get(url, (res) => {
      let body = '';
      res.on('data', (chunk) => (body += chunk));
      res.on('end', () => resolve({ statusCode: res.statusCode || 200, headers: res.headers, body }));
    }).on('error', reject);
  });
}

async function runEndToEndFixtureTests() {
  console.log('=== Sentinel End-to-End Live Fixture Server Tests ===\n');

  const server = createFixtureServer(PORT);
  await new Promise<void>((resolve) => server.listen(PORT, '127.0.0.1', () => resolve()));
  console.log(`[1/5] Fixture server listening on ${BASE_URL}`);

  try {
    // Test 1: Fetch baseline vulnerable route and evaluate passive rules
    console.log('[2/5] Testing baseline vulnerable route (/)');
    const baseRes = await fetchUrl(`${BASE_URL}/`);
    assert.strictEqual(baseRes.statusCode, 200);

    const baseEvidence: EvidenceRecord = {
      id: 'EV-BASE-TEST',
      timestamp: new Date().toISOString(),
      kind: 'RES',
      label: 'HTTP Response 200',
      detail: `${BASE_URL}/`,
      source: 'network',
      meta: {
        url: `${BASE_URL}/`,
        statusCode: baseRes.statusCode,
        headers: baseRes.headers as Record<string, string[]>,
        resourceType: 'main_frame',
      },
    };

    const baseFindings = evaluateEvidenceRules([baseEvidence]);
    console.log(`  -> Detected ${baseFindings.length} passive hygiene findings on baseline:`);
    baseFindings.forEach((f) => console.log(`     • [${f.severity}] ${f.title} (${f.cwe})`));

    assert.ok(baseFindings.some((f) => f.title.includes('Content-Security-Policy')));
    assert.ok(baseFindings.some((f) => f.title.includes('X-Content-Type-Options')));
    assert.ok(baseFindings.some((f) => f.title.includes('Cookie "auth_token" Weak Attributes')));
    assert.ok(baseFindings.some((f) => f.title.includes('Referrer-Policy')));

    // Test 2: Test inert reflection canary endpoint
    console.log('\n[3/5] Testing inert reflection canary (/search?q=...)');
    const token = generateCanaryToken();
    const canaryUrl = buildCanaryTargetUrl(`${BASE_URL}/search`, 'q', token);
    const canaryRes = await fetchUrl(canaryUrl);

    const canaryAnalysis = analyzeDomReflection(canaryRes.body, token);
    console.log(`  -> Canary Token: ${token}`);
    console.log(`  -> Reflected: ${canaryAnalysis.isReflected}`);
    console.log(`  -> Context: ${canaryAnalysis.context}`);
    console.log(`  -> Snippet: "${canaryAnalysis.snippet}"`);

    assert.strictEqual(canaryAnalysis.isReflected, true);
    assert.strictEqual(canaryAnalysis.isRawUnencoded, true);

    // Test 3: Test CORS endpoint
    console.log('\n[4/5] Testing CORS endpoint (/api/cors)');
    const corsRes = await fetchUrl(`${BASE_URL}/api/cors`);
    const corsEvidence: EvidenceRecord = {
      id: 'EV-CORS-TEST',
      timestamp: new Date().toISOString(),
      kind: 'RES',
      label: 'HTTP Response 200',
      detail: `${BASE_URL}/api/cors`,
      source: 'network',
      meta: {
        url: `${BASE_URL}/api/cors`,
        statusCode: corsRes.statusCode,
        headers: corsRes.headers as Record<string, string[]>,
      },
    };
    const corsFindings = evaluateEvidenceRules([corsEvidence]);
    assert.ok(corsFindings.some((f) => f.title.includes('Insecure CORS: Wildcard Origin with Credentials Allowed')));
    console.log(`  -> CORS finding correctly flagged with High severity (CWE-942)`);

    // Test 4: Test Remediated Route and Replay Verification
    console.log('\n[5/5] Testing Remediated Route (/fixed) and Replay Comparator');
    const fixedRes = await fetchUrl(`${BASE_URL}/fixed`);
    const fixedEvidence: EvidenceRecord = {
      id: 'EV-FIXED-TEST',
      timestamp: new Date().toISOString(),
      kind: 'RES',
      label: 'HTTP Response 200',
      detail: `${BASE_URL}/fixed`,
      source: 'network',
      meta: {
        url: `${BASE_URL}/fixed`,
        statusCode: fixedRes.statusCode,
        headers: fixedRes.headers as Record<string, string[]>,
        resourceType: 'main_frame',
      },
    };

    const cspFinding = baseFindings.find((f) => f.title.includes('Content-Security-Policy'))!;
    const replayResult = compareReplayEvidence(cspFinding, [baseEvidence], [fixedEvidence]);

    console.log(`  -> Target Finding: "${cspFinding.title}"`);
    console.log(`  -> Replay Verdict: ${replayResult.status}`);
    console.log(`  -> Explanation: ${replayResult.explanation}`);
    console.log(`  -> Header Changes Detected:`);
    replayResult.headerDiff?.filter((d) => d.status !== 'unchanged').forEach((d) => {
      console.log(`     • [${d.status.toUpperCase()}] ${d.name}: ${d.retest || d.baseline}`);
    });

    assert.strictEqual(replayResult.status, 'Fixed');
    assert.ok(replayResult.headerDiff && replayResult.headerDiff.length > 0);

    console.log('\n✓ ALL LIVE END-TO-END FIXTURE TESTS PASSED SUCCESSFULLY!\n');
  } finally {
    server.close();
  }
}

runEndToEndFixtureTests().catch((err) => {
  console.error('E2E test failed:', err);
  process.exit(1);
});
