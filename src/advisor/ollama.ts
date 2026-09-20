import { EvidenceRecord, Finding } from "../desktop";

export interface AdvisorResponse {
  whyItMatters: string;
  citedEvidenceIds: string[];
  isGrounded: boolean;
  codePatches: Array<{
    framework: string;
    code: string;
    description: string;
  }>;
}

function escapeXml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

export function getOfflineKnowledge(cwe?: string, owasp?: string): string {
  const cweNum = cwe ? cwe.toUpperCase().replace(/[^0-9]/g, "") : "";

  if (cweNum === "79" || owasp?.includes("Injection")) {
    return `[OWASP A03 / CWE-79 Injection Reference]
Context-aware output encoding is the primary defense against XSS.
- In HTML Body: Entity-encode (< -> &lt;, > -> &gt;, & -> &amp;, " -> &quot;, ' -> &#x27;)
- In JavaScript context: Avoid direct string concatenation. Use JSON-safe serialization (JSON.stringify) or pass data via data-* attributes parsed on load.
- In Tag Attributes: Quote all attributes and encode attribute delimiters.`;
  }

  if (cweNum === "614" || cweNum === "1004" || cweNum === "1275") {
    return `[OWASP A05 / CWE-614 Cookie Security Reference]
Cookies containing session or authentication state must enforce RFC 6265bis directives:
- 'HttpOnly': Blocks JavaScript document.cookie access.
- 'Secure': Restricts cookie transmission strictly to TLS encrypted HTTPS channels.
- 'SameSite=Lax/Strict': Mitigates CSRF.
- '__Host-' Prefix: Enforces Secure, Path=/, and rejection of Domain attribute.`;
  }

  if (cweNum === "1021") {
    return `[OWASP A05 / CWE-1021 Clickjacking Reference]
Clickjacking allows invisible framing attacks. Mitigate with:
- CSP 'frame-ancestors 'none'' (or 'self')
- 'X-Frame-Options: DENY' for legacy browser support.`;
  }

  if (cweNum === "942") {
    return `[OWASP A01 / CWE-942 CORS Reference]
CORS headers dictate cross-origin read permissions.
- Never mirror Origin request header into Access-Control-Allow-Origin while setting Access-Control-Allow-Credentials: true.
- Use explicit origin whitelisting.`;
  }

  return `[OWASP A05 Security Misconfiguration Reference]
Apply defense-in-depth HTTP security headers (CSP, HSTS, X-Content-Type-Options: nosniff, Referrer-Policy, Permissions-Policy).`;
}

export function buildQuarantinedPrompt(
  finding: Finding,
  relevantEvidence: EvidenceRecord[]
): string {
  const sanitizedEvidence = relevantEvidence.map((e) => ({
    id: escapeXml(e.id),
    kind: escapeXml(e.kind),
    label: escapeXml(e.label),
    detail: escapeXml(e.detail.slice(0, 300)),
    meta: e.meta ? escapeXml(JSON.stringify(e.meta).slice(0, 400)) : undefined,
  }));

  const knowledge = getOfflineKnowledge(finding.cwe, finding.owasp);

  return `You are a senior AppSec engineer and defensive security mentor.
Analyze the following verified finding for an application owner.
Explain why it matters in principle, cite the EXACT evidence IDs from the quarantined evidence list, and provide defensive, production-ready code remediation patches across multiple frameworks (e.g. Node.js/Express, Next.js, Python/FastAPI, or Django).
Do NOT generate exploit payloads, attack strings, or instructions on how to attack.

<curated_knowledge_base>
${knowledge}
</curated_knowledge_base>

<finding_context>
Title: ${escapeXml(finding.title)}
Severity: ${escapeXml(finding.severity)}
OWASP: ${escapeXml(finding.owasp || "N/A")}
CWE: ${escapeXml(finding.cwe || "N/A")}
Evidence ID: ${escapeXml(finding.evidence)}
</finding_context>

<quarantined_evidence>
${JSON.stringify(sanitizedEvidence, null, 2)}
</quarantined_evidence>

Respond ONLY with valid JSON conforming to this exact schema:
{
  "whyItMatters": "string explaining the security risk in words with context",
  "citedEvidenceIds": ["${finding.evidence}"],
  "codePatches": [
    {
      "framework": "Node.js (Express / Helmet)",
      "description": "Brief description of the fix",
      "code": "// Clean defensive code snippet"
    },
    {
      "framework": "Next.js",
      "description": "Brief description of the fix",
      "code": "// Clean defensive code snippet"
    },
    {
      "framework": "Python (FastAPI / Django)",
      "description": "Brief description of the fix",
      "code": "# Clean defensive code snippet"
    }
  ]
}`;
}

export function parseAndValidateAdvisorResponse(
  rawJson: string,
  availableEvidence: EvidenceRecord[],
  findingFallback?: Finding
): AdvisorResponse {
  const availableIds = new Set(availableEvidence.map((e) => e.id));

  try {
    const parsed = JSON.parse(rawJson);
    const whyItMatters = typeof parsed.whyItMatters === "string" ? parsed.whyItMatters : "Review response configuration and apply defensive controls.";
    const citedEvidenceIds = Array.isArray(parsed.citedEvidenceIds) ? (parsed.citedEvidenceIds as string[]) : [];

    // Check if citations are grounded in our real evidence store
    const isGrounded = citedEvidenceIds.length > 0 && citedEvidenceIds.every((id) => availableIds.has(id));

    const codePatches = Array.isArray(parsed.codePatches)
      ? parsed.codePatches.map((p: Record<string, unknown>) => ({
          framework: String(p.framework || "Generic"),
          description: String(p.description || "Apply security header/attribute"),
          code: String(p.code || "// Add defensive configuration"),
        }))
      : [];

    return {
      whyItMatters,
      citedEvidenceIds,
      isGrounded,
      codePatches: codePatches.length > 0 ? codePatches : getDefaultDeterministicPatches(findingFallback),
    };
  } catch {
    return {
      whyItMatters: findingFallback?.description || "The response did not conform to JSON. Inspect the cited evidence directly.",
      citedEvidenceIds: findingFallback?.evidence ? [findingFallback.evidence] : [],
      isGrounded: true,
      codePatches: getDefaultDeterministicPatches(findingFallback),
    };
  }
}

export function getDefaultDeterministicPatches(finding?: Finding): Array<{ framework: string; description: string; code: string }> {
  if (!finding) return [];
  const cwe = finding.cwe || "";

  if (cwe.includes("79") || finding.source === "Canary") {
    return [
      {
        framework: "React / Modern DOM",
        description: "Rely on standard JSX bindings which automatically HTML-encode user data.",
        code: `// Safe JSX auto-escaping:\nfunction SearchDisplay({ query }: { query: string }) {\n  return <h1>Search results for: {query}</h1>;\n}\n// Avoid: <div dangerouslySetInnerHTML={{ __html: query }} />`,
      },
      {
        framework: "Node.js / Express",
        description: "Use DOMPurify and contextual entity encoders when building dynamic markup.",
        code: `const createDOMPurify = require('dompurify');\nconst { JSDOM } = require('jsdom');\nconst window = new JSDOM('').window;\nconst DOMPurify = createDOMPurify(window);\n\nconst cleanHtml = DOMPurify.sanitize(userInput);`,
      },
      {
        framework: "Python / Django",
        description: "Use Django template autoescaping and escape filters.",
        code: `from django.utils.html import escape\n\nsafe_output = escape(user_input)`,
      },
    ];
  }

  if (cwe.includes("614") || cwe.includes("1004") || cwe.includes("1275")) {
    return [
      {
        framework: "Node.js (Express Session)",
        description: "Configure explicit Secure, HttpOnly, and SameSite attributes.",
        code: `app.use(session({\n  secret: process.env.SESSION_SECRET,\n  cookie: {\n    httpOnly: true,\n    secure: process.env.NODE_ENV === 'production',\n    sameSite: 'lax',\n    path: '/'\n  }\n}));`,
      },
      {
        framework: "Python (FastAPI)",
        description: "Issue cookies with full defensive flags.",
        code: `from fastapi import Response\n\n@app.post("/auth")\ndef set_auth(response: Response, token: str):\n    response.set_cookie(\n        key="__Host-session",\n        value=token,\n        httponly=True,\n        secure=True,\n        samesite="lax",\n        path="/"\n    )`,
      },
    ];
  }

  return [
    {
      framework: "Node.js (Helmet Middleware)",
      description: "Apply industry-standard HTTP security headers automatically.",
      code: `const helmet = require('helmet');\n\napp.use(helmet({\n  contentSecurityPolicy: {\n    directives: {\n      defaultSrc: ["'self'"],\n      scriptSrc: ["'self'"],\n      objectSrc: ["'none'"],\n      frameAncestors: ["'none'"],\n    },\n  },\n  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },\n  hsts: { maxAge: 31536000, includeSubDomains: true },\n}));`,
    },
    {
      framework: "Next.js (next.config.mjs)",
      description: "Define comprehensive security headers at the routing edge.",
      code: `// next.config.mjs\nexport default {\n  async headers() {\n    return [\n      {\n        source: '/(.*)',\n        headers: [\n          { key: 'X-Content-Type-Options', value: 'nosniff' },\n          { key: 'X-Frame-Options', value: 'DENY' },\n          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },\n          { key: 'Content-Security-Policy', value: "default-src 'self'; script-src 'self'; object-src 'none';" },\n        ],\n      },\n    ];\n  },\n};`,
    },
  ];
}
