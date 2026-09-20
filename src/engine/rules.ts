import { EvidenceRecord, Finding } from "../desktop";

export function generateFindingId(): string {
  return "FND-" + Date.now().toString(36).toUpperCase() + "-" + Math.random().toString(36).substr(2, 4).toUpperCase();
}

export function getHeaderValues(headers: Record<string, string | string[]> | undefined, headerName: string): string[] {
  if (!headers || typeof headers !== "object") return [];
  const target = headerName.toLowerCase();
  for (const [key, val] of Object.entries(headers)) {
    if (key.toLowerCase() === target) {
      if (Array.isArray(val)) return val;
      if (typeof val === "string") return [val];
    }
  }
  return [];
}

export function getFirstHeader(headers: Record<string, string | string[]> | undefined, headerName: string): string | undefined {
  const values = getHeaderValues(headers, headerName);
  return values[0];
}

export function evaluateEvidenceRules(evidenceList: EvidenceRecord[]): Finding[] {
  const findings: Finding[] = [];
  const responses = evidenceList.filter((e) => e.kind === "RES" || e.kind === "RES_DONE");

  // 1. Main Document Response Rules (CSP, HSTS, MIME, Clickjacking, Referrer, Permissions, CORP, COEP)
  const mainDocResponse = responses.find((r) => {
    const meta = r.meta as { resourceType?: string; headers?: Record<string, string[]> } | undefined;
    return meta?.resourceType === "main_frame" || !meta?.resourceType;
  }) || responses[0];

  if (mainDocResponse) {
    const headers = (mainDocResponse.meta?.headers as Record<string, string[]>) || {};
    const csp = getFirstHeader(headers, "content-security-policy") || getFirstHeader(headers, "content-security-policy-report-only");

    if (!csp) {
      findings.push({
        id: generateFindingId(),
        severity: "Medium",
        title: "Content-Security-Policy (CSP) Header Missing",
        source: "Passive",
        evidence: mainDocResponse.id,
        owasp: "A05:2021-Security Misconfiguration",
        cwe: "CWE-693",
        description:
          "The document response did not include a Content-Security-Policy header. Without CSP, the application lacks defense-in-depth protection against cross-site scripting and unauthorized content injection.",
        remediation:
          "Configure a Content-Security-Policy HTTP header restricting script-src, object-src, and default-src to trusted origins.",
      });
    }

    // 2. Strict Transport Security (HSTS) over HTTPS
    const isHttps = mainDocResponse.detail?.startsWith("https://") || (mainDocResponse.meta?.url as string)?.startsWith("https://");
    if (isHttps) {
      const hsts = getFirstHeader(headers, "strict-transport-security");
      if (!hsts) {
        findings.push({
          id: generateFindingId(),
          severity: "Low",
          title: "HTTP Strict-Transport-Security (HSTS) Missing",
          source: "Passive",
          evidence: mainDocResponse.id,
          owasp: "A05:2021-Security Misconfiguration",
          cwe: "CWE-319",
          description:
            "The HTTPS document response did not declare an HSTS header. Browsers may downgrade future connections to insecure HTTP.",
          remediation:
            "Add Strict-Transport-Security: max-age=31536000; includeSubDomains to enforce HTTPS transport.",
        });
      }
    }

    // 3. MIME-Sniffing Protection (X-Content-Type-Options)
    const xcto = getFirstHeader(headers, "x-content-type-options");
    if (!xcto || xcto.toLowerCase() !== "nosniff") {
      findings.push({
        id: generateFindingId(),
        severity: "Info",
        title: "X-Content-Type-Options Header Missing",
        source: "Passive",
        evidence: mainDocResponse.id,
        owasp: "A05:2021-Security Misconfiguration",
        cwe: "CWE-116",
        description:
          "The server did not include 'X-Content-Type-Options: nosniff'. Browsers may attempt to sniff MIME types, potentially treating user-supplied files as executable scripts.",
        remediation: "Add header 'X-Content-Type-Options: nosniff' to all HTTP responses.",
      });
    }

    // 4. Clickjacking Frame Protection
    const xfo = getFirstHeader(headers, "x-frame-options");
    const cspDirectives = getHeaderValues(headers, "content-security-policy");
    const hasFrameAncestors = cspDirectives.some((c) => c.toLowerCase().includes("frame-ancestors"));

    if (!xfo && !hasFrameAncestors) {
      findings.push({
        id: generateFindingId(),
        severity: "Low",
        title: "Missing Anti-Clickjacking Frame Protection",
        source: "Passive",
        evidence: mainDocResponse.id,
        owasp: "A05:2021-Security Misconfiguration",
        cwe: "CWE-1021",
        description:
          "The document response does not specify X-Frame-Options or CSP frame-ancestors directive. The page may be embedded inside unauthorized third-party iframes.",
        remediation: "Set 'X-Frame-Options: DENY' or use CSP 'frame-ancestors 'none'' to prevent clickjacking.",
      });
    }

    // 5. Referrer-Policy Header Check
    const refPolicy = getFirstHeader(headers, "referrer-policy");
    const unsafePolicies = ["unsafe-url", "no-referrer-when-downgrade"];
    if (!refPolicy || unsafePolicies.includes(refPolicy.toLowerCase().trim())) {
      findings.push({
        id: generateFindingId(),
        severity: "Info",
        title: refPolicy ? `Unsafe Referrer-Policy: ${refPolicy}` : "Referrer-Policy Header Missing",
        source: "Passive",
        evidence: mainDocResponse.id,
        owasp: "A05:2021-Security Misconfiguration",
        cwe: "CWE-116",
        description: refPolicy
          ? `The Referrer-Policy '${refPolicy}' may leak sensitive query parameters and URLs to third-party domains.`
          : "No Referrer-Policy header declared. The browser default may expose internal pathnames and query strings in cross-origin requests.",
        remediation: "Add 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer' to responses.",
      });
    }

    // 6. Permissions-Policy / Feature-Policy Check
    const permPolicy = getFirstHeader(headers, "permissions-policy") || getFirstHeader(headers, "feature-policy");
    if (!permPolicy) {
      findings.push({
        id: generateFindingId(),
        severity: "Info",
        title: "Permissions-Policy Header Missing",
        source: "Passive",
        evidence: mainDocResponse.id,
        owasp: "A05:2021-Security Misconfiguration",
        cwe: "CWE-693",
        description:
          "The document does not restrict powerful browser features (camera, microphone, geolocation, payment) via Permissions-Policy.",
        remediation: "Add 'Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()' to disable unnecessary browser APIs.",
      });
    }

    // 7. Cross-Origin-Resource-Policy (CORP) & Cross-Origin-Embedder-Policy (COEP)
    const corp = getFirstHeader(headers, "cross-origin-resource-policy");
    const coep = getFirstHeader(headers, "cross-origin-embedder-policy");
    if (!corp) {
      findings.push({
        id: generateFindingId(),
        severity: "Info",
        title: "Cross-Origin-Resource-Policy (CORP) Missing",
        source: "Passive",
        evidence: mainDocResponse.id,
        owasp: "A05:2021-Security Misconfiguration",
        cwe: "CWE-693",
        description: "Without Cross-Origin-Resource-Policy: same-origin or same-site, external origins may read or embed this resource across origins (Spectre isolation).",
        remediation: "Add 'Cross-Origin-Resource-Policy: same-origin' on sensitive resources.",
      });
    }
  }

  // 8. Permissive CORS with Credentials (evaluated across ALL response events, including APIs)
  const seenCors = new Set<string>();
  for (const resp of responses) {
    const headers = (resp.meta?.headers as Record<string, string[]>) || {};
    const allowOrigin = getFirstHeader(headers, "access-control-allow-origin");
    const allowCreds = getFirstHeader(headers, "access-control-allow-credentials")?.toLowerCase() === "true";

    if (allowOrigin === "*" && allowCreds && !seenCors.has(resp.detail)) {
      seenCors.add(resp.detail);
      findings.push({
        id: generateFindingId(),
        severity: "High",
        title: "Insecure CORS: Wildcard Origin with Credentials Allowed",
        source: "Passive",
        evidence: resp.id,
        owasp: "A01:2021-Broken Access Control",
        cwe: "CWE-942",
        description:
          "Access-Control-Allow-Origin is set to '*' while Access-Control-Allow-Credentials is true. Arbitrary cross-origin sites can read authenticated response data.",
        remediation: "Specify an explicit origin allowlist instead of '*' when credentials are required.",
      });
    }
  }

  // 9. Cookie Hygiene + __Host- and __Secure- Prefix Compliance
  const cookieFindingsMap = new Map<string, { evidenceId: string; issues: string[] }>();
  responses.forEach((r) => {
    const headers = r.meta?.headers as Record<string, string[]> | undefined;
    const setCookieHeaders = getHeaderValues(headers, "set-cookie");

    for (const cookieStr of setCookieHeaders) {
      const parts = cookieStr.split(";").map((p) => p.trim());
      if (parts.length === 0 || !parts[0]) continue;
      const nameValue = parts[0].split("=");
      const cookieName = nameValue[0];
      const attrs = parts.slice(1).map((p) => p.toLowerCase());

      const isHttpOnly = attrs.includes("httponly");
      const isSecure = attrs.includes("secure");
      const hasSameSite = attrs.some((a) => a.startsWith("samesite="));
      const hasPathSlash = attrs.some((a) => a === "path=/");
      const hasDomain = attrs.some((a) => a.startsWith("domain="));

      const issues: string[] = [];
      if (!isHttpOnly) issues.push("Missing HttpOnly");
      if (!isSecure) issues.push("Missing Secure");
      if (!hasSameSite) issues.push("Missing SameSite");

      // Check __Host- prefix requirements (RFC 6265bis): must have Secure, Path=/, and NO Domain attribute
      if (cookieName.startsWith("__Host-")) {
        if (!isSecure) issues.push("__Host- cookie without Secure flag");
        if (!hasPathSlash) issues.push("__Host- cookie without Path=/");
        if (hasDomain) issues.push("__Host- cookie specifies Domain attribute");
      }

      // Check __Secure- prefix requirements: must have Secure
      if (cookieName.startsWith("__Secure-")) {
        if (!isSecure) issues.push("__Secure- cookie without Secure flag");
      }

      if (issues.length > 0 && !cookieFindingsMap.has(cookieName)) {
        cookieFindingsMap.set(cookieName, { evidenceId: r.id, issues });
      }
    }
  });

  cookieFindingsMap.forEach((data, cookieName) => {
    const isPrefixIssue = data.issues.some((i) => i.includes("__Host-") || i.includes("__Secure-"));
    findings.push({
      id: generateFindingId(),
      severity: isPrefixIssue ? "Medium" : "Low",
      title: isPrefixIssue
        ? `Cookie Prefix Violation on "${cookieName}"`
        : `Cookie "${cookieName}" Weak Attributes (${data.issues.join(", ")})`,
      source: "Passive",
      evidence: data.evidenceId,
      owasp: "A05:2021-Security Misconfiguration",
      cwe: "CWE-614",
      description: `Cookie "${cookieName}" was observed with: ${data.issues.join(", ")}. Cookies should follow strict transport and attribute constraints.`,
      remediation: cookieName.startsWith("__Host-")
        ? `Set '__Host-${cookieName.replace(/^__Host-/, "")}' with 'Secure; Path=/; SameSite=Lax; HttpOnly' and omit the Domain attribute.`
        : `Set 'SameSite=Lax; Secure; HttpOnly' attributes when generating the '${cookieName}' cookie.`,
    });
  });

  // 10. Subresource CSP and Insecure Content Violation Detection (from REQ stream)
  const reqEvents = evidenceList.filter((e) => e.kind === "REQ");
  const mixedContentReqs = reqEvents.filter((req) => {
    const isParentHttps = mainDocResponse?.detail?.startsWith("https://") || (mainDocResponse?.meta?.url as string)?.startsWith("https://");
    const reqUrl = req.detail || (req.meta?.url as string) || "";
    return isParentHttps && reqUrl.startsWith("http://");
  });

  if (mixedContentReqs.length > 0) {
    const firstMixed = mixedContentReqs[0];
    findings.push({
      id: generateFindingId(),
      severity: "High",
      title: `Mixed Content Detected: Insecure HTTP Subresource`,
      source: "Passive",
      evidence: firstMixed.id,
      owasp: "A05:2021-Security Misconfiguration",
      cwe: "CWE-311",
      description: `An HTTPS parent document loaded an unencrypted HTTP subresource (${firstMixed.detail}). Mixed content allows man-in-the-middle tampering.`,
      remediation: "Upgrade all subresource links (scripts, images, styles, API calls) to HTTPS or use CSP 'upgrade-insecure-requests'.",
    });
  }

  // 11. Console Errors
  const consoleErrors = evidenceList.filter((e) => e.kind === "CONSOLE" && (e.meta?.level === "error" || e.label.toLowerCase().includes("error")));
  consoleErrors.slice(0, 3).forEach((err) => {
    findings.push({
      id: generateFindingId(),
      severity: "Info",
      title: `Client-Side Console Error: ${err.detail.slice(0, 45)}...`,
      source: "Browser",
      evidence: err.id,
      owasp: "A05:2021-Security Misconfiguration",
      cwe: "CWE-209",
      description: `Browser reported an unhandled runtime error: ${err.detail}`,
      remediation: "Review client scripts to handle unhandled rejections and prevent leaking internal application state.",
    });
  });

  return findings;
}
