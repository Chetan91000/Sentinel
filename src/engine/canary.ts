import { EvidenceRecord, Finding } from "../desktop";
import { generateFindingId } from "./rules";

export function generateCanaryToken(prefix = "sentinel-canary"): string {
  const rand = Math.random().toString(36).substring(2, 8).toUpperCase();
  return `${prefix}-${rand}`;
}

export function buildCanaryTargetUrl(baseUrl: string, paramName: string, token: string): string {
  try {
    const parsed = new URL(baseUrl);
    parsed.searchParams.set(paramName, token);
    return parsed.toString();
  } catch {
    return baseUrl;
  }
}

export function buildBatchCanaryTargetUrl(
  baseUrl: string,
  params: Array<{ paramName: string; token: string }>
): string {
  try {
    const parsed = new URL(baseUrl);
    for (const p of params) {
      parsed.searchParams.set(p.paramName, p.token);
    }
    return parsed.toString();
  } catch {
    return baseUrl;
  }
}

export interface ReflectionAnalysis {
  isReflected: boolean;
  isRawUnencoded: boolean;
  context: "HTML_BODY" | "ATTRIBUTE" | "SCRIPT" | "SCRIPT_STRING" | "HEADER" | "NOT_FOUND";
  snippet: string;
}

export function analyzeDomReflection(domHtml: string, token: string): ReflectionAnalysis {
  if (!domHtml || !token || !domHtml.includes(token)) {
    return {
      isReflected: false,
      isRawUnencoded: false,
      context: "NOT_FOUND",
      snippet: "",
    };
  }

  const tokenIdx = domHtml.indexOf(token);
  const start = Math.max(0, tokenIdx - 60);
  const end = Math.min(domHtml.length, tokenIdx + token.length + 60);
  const snippet = domHtml.substring(start, end).replace(/[\r\n]+/g, " ");

  // Check if reflection is inside <script> tag
  const beforeSlice = domHtml.substring(0, tokenIdx).toLowerCase();
  const lastScriptOpen = beforeSlice.lastIndexOf("<script");
  const lastScriptClose = beforeSlice.lastIndexOf("</script");
  const insideScript = lastScriptOpen !== -1 && lastScriptOpen > lastScriptClose;

  if (insideScript) {
    // Check if inside JavaScript string quotes
    const scriptBodyBefore = domHtml.substring(lastScriptOpen, tokenIdx);
    const singleQuotes = (scriptBodyBefore.match(/'/g) || []).length;
    const doubleQuotes = (scriptBodyBefore.match(/"/g) || []).length;
    const backticks = (scriptBodyBefore.match(/`/g) || []).length;
    const inStringQuote = (singleQuotes % 2 === 1) || (doubleQuotes % 2 === 1) || (backticks % 2 === 1);

    return {
      isReflected: true,
      isRawUnencoded: true,
      context: inStringQuote ? "SCRIPT_STRING" : "SCRIPT",
      snippet,
    };
  }

  // Check if inside attribute e.g. value="token" or href="token"
  const tagOpen = beforeSlice.lastIndexOf("<");
  const tagClose = beforeSlice.lastIndexOf(">");
  const insideTag = tagOpen !== -1 && tagOpen > tagClose;

  return {
    isReflected: true,
    isRawUnencoded: true,
    context: insideTag ? "ATTRIBUTE" : "HTML_BODY",
    snippet,
  };
}

export function analyzeHeaderReflection(
  responseHeaders: Record<string, string | string[]> | undefined,
  token: string
): { isReflected: boolean; headerName?: string; snippet?: string } {
  if (!responseHeaders || !token) return { isReflected: false };

  for (const [name, val] of Object.entries(responseHeaders)) {
    const headerStr = Array.isArray(val) ? val.join("; ") : String(val);
    if (headerStr.includes(token)) {
      return {
        isReflected: true,
        headerName: name,
        snippet: `${name}: ${headerStr.slice(0, 100)}`,
      };
    }
  }

  return { isReflected: false };
}

export function createCanaryFinding(
  url: string,
  paramName: string,
  analysis: ReflectionAnalysis,
  evidenceId: string
): Finding {
  const isScript = analysis.context === "SCRIPT" || analysis.context === "SCRIPT_STRING";
  return {
    id: generateFindingId(),
    severity: isScript ? "High" : "Medium",
    title: `Unencoded Reflection in ${analysis.context} (${paramName})`,
    source: "Canary",
    evidence: evidenceId,
    owasp: "A03:2021-Injection",
    cwe: "CWE-79",
    description: `The inert test parameter '${paramName}' was reflected verbatim in the ${analysis.context} context without context-aware HTML entity or JavaScript string encoding. Snippet observed: "${analysis.snippet}". This demonstrates an output encoding weakness.`,
    remediation: isScript
      ? `Ensure input placed into JavaScript contexts is serialized with secure JSON serialization (e.g. JSON.stringify or template-level JS escaping), or avoid embedding user data directly in inline scripts.`
      : `Apply context-aware output encoding (e.g. HTML entity encoding for body, attribute encoding for tag attributes) before rendering untrusted input.`,
  };
}
