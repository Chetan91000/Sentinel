import { EvidenceRecord, Finding } from "../desktop";
import { generateFindingId } from "./rules";

export interface SarifLog {
  version?: string;
  runs?: Array<{
    tool?: {
      driver?: {
        name?: string;
        version?: string;
        rules?: Array<{
          id: string;
          name?: string;
          shortDescription?: { text?: string };
          fullDescription?: { text?: string };
          helpUri?: string;
          properties?: {
            tags?: string[];
            cwe?: string | string[];
            owasp?: string;
            "problem.severity"?: string;
          };
        }>;
      };
    };
    results?: Array<{
      ruleId?: string;
      ruleIndex?: number;
      message?: { text?: string };
      level?: string;
      locations?: Array<{
        physicalLocation?: {
          artifactLocation?: { uri?: string };
          region?: { startLine?: number };
        };
      }>;
      properties?: Record<string, unknown>;
    }>;
  }>;
}

export interface ZapReport {
  site?: Array<{
    "@name"?: string;
    "@host"?: string;
    alerts?: Array<{
      pluginid?: string;
      alert?: string;
      riskcode?: string;
      riskdesc?: string;
      desc?: string;
      solution?: string;
      cweid?: string;
      wascid?: string;
      uri?: string;
      instances?: Array<{ uri?: string; method?: string; param?: string }>;
    }>;
  }>;
}

function mapCweToOwasp(cwe: string): string {
  const num = parseInt(cwe.replace(/[^0-9]/g, ""), 10);
  if (isNaN(num)) return "A05:2021-Security Misconfiguration";

  switch (num) {
    case 79:
    case 89:
    case 78:
    case 77:
      return "A03:2021-Injection";
    case 287:
    case 384:
    case 613:
      return "A07:2021-Identification and Authentication Failures";
    case 200:
    case 311:
    case 319:
    case 359:
      return "A02:2021-Cryptographic Failures";
    case 16:
    case 614:
    case 693:
    case 1004:
    case 1021:
      return "A05:2021-Security Misconfiguration";
    case 942:
    case 862:
    case 863:
    case 639:
      return "A01:2021-Broken Access Control";
    case 1035:
    case 1104:
      return "A06:2021-Vulnerable and Outdated Components";
    default:
      return "A05:2021-Security Misconfiguration";
  }
}

export function parseScannerReport(
  rawJson: string,
  filename: string
): { findings: Finding[]; records: EvidenceRecord[] } {
  const findings: Finding[] = [];
  const records: EvidenceRecord[] = [];

  try {
    const data = JSON.parse(rawJson);

    // 1. Strict SARIF v2.1.0 Parser with rule property resolution
    if (data.runs && Array.isArray(data.runs)) {
      const sarif = data as SarifLog;
      const toolName = sarif.runs?.[0]?.tool?.driver?.name || "Scanner (SARIF)";

      sarif.runs?.forEach((run) => {
        const rulesMap = new Map<string, any>();
        if (Array.isArray(run.tool?.driver?.rules)) {
          run.tool.driver.rules.forEach((r) => {
            if (r.id) rulesMap.set(r.id, r);
          });
        }

        run.results?.forEach((res) => {
          const ruleId = res.ruleId || "VULN";
          const ruleMeta = rulesMap.get(ruleId) || {};
          const msg = res.message?.text || ruleMeta.shortDescription?.text || "Security issue reported";
          const uri = res.locations?.[0]?.physicalLocation?.artifactLocation?.uri || "N/A";
          
          const severityMap: Record<string, "High" | "Medium" | "Low" | "Info"> = {
            error: "High",
            warning: "Medium",
            note: "Low",
            none: "Info",
          };
          const severity = severityMap[res.level?.toLowerCase() || "warning"] || "Medium";

          // Extract CWE and map OWASP category
          let cwe = "CWE-693";
          const tags = (ruleMeta.properties?.tags as string[]) || [];
          const cweTag = tags.find((t) => t.toUpperCase().startsWith("CWE-"));
          if (cweTag) {
            cwe = cweTag.toUpperCase();
          } else if (ruleMeta.properties?.cwe) {
            const rawCwe = Array.isArray(ruleMeta.properties.cwe) ? String(ruleMeta.properties.cwe[0]) : String(ruleMeta.properties.cwe);
            cwe = rawCwe.toUpperCase().startsWith("CWE-") ? rawCwe.toUpperCase() : `CWE-${rawCwe}`;
          }

          const owasp = ruleMeta.properties?.owasp || mapCweToOwasp(cwe);

          const evId = `EV-SARIF-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).substr(2, 4).toUpperCase()}`;
          const evRecord: EvidenceRecord = {
            id: evId,
            timestamp: new Date().toISOString(),
            kind: "SCANNER_ALERT",
            label: `${toolName}: ${ruleId}`,
            detail: `${msg.slice(0, 80)} at ${uri}`,
            source: "scanner",
            meta: { toolName, ruleId, uri, cwe, owasp, raw: res },
          };
          records.push(evRecord);

          findings.push({
            id: generateFindingId(),
            severity,
            title: `[${toolName}] ${ruleMeta.name || ruleId}: ${msg.slice(0, 50)}`,
            source: "Imported Scanner",
            evidence: evId,
            owasp,
            cwe,
            description: ruleMeta.fullDescription?.text || `Imported from ${filename} (${toolName}). Target location: ${uri}. Detail: ${msg}`,
            remediation: ruleMeta.helpUri
              ? `Review scanner documentation at ${ruleMeta.helpUri} and inspect ${uri}.`
              : "Inspect the affected resource, review scanner recommendations, and verify whether the component requires patching.",
          });
        });
      });
      return { findings, records };
    }

    // 2. OWASP ZAP JSON Parser
    if (data.site || data.alerts || data.OWASPZAPReport) {
      let sitesList: any[] = [];
      if (Array.isArray(data.site)) {
        sitesList = data.site;
      } else if (data.site && typeof data.site === "object") {
        sitesList = [data.site];
      } else if (data.OWASPZAPReport?.site) {
        sitesList = Array.isArray(data.OWASPZAPReport.site) ? data.OWASPZAPReport.site : [data.OWASPZAPReport.site];
      } else if (data.alerts) {
        sitesList = [{ alerts: data.alerts }];
      }

      sitesList.forEach((s) => {
        const rawAlerts = Array.isArray(s.alerts) ? s.alerts : (s.alerts && typeof s.alerts === "object" ? [s.alerts] : []);
        rawAlerts.forEach((alert: any) => {
          const title = alert.alert || alert.name || "ZAP Alert";
          const riskMap: Record<string, "High" | "Medium" | "Low" | "Info"> = {
            "3": "High",
            "2": "Medium",
            "1": "Low",
            "0": "Info",
          };
          const severity = riskMap[alert.riskcode || "1"] || "Low";
          const uri = alert.instances?.[0]?.uri || alert.uri || s["@name"] || "N/A";
          const cwe = alert.cweid ? `CWE-${alert.cweid}` : "CWE-693";
          const owasp = mapCweToOwasp(cwe);

          const evId = `EV-ZAP-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).substr(2, 4).toUpperCase()}`;
          const evRecord: EvidenceRecord = {
            id: evId,
            timestamp: new Date().toISOString(),
            kind: "SCANNER_ALERT",
            label: `ZAP: ${title}`,
            detail: `${alert.riskdesc || severity} at ${uri}`,
            source: "scanner",
            meta: { alert, uri, cwe, owasp },
          };
          records.push(evRecord);

          findings.push({
            id: generateFindingId(),
            severity,
            title: `[OWASP ZAP] ${title}`,
            source: "Imported Scanner",
            evidence: evId,
            owasp,
            cwe,
            description: `${alert.desc || alert.description || "ZAP alert"} (Location: ${uri})`,
            remediation: alert.solution || "Review response configuration and apply defensive controls.",
          });
        });
      });
      return { findings, records };
    }

    return { findings: [], records: [] };
  } catch {
    return { findings: [], records: [] };
  }
}
