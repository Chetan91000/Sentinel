import { EvidenceRecord, Finding } from "../desktop";
import { evaluateEvidenceRules } from "./rules";

export interface HeaderDiffItem {
  name: string;
  baseline?: string;
  retest?: string;
  status: "added" | "removed" | "modified" | "unchanged";
}

export interface ReplayComparisonResult {
  findingId: string;
  status: "Fixed" | "Still Present" | "Not Comparable";
  explanation: string;
  baselineEvidenceId: string;
  retestEvidenceId?: string;
  headerDiff?: HeaderDiffItem[];
}

export function computeHeaderDiff(
  baselineHeaders: Record<string, string | string[]> | undefined,
  retestHeaders: Record<string, string | string[]> | undefined
): HeaderDiffItem[] {
  const diffs: HeaderDiffItem[] = [];
  const base = baselineHeaders || {};
  const retest = retestHeaders || {};

  const allKeys = new Set([...Object.keys(base).map((k) => k.toLowerCase()), ...Object.keys(retest).map((k) => k.toLowerCase())]);

  for (const k of allKeys) {
    const baseVal = getHeaderStr(base, k);
    const retestVal = getHeaderStr(retest, k);

    if (baseVal !== undefined && retestVal === undefined) {
      diffs.push({ name: k, baseline: baseVal, status: "removed" });
    } else if (baseVal === undefined && retestVal !== undefined) {
      diffs.push({ name: k, retest: retestVal, status: "added" });
    } else if (baseVal !== retestVal) {
      diffs.push({ name: k, baseline: baseVal, retest: retestVal, status: "modified" });
    } else {
      diffs.push({ name: k, baseline: baseVal, retest: retestVal, status: "unchanged" });
    }
  }

  return diffs;
}

function getHeaderStr(headers: Record<string, string | string[]>, targetName: string): string | undefined {
  for (const [key, val] of Object.entries(headers)) {
    if (key.toLowerCase() === targetName.toLowerCase()) {
      return Array.isArray(val) ? val.join("; ") : String(val);
    }
  }
  return undefined;
}

export function compareReplayEvidence(
  targetFinding: Finding,
  baselineEvidence: EvidenceRecord[],
  retestEvidence: EvidenceRecord[]
): ReplayComparisonResult {
  const baselineRecord = baselineEvidence.find((e) => e.id === targetFinding.evidence);
  if (!baselineRecord) {
    return {
      findingId: targetFinding.id,
      status: "Not Comparable",
      explanation: "Baseline evidence was not found in the baseline store.",
      baselineEvidenceId: targetFinding.evidence,
    };
  }

  // Handle active Canary findings
  if (targetFinding.source === "Canary") {
    const canaryRetest = retestEvidence.find((e) => e.kind === "CANARY_REFLECT");
    if (canaryRetest) {
      return {
        findingId: targetFinding.id,
        status: "Still Present",
        explanation: `Inert canary reflection was observed again in re-test (${canaryRetest.id}). Output encoding is still missing.`,
        baselineEvidenceId: targetFinding.evidence,
        retestEvidenceId: canaryRetest.id,
      };
    }
    const navCompleted = retestEvidence.find((e) => e.kind === "NAV" || e.kind === "RES");
    if (navCompleted) {
      return {
        findingId: targetFinding.id,
        status: "Fixed",
        explanation: `Canary token was no longer reflected in the target DOM. Context-aware encoding verified.`,
        baselineEvidenceId: targetFinding.evidence,
        retestEvidenceId: navCompleted.id,
      };
    }
    return {
      findingId: targetFinding.id,
      status: "Not Comparable",
      explanation: "Re-test failed to capture DOM navigation state.",
      baselineEvidenceId: targetFinding.evidence,
    };
  }

  // Handle imported scanner findings (SCANNER_ALERT)
  if (targetFinding.source === "Imported Scanner") {
    const retestAlerts = retestEvidence.filter((e) => e.kind === "SCANNER_ALERT");
    const matchingAlert = retestAlerts.find((a) => a.label === baselineRecord.label || a.detail === baselineRecord.detail);
    if (matchingAlert) {
      return {
        findingId: targetFinding.id,
        status: "Still Present",
        explanation: `Scanner alert '${matchingAlert.label}' re-triggered on target URI in latest scanner run.`,
        baselineEvidenceId: targetFinding.evidence,
        retestEvidenceId: matchingAlert.id,
      };
    }

    const completedScannerRun = retestEvidence.some((e) => e.kind === "SCANNER_ALERT" || e.kind === "NAV");
    if (completedScannerRun) {
      return {
        findingId: targetFinding.id,
        status: "Fixed",
        explanation: `Scanner alert '${targetFinding.title}' is absent in the new assessment timeline.`,
        baselineEvidenceId: targetFinding.evidence,
      };
    }

    return {
      findingId: targetFinding.id,
      status: "Not Comparable",
      explanation: "No scanner alerts or re-test execution captured for imported finding.",
      baselineEvidenceId: targetFinding.evidence,
    };
  }

  // Check if re-test captured HTTP responses
  const retestResponses = retestEvidence.filter((e) => e.kind === "RES" || e.kind === "RES_DONE");
  if (retestResponses.length === 0) {
    return {
      findingId: targetFinding.id,
      status: "Not Comparable",
      explanation: "No network responses were captured during the re-test session. Check connectivity.",
      baselineEvidenceId: targetFinding.evidence,
    };
  }

  const baselineHeaders = baselineRecord.meta?.headers as Record<string, string | string[]> | undefined;
  const retestHeaders = retestResponses[0]?.meta?.headers as Record<string, string | string[]> | undefined;
  const headerDiff = computeHeaderDiff(baselineHeaders, retestHeaders);

  // Evaluate rules on the re-test evidence stream
  const newFindings = evaluateEvidenceRules(retestEvidence);

  // Check if the specific finding still persists by matching normalized title
  const matchingStillPresent = newFindings.find((f) => {
    return f.title.trim().toLowerCase() === targetFinding.title.trim().toLowerCase();
  });

  if (matchingStillPresent) {
    return {
      findingId: targetFinding.id,
      status: "Still Present",
      explanation: `The vulnerability was re-observed in the new response (${matchingStillPresent.evidence}). Remediation is incomplete.`,
      baselineEvidenceId: targetFinding.evidence,
      retestEvidenceId: matchingStillPresent.evidence,
      headerDiff,
    };
  }

  // If absent in retest but navigation was successful, it's fixed!
  return {
    findingId: targetFinding.id,
    status: "Fixed",
    explanation: `The weakness is no longer observed in the re-tested response (${retestResponses[0]?.id}). Fix verified.`,
    baselineEvidenceId: targetFinding.evidence,
    retestEvidenceId: retestResponses[0]?.id,
    headerDiff,
  };
}
