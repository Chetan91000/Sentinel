export interface EvidenceRecord {
  id: string
  timestamp: string
  kind: string
  label: string
  detail: string
  source: string
  hash?: string
  meta?: Record<string, unknown>
}

export interface Finding {
  id: string
  severity: "High" | "Medium" | "Low" | "Info"
  title: string
  source: "Passive" | "Canary" | "Imported Scanner" | "Browser"
  evidence: string
  description: string
  owasp?: string
  cwe?: string
  remediation?: string
  codePatch?: {
    framework: string
    code: string
  }[]
  retestStatus?: "Fixed" | "Still Present" | "Not Comparable"
}

export interface CanaryResult {
  ok: boolean
  domHtml?: string
  token?: string
  url?: string
  paramName?: string
  error?: string
}

export interface AdvisorResult {
  ok: boolean
  response?: string
  error?: string
}

export interface OllamaStatusResult {
  ready: boolean
  models: string[]
  error?: string
}

declare global {
  interface Window {
    sentinelDesktop?: {
      configureBrowser: (originOrPayload: string | { origin: string; mode?: string; consent?: boolean }) => Promise<{ ok: boolean; origin?: string; mode?: string; error?: string }>
      navigateBrowser: (url: string) => Promise<{ ok: boolean; error?: string }>
      setBrowserBounds: (bounds: { x: number; y: number; width: number; height: number }) => void
      hideBrowser: () => void
      onBrowserNavigated: (callback: (payload: { url: string }) => void) => () => void
      startRecording: () => Promise<{ ok: boolean; error?: string }>
      stopRecording: () => Promise<{ ok: boolean; count?: number; error?: string }>
      getEvidence: () => Promise<{ ok: boolean; evidence: EvidenceRecord[]; error?: string }>
      clearEvidence: () => Promise<{ ok: boolean; error?: string }>
      addEvidence: (record: Partial<EvidenceRecord>) => Promise<{ ok: boolean; record?: EvidenceRecord; error?: string }>
      injectCanary: (payload: { url: string; paramName?: string; token: string }) => Promise<CanaryResult>
      queryAdvisor: (payload: { prompt: string; model?: string; host?: string }) => Promise<AdvisorResult>
      checkOllamaStatus: (options?: { host?: string }) => Promise<OllamaStatusResult>
      onEvidence: (callback: (record: EvidenceRecord) => void) => () => void
      onEvidenceCleared: (callback: () => void) => () => void
    }
  }
}
