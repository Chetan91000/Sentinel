declare global {
  interface Window {
    sentinelDesktop?: {
      configureBrowser: (origin: string) => Promise<{ ok: boolean; origin?: string; error?: string }>
      navigateBrowser: (url: string) => Promise<{ ok: boolean; error?: string }>
      setBrowserBounds: (bounds: { x: number; y: number; width: number; height: number }) => void
      hideBrowser: () => void
      onBrowserNavigated: (callback: (payload: { url: string }) => void) => () => void
      startRecording: () => Promise<{ ok: boolean; error?: string }>
      stopRecording: () => Promise<{ ok: boolean; count?: number; error?: string }>
      getEvidence: () => Promise<{ ok: boolean; evidence: EvidenceRecord[]; error?: string }>
      clearEvidence: () => Promise<{ ok: boolean; error?: string }>
      onEvidence: (callback: (record: EvidenceRecord) => void) => () => void
      onEvidenceCleared: (callback: () => void) => () => void
    }
  }
}

interface EvidenceRecord {
  id: string
  timestamp: string
  kind: string
  label: string
  detail: string
  source: string
  meta?: Record<string, unknown>
}

export {}