# Sentinel Desktop

A local, evidence-first browser security assistant for applications you own or are authorized to test.

## Requirements

- **Node.js** (v18 or higher recommended)
- **npm** (comes with Node.js)
- Operating System: Windows, macOS, or Linux (Electron compatible)

## Run

```powershell
npm install
npm run dev
```

The first milestone includes consent onboarding, origin validation, a recording state, passive finding cards, an evidence timeline, and redacted JSON export. Electron browser instrumentation comes next.

Sentinel does not generate exploit payloads, perform brute force, or visit hosts outside an approved origin.
