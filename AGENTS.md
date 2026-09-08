# AGENTS — Sentinel Desktop

## Commands

| Script | Description |
|---|---|
| `npm run dev` | Starts Vite dev server + Electron (`vite --host 127.0.0.1` then `wait-on http://127.0.0.1:5173 && electron .`) |
| `npm run build` | `tsc -b && vite build` — type-check + bundle |
| `npm run preview` | `vite preview` — serve production build locally |
| `npm run desktop` | `electron .` — run Electron only (no Vite) |

## Architecture

- **React + Vite + TypeScript** in `src/`. Entry: `src/main.tsx` → renders `src/App.tsx` into `#root`.
- **Electron** runs the React app in a desktop window. `src/desktop.d.ts` exposes `window.sentinelDesktop` API with methods: `configureBrowser`, `navigateBrowser`, `setBrowserBounds`, `hideBrowser`, `onBrowserNavigated`.
- **TypeScript** config: `tsc -b` uses `tsconfig.app.json` (ES2022, strict, react-jsx) and `tsconfig.node.json` (ES2023).
- No test framework or lint scripts are configured. `tsc -b` is the only type-check step.
- Build output goes to `dist/` (Vite) and `.ts` → `.cjs` via TypeScript.

## Onboarding flow

App requires three things before session starts (see `src/App.tsx:30-38`):
1. **Name** — non-empty string
2. **URL** — valid `http:` or `https:` URL
3. **Consent** — checkbox must be checked

Failing any of these sets a notice. After all three are met, `createSession()` locks the origin and launches the browser via `window.sentinelDesktop?.configureBrowser(origin).then(...).then(...)`.

## Export

`src/App.tsx:44-47` — `exportSession()` creates a `sentinel-session.json` with redacted session data (name, origin, timestamp, events, findings). Downloads via anchor click.

## Gotchas

- `dev` script runs two commands concurrently; killing the terminal may leave processes running.
- `tsc -b` uses build references (`tsconfig.json` → `tsconfig.app.json` + `tsconfig.node.json`); editing tsconfigs requires a full rebuild.
- Electron preload script (`electron/preload.cjs`) is not detailed here — inspect it if `window.sentinelDesktop` behaves unexpectedly.