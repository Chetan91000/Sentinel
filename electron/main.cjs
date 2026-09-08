const { app, BrowserWindow, WebContentsView, ipcMain, session } = require('electron')
const path = require('node:path')
const fs = require('node:fs')

let mainWindow
let browserView
let allowedOrigin = null
let isRecording = false
let evidenceStore = []
const evidenceFilePath = path.join(__dirname, '..', 'evidence.json')

function loadEvidence() {
  try {
    if (fs.existsSync(evidenceFilePath)) {
      const data = fs.readFileSync(evidenceFilePath, 'utf8')
      evidenceStore = JSON.parse(data)
    }
  } catch {
    evidenceStore = []
  }
}

function saveEvidence() {
  try {
    fs.writeFileSync(evidenceFilePath, JSON.stringify(evidenceStore, null, 2))
  } catch (error) {
    console.error('Failed to save evidence:', error)
  }
}

function generateId() {
  return 'EV-' + Date.now().toString(36) + Math.random().toString(36).substr(2, 5)
}

function addEvidence(event) {
  const record = {
    id: generateId(),
    timestamp: new Date().toISOString(),
    ...event
  }
  evidenceStore.push(record)
  saveEvidence()
  if (mainWindow) {
    mainWindow.webContents.send('evidence:new', record)
  }
  return record
}

function clearEvidence() {
  evidenceStore = []
  saveEvidence()
  if (mainWindow) {
    mainWindow.webContents.send('evidence:cleared')
  }
}

function isAllowed(url) {
  try {
    return new URL(url).origin === allowedOrigin
  } catch {
    return false
  }
}

function isAllowed(url) {
  try {
    return new URL(url).origin === allowedOrigin
  } catch {
    return false
  }
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1080,
    minHeight: 720,
    backgroundColor: '#0d1116',
    show: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  })

  mainWindow.once('ready-to-show', () => mainWindow.show())
  mainWindow.on('closed', () => { mainWindow = null; browserView = null })

  const rendererUrl = !app.isPackaged ? 'http://127.0.0.1:5173' : null
  if (rendererUrl) mainWindow.loadURL(rendererUrl)
  else mainWindow.loadFile(path.join(__dirname, '..', 'dist', 'index.html'))
}

function createBrowserView() {
  if (browserView || !mainWindow) return
  browserView = new WebContentsView({
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  })
  mainWindow.contentView.addChildView(browserView)
  browserView.setBounds({ x: 0, y: 0, width: 1, height: 1 })
  browserView.webContents.setWindowOpenHandler(() => ({ action: 'deny' }))
  browserView.webContents.on('will-navigate', (event, url) => {
    if (!isAllowed(url)) event.preventDefault()
  })
  browserView.webContents.on('did-navigate', (_event, url) => {
    mainWindow?.webContents.send('browser:navigated', { url })
    if (isRecording) {
      addEvidence({ kind: 'NAV', label: 'Navigation', detail: url, source: 'browser' })
    }
  })

  browserView.webContents.on('console-message', (_event, level, message, line, sourceId) => {
    if (isRecording) {
      addEvidence({
        kind: 'CONSOLE',
        label: `Console ${level}`,
        detail: message,
        source: 'browser',
        meta: { level, line, sourceId }
      })
    }
  })

  const filter = { urls: [`${allowedOrigin}/*`] }
  session.defaultSession.webRequest.onBeforeRequest(filter, (details, callback) => {
    if (isRecording) {
      addEvidence({
        kind: 'REQ',
        label: 'Request sent',
        detail: `${details.method} ${details.url}`,
        source: 'network',
        meta: { method: details.method, url: details.url, resourceType: details.resourceType }
      })
    }
    callback({ cancel: false })
  })

  session.defaultSession.webRequest.onHeadersReceived(filter, (details, callback) => {
    if (isRecording) {
      const headers = details.responseHeaders || {}
      addEvidence({
        kind: 'RES',
        label: 'Response headers',
        detail: `${details.statusCode} ${details.url}`,
        source: 'network',
        meta: { statusCode: details.statusCode, url: details.url, headers }
      })
    }
    callback({ cancel: false, responseHeaders: details.responseHeaders })
  })

  session.defaultSession.webRequest.onCompleted(filter, (details) => {
    if (isRecording) {
      addEvidence({
        kind: 'RES_DONE',
        label: 'Response complete',
        detail: `${details.statusCode} ${details.url}`,
        source: 'network',
        meta: { statusCode: details.statusCode, url: details.url, resourceType: details.resourceType }
      })
    }
  })

  session.defaultSession.webRequest.onErrorOccurred(filter, (details) => {
    if (isRecording) {
      addEvidence({
        kind: 'ERR',
        label: 'Request error',
        detail: `${details.error} ${details.url}`,
        source: 'network',
        meta: { error: details.error, url: details.url }
      })
    }
  })
}

function setBounds(bounds) {
  if (!browserView || !mainWindow) return
  const windowBounds = mainWindow.getContentBounds()
  browserView.setBounds({
    x: Math.max(0, Math.round(bounds.x)),
    y: Math.max(0, Math.round(bounds.y)),
    width: Math.max(1, Math.round(Math.min(bounds.width, windowBounds.width - bounds.x))),
    height: Math.max(1, Math.round(Math.min(bounds.height, windowBounds.height - bounds.y))),
  })
}

ipcMain.handle('browser:configure', (_event, origin) => {
  try {
    const parsed = new URL(origin)
    if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('Only HTTP and HTTPS origins are supported')
    allowedOrigin = parsed.origin
    createBrowserView()
    return { ok: true, origin: allowedOrigin }
  } catch (error) {
    return { ok: false, error: error.message }
  }
})

ipcMain.handle('browser:navigate', (_event, url) => {
  if (!browserView || !isAllowed(url)) return { ok: false, error: 'Navigation blocked by the origin allowlist.' }
  browserView.webContents.loadURL(url)
  return { ok: true }
})

ipcMain.handle('recording:start', () => {
  if (!browserView) return { ok: false, error: 'Browser not configured' }
  isRecording = true
  clearEvidence()
  addEvidence({ kind: 'REC', label: 'Recording started', detail: allowedOrigin, source: 'system' })
  return { ok: true }
})

ipcMain.handle('recording:stop', () => {
  isRecording = false
  addEvidence({ kind: 'REC', label: 'Recording stopped', detail: allowedOrigin, source: 'system' })
  return { ok: true, count: evidenceStore.length }
})

ipcMain.handle('evidence:get', () => ({ ok: true, evidence: evidenceStore }))

ipcMain.handle('evidence:clear', () => {
  clearEvidence()
  return { ok: true }
})

ipcMain.on('browser:set-bounds', (_event, bounds) => setBounds(bounds))
ipcMain.on('browser:hide', () => browserView?.setBounds({ x: 0, y: 0, width: 1, height: 1 }))

app.whenReady().then(() => {
  session.defaultSession.setPermissionRequestHandler((_webContents, _permission, callback) => callback(false))
  createWindow()
  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow() })
})

app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit() })