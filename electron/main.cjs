const { app, BrowserWindow, WebContentsView, ipcMain, session } = require('electron')
const path = require('node:path')
const fs = require('node:fs')
const crypto = require('node:crypto')
const http = require('node:http')

let mainWindow
let browserView
let allowedOrigin = null
let sessionMode = 'inspect' // 'inspect' | 'own-app'
let isRecording = false
let evidenceStore = []
let cdpAttached = false
let saveTimeout = null

const evidenceFilePath = path.join(__dirname, '..', 'evidence.json')
const archiveDir = path.join(__dirname, '..', '.kilo', 'archives')
const MAX_EVIDENCE_STORE_SIZE = 1000 // Rotate when store exceeds 1000 events

function ensureDirectory(dir) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true })
  }
}

function loadEvidence() {
  try {
    if (fs.existsSync(evidenceFilePath)) {
      const data = fs.readFileSync(evidenceFilePath, 'utf8')
      const parsed = JSON.parse(data)
      evidenceStore = Array.isArray(parsed) ? parsed : (parsed.evidence || [])
    }
  } catch {
    evidenceStore = []
  }
}

function rotateEvidenceStoreIfNeeded() {
  if (evidenceStore.length > MAX_EVIDENCE_STORE_SIZE) {
    try {
      ensureDirectory(archiveDir)
      const archivePath = path.join(archiveDir, `evidence-${Date.now()}.json`)
      fs.writeFileSync(archivePath, JSON.stringify(evidenceStore, null, 2))
      // Retain the latest 200 records in memory
      evidenceStore = evidenceStore.slice(-200)
    } catch (err) {
      console.error('Failed to rotate evidence store:', err)
    }
  }
}

function saveEvidenceDebounced() {
  if (saveTimeout) clearTimeout(saveTimeout)
  saveTimeout = setTimeout(() => {
    try {
      rotateEvidenceStoreIfNeeded()
      const payload = {
        meta: {
          zeroPayloadConfirmation: true,
          ephemeralPartitionVerified: true,
          mode: sessionMode,
          origin: allowedOrigin,
          savedAt: new Date().toISOString(),
          recordCount: evidenceStore.length,
        },
        evidence: evidenceStore,
      }
      fs.writeFileSync(evidenceFilePath, JSON.stringify(payload, null, 2))
    } catch (error) {
      console.error('Failed to save evidence:', error)
    }
  }, 250)
}

function generateId(prefix = 'EV') {
  return `${prefix}-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).substr(2, 5).toUpperCase()}`
}

function redactSensitiveData(data) {
  if (!data) return data
  if (typeof data === 'string') {
    return data
      .replace(/(bearer\s+)[a-zA-Z0-9_\-\.]{10,}/gi, '$1[REDACTED]')
      .replace(/(api[_-]?key\s*[:=]\s*)[a-zA-Z0-9_\-\.]{8,}/gi, '$1[REDACTED]')
      .replace(/(password\s*[:=]\s*)[^\s&]{4,}/gi, '$1[REDACTED]')
      .replace(/(secret\s*[:=]\s*)[^\s&]{4,}/gi, '$1[REDACTED]')
  }
  return data
}

function redactHeaders(rawHeaders) {
  if (!rawHeaders || typeof rawHeaders !== 'object') return rawHeaders
  const redacted = {}
  for (const [key, value] of Object.entries(rawHeaders)) {
    const lowerKey = key.toLowerCase()
    if (['authorization', 'proxy-authorization', 'x-api-key'].includes(lowerKey)) {
      redacted[key] = ['[REDACTED]']
    } else if (lowerKey === 'cookie') {
      const cookies = Array.isArray(value) ? value : [String(value)]
      redacted[key] = cookies.map((headerStr) => {
        // Redact each cookie value in a Cookie request header
        return headerStr
          .split(';')
          .map((pair) => {
            const trimmed = pair.trim()
            const eqIdx = trimmed.indexOf('=')
            if (eqIdx === -1) return trimmed
            const cName = trimmed.substring(0, eqIdx).trim()
            const cVal = trimmed.substring(eqIdx + 1).trim()
            const maskedVal = cVal.length > 4 ? `[REDACTED_${cVal.length}chars]` : '[REDACTED]'
            return `${cName}=${maskedVal}`
          })
          .join('; ')
      })
    } else if (lowerKey === 'set-cookie') {
      const cookies = Array.isArray(value) ? value : [String(value)]
      redacted[key] = cookies.map((c) => {
        // Preserve cookie structure/attributes for security analysis, redact token values
        const parts = c.split(';')
        if (parts.length === 0) return c
        const [nameVal, ...attrs] = parts
        const eqIdx = nameVal.indexOf('=')
        if (eqIdx === -1) return nameVal
        const cookieName = nameVal.substring(0, eqIdx).trim()
        const cookieVal = nameVal.substring(eqIdx + 1).trim()
        const maskedVal = cookieVal.length > 4 ? `[REDACTED_${cookieVal.length}chars]` : '[REDACTED]'
        return [`${cookieName}=${maskedVal}`, ...attrs].join('; ')
      })
    } else {
      redacted[key] = value
    }
  }
  return redacted
}

function computeHash(payload) {
  try {
    return crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex')
  } catch {
    return ''
  }
}

function addEvidence(event) {
  const normalizedDetail = redactSensitiveData(event.detail || '')
  const normalizedMeta = event.meta ? JSON.parse(JSON.stringify(event.meta)) : undefined
  if (normalizedMeta?.headers) {
    normalizedMeta.headers = redactHeaders(normalizedMeta.headers)
  }

  const record = {
    id: event.id || generateId(),
    timestamp: event.timestamp || new Date().toISOString(),
    kind: event.kind,
    label: event.label,
    detail: normalizedDetail,
    source: event.source,
    hash: computeHash({ kind: event.kind, detail: normalizedDetail, meta: normalizedMeta }),
    meta: normalizedMeta,
  }

  evidenceStore.push(record)
  saveEvidenceDebounced()

  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('evidence:new', record)
  }
  return record
}

function clearEvidence() {
  evidenceStore = []
  saveEvidenceDebounced()
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('evidence:cleared')
  }
}

function isAllowed(url) {
  try {
    if (!allowedOrigin) return false
    const parsed = new URL(url)
    return parsed.origin === allowedOrigin
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
  mainWindow.on('closed', () => {
    mainWindow = null
    browserView = null
    cdpAttached = false
  })

  const rendererUrl = !app.isPackaged ? 'http://127.0.0.1:5173' : null
  if (rendererUrl) mainWindow.loadURL(rendererUrl)
  else mainWindow.loadFile(path.join(__dirname, '..', 'dist', 'index.html'))
}

function attachCdpDebugger() {
  if (!browserView || cdpAttached) return
  try {
    const webContents = browserView.webContents
    if (webContents.isDestroyed()) return

    webContents.debugger.attach('1.3')
    cdpAttached = true

    webContents.debugger.on('detach', () => {
      cdpAttached = false
    })

    webContents.debugger.on('message', (_event, method, params) => {
      if (!isRecording) return

      if (method === 'Runtime.consoleAPICalled') {
        const textArgs = (params.args || []).map((a) => a.value || a.description || '').join(' ')
        addEvidence({
          kind: 'CONSOLE',
          label: `Console ${params.type}`,
          detail: textArgs,
          source: 'browser',
          meta: {
            level: params.type,
            stackTrace: params.stackTrace,
            timestamp: params.timestamp,
          },
        })
      } else if (method === 'Runtime.exceptionThrown') {
        addEvidence({
          kind: 'CONSOLE',
          label: 'Uncaught Exception',
          detail: params.exceptionDetails?.text || params.exceptionDetails?.exception?.description || 'Runtime error',
          source: 'browser',
          meta: {
            level: 'error',
            exceptionDetails: params.exceptionDetails,
          },
        })
      } else if (method === 'Network.webSocketFrameSent') {
        addEvidence({
          kind: 'REQ',
          label: 'WebSocket Frame Sent',
          detail: `WS -> ${params.response?.payloadData?.slice(0, 80) || '[Frame]'}`,
          source: 'network',
          meta: { opcode: params.response?.opcode, mask: params.response?.mask },
        })
      } else if (method === 'Network.webSocketFrameReceived') {
        addEvidence({
          kind: 'RES',
          label: 'WebSocket Frame Received',
          detail: `WS <- ${params.response?.payloadData?.slice(0, 80) || '[Frame]'}`,
          source: 'network',
          meta: { opcode: params.response?.opcode },
        })
      }
    })

    webContents.debugger.sendCommand('Runtime.enable').catch(() => {})
    webContents.debugger.sendCommand('Network.enable').catch(() => {})
  } catch (err) {
    console.error('CDP Debugger attach error:', err.message)
    cdpAttached = false
  }
}

function createBrowserView() {
  if (browserView || !mainWindow) return

  const labSession = session.fromPartition('in-memory-lab', { cache: false })
  labSession.setPermissionRequestHandler((_webContents, _permission, callback) => callback(false))
  labSession.on('will-download', (event) => event.preventDefault())

  browserView = new WebContentsView({
    webPreferences: {
      partition: 'in-memory-lab',
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  })

  mainWindow.contentView.addChildView(browserView)
  browserView.setBounds({ x: 0, y: 0, width: 1, height: 1 })
  browserView.webContents.setWindowOpenHandler(() => ({ action: 'deny' }))

  browserView.webContents.on('will-navigate', (event, url) => {
    if (!isAllowed(url)) {
      event.preventDefault()
    }
  })

  browserView.webContents.on('will-redirect', (event, url) => {
    if (!isAllowed(url)) {
      event.preventDefault()
    }
  })

  browserView.webContents.on('did-navigate', (_event, url) => {
    mainWindow?.webContents.send('browser:navigated', { url })
    if (isRecording) {
      addEvidence({ kind: 'NAV', label: 'Navigation', detail: url, source: 'browser' })
    }
  })

  // Network interception on isolated labSession
  const filter = { urls: [`${allowedOrigin}/*`] }

  labSession.webRequest.onBeforeRequest(filter, (details, callback) => {
    if (isRecording) {
      addEvidence({
        kind: 'REQ',
        label: 'Request sent',
        detail: `${details.method} ${details.url}`,
        source: 'network',
        meta: { method: details.method, url: details.url, resourceType: details.resourceType },
      })
    }
    callback({ cancel: false })
  })

  labSession.webRequest.onHeadersReceived(filter, (details, callback) => {
    if (isRecording) {
      const headers = details.responseHeaders || {}
      addEvidence({
        kind: 'RES',
        label: 'Response headers',
        detail: `${details.statusCode} ${details.url}`,
        source: 'network',
        meta: { statusCode: details.statusCode, url: details.url, headers },
      })
    }
    callback({ cancel: false, responseHeaders: details.responseHeaders })
  })

  labSession.webRequest.onCompleted(filter, (details) => {
    if (isRecording) {
      addEvidence({
        kind: 'RES_DONE',
        label: 'Response complete',
        detail: `${details.statusCode} ${details.url}`,
        source: 'network',
        meta: { statusCode: details.statusCode, url: details.url, resourceType: details.resourceType },
      })
    }
  })

  labSession.webRequest.onErrorOccurred(filter, (details) => {
    if (isRecording) {
      addEvidence({
        kind: 'ERR',
        label: 'Request error',
        detail: `${details.error} ${details.url}`,
        source: 'network',
        meta: { error: details.error, url: details.url },
      })
    }
  })

  // Automatically start recording when browser view is created so initial page load traffic is captured
  isRecording = true
  attachCdpDebugger()
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

function isLoopbackHost(hostUrl) {
  try {
    const parsed = new URL(hostUrl)
    return ['127.0.0.1', 'localhost', '::1', '[::1]'].includes(parsed.hostname.toLowerCase())
  } catch {
    return false
  }
}

// IPC Handlers
ipcMain.handle('browser:configure', (_event, payload) => {
  try {
    const rawOrigin = typeof payload === 'string' ? payload : payload?.origin
    const mode = typeof payload === 'object' && payload?.mode ? payload.mode : 'inspect'
    const consent = typeof payload === 'object' && payload?.consent ? Boolean(payload.consent) : false
    const parsed = new URL(rawOrigin)

    if (!['http:', 'https:'].includes(parsed.protocol)) {
      throw new Error('Only HTTP and HTTPS origins are supported')
    }

    allowedOrigin = parsed.origin
    sessionMode = mode
    loadEvidence()

    // Add Audit Consent log entry
    addEvidence({
      kind: 'AUDIT',
      label: 'Session Initialized',
      detail: `Mode: ${mode} | Origin: ${allowedOrigin} | User Consent: ${consent ? 'Granted' : 'Inspect-Only'}`,
      source: 'system',
      meta: { mode, origin: allowedOrigin, consent, timestamp: new Date().toISOString() },
    })

    // Always capture initial navigation upon session launch
    addEvidence({ kind: 'NAV', label: 'Session Launched', detail: allowedOrigin, source: 'browser' })

    createBrowserView()
    return { ok: true, origin: allowedOrigin, mode: sessionMode }
  } catch (error) {
    return { ok: false, error: error.message }
  }
})

ipcMain.handle('browser:navigate', (_event, url) => {
  if (!browserView || !isAllowed(url)) {
    return { ok: false, error: 'Navigation blocked: Destination is outside the locked origin allowlist.' }
  }
  browserView.webContents.loadURL(url)
  addEvidence({ kind: 'NAV', label: 'Navigation Requested', detail: url, source: 'browser' })
  return { ok: true }
})

ipcMain.handle('recording:start', () => {
  if (!browserView) return { ok: false, error: 'Browser not configured' }
  isRecording = true
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

ipcMain.handle('evidence:add', (_event, record) => {
  const stored = addEvidence(record)
  return { ok: true, record: stored }
})

// Canary execution handler
ipcMain.handle('canary:inject', async (_event, payload) => {
  if (!browserView || !allowedOrigin) {
    return { ok: false, error: 'Browser session is not active' }
  }

  const { url, paramName = '__sentinel_canary', token } = payload
  if (!isAllowed(url)) {
    return { ok: false, error: 'Canary target URL is outside the allowed origin' }
  }

  try {
    // Navigate browser to canary URL
    await browserView.webContents.loadURL(url)

    // Wait for DOM to settle
    await new Promise((resolve) => setTimeout(resolve, 800))

    // Read full DOM HTML safely from webContents
    const domHtml = await browserView.webContents.executeJavaScript(
      'document.documentElement.outerHTML',
      true
    )

    return { ok: true, domHtml, token, url, paramName }
  } catch (error) {
    return { ok: false, error: error.message }
  }
})

// Local AI Advisor handler (queries Ollama at 127.0.0.1:11434)
ipcMain.handle('advisor:query', async (_event, { prompt, model = 'llama3:latest', host = 'http://127.0.0.1:11434' }) => {
  return new Promise((resolve) => {
    try {
      if (!isLoopbackHost(host)) {
        return resolve({ ok: false, error: 'Access denied: AI Advisor host must be a local loopback address' })
      }
      const urlObj = new URL(host)
      const postData = JSON.stringify({
        model,
        prompt,
        stream: false,
        format: 'json',
        options: { temperature: 0.2 },
      })

      const req = http.request(
        {
          hostname: urlObj.hostname,
          port: urlObj.port || 11434,
          path: '/api/generate',
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(postData),
          },
          timeout: 20000,
        },
        (res) => {
          let rawBody = ''
          res.on('data', (chunk) => {
            rawBody += chunk
          })
          res.on('end', () => {
            if (res.statusCode >= 200 && res.statusCode < 300) {
              try {
                const parsed = JSON.parse(rawBody)
                resolve({ ok: true, response: parsed.response })
              } catch {
                resolve({ ok: false, error: 'Invalid JSON response from Ollama' })
              }
            } else {
              resolve({ ok: false, error: `Ollama returned HTTP ${res.statusCode}` })
            }
          })
        }
      )

      req.on('timeout', () => {
        req.destroy()
        resolve({ ok: false, error: 'Ollama request timed out after 20s' })
      })

      req.on('error', (err) => {
        resolve({ ok: false, error: `Could not connect to Ollama: ${err.message}` })
      })

      req.write(postData)
      req.end()
    } catch (err) {
      resolve({ ok: false, error: err.message })
    }
  })
})

// Ollama Status Check
ipcMain.handle('ollama:status', async (_event, { host = 'http://127.0.0.1:11434' } = {}) => {
  return new Promise((resolve) => {
    try {
      if (!isLoopbackHost(host)) {
        return resolve({ ready: false, models: [], error: 'Access denied: Host must be a local loopback address' })
      }
      const urlObj = new URL(host)
      const req = http.request(
        {
          hostname: urlObj.hostname,
          port: urlObj.port || 11434,
          path: '/api/tags',
          method: 'GET',
          timeout: 2500,
        },
        (res) => {
          let rawBody = ''
          res.on('data', (chunk) => {
            rawBody += chunk
          })
          res.on('end', () => {
            if (res.statusCode === 200) {
              try {
                const data = JSON.parse(rawBody)
                const models = Array.isArray(data.models) ? data.models.map((m) => m.name || m.model) : []
                resolve({ ready: true, models })
              } catch {
                resolve({ ready: false, models: [], error: 'Failed to parse Ollama model list' })
              }
            } else {
              resolve({ ready: false, models: [], error: `Ollama status ${res.statusCode}` })
            }
          })
        }
      )

      req.on('timeout', () => {
        req.destroy()
        resolve({ ready: false, models: [], error: 'Connection timed out' })
      })

      req.on('error', (err) => {
        resolve({ ready: false, models: [], error: err.message })
      })

      req.end()
    } catch (err) {
      resolve({ ready: false, models: [], error: err.message })
    }
  })
})

ipcMain.on('browser:set-bounds', (_event, bounds) => setBounds(bounds))
ipcMain.on('browser:hide', () => browserView?.setBounds({ x: 0, y: 0, width: 1, height: 1 }))

app.whenReady().then(() => {
  session.defaultSession.setPermissionRequestHandler((_webContents, _permission, callback) => callback(false))
  createWindow()
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
  })
})

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit()
})
