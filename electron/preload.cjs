const { contextBridge, ipcRenderer } = require('electron')

contextBridge.exposeInMainWorld('sentinelDesktop', {
  configureBrowser: (payload) => ipcRenderer.invoke('browser:configure', payload),
  navigateBrowser: (url) => ipcRenderer.invoke('browser:navigate', url),
  setBrowserBounds: (bounds) => ipcRenderer.send('browser:set-bounds', bounds),
  hideBrowser: () => ipcRenderer.send('browser:hide'),
  onBrowserNavigated: (callback) => {
    const listener = (_event, payload) => callback(payload)
    ipcRenderer.on('browser:navigated', listener)
    return () => ipcRenderer.removeListener('browser:navigated', listener)
  },
  startRecording: () => ipcRenderer.invoke('recording:start'),
  stopRecording: () => ipcRenderer.invoke('recording:stop'),
  getEvidence: () => ipcRenderer.invoke('evidence:get'),
  clearEvidence: () => ipcRenderer.invoke('evidence:clear'),
  addEvidence: (record) => ipcRenderer.invoke('evidence:add', record),
  onEvidence: (callback) => {
    const listener = (_event, payload) => callback(payload)
    ipcRenderer.on('evidence:new', listener)
    return () => ipcRenderer.removeListener('evidence:new', listener)
  },
  onEvidenceCleared: (callback) => {
    const listener = () => callback()
    ipcRenderer.on('evidence:cleared', listener)
    return () => ipcRenderer.removeListener('evidence:cleared', listener)
  },
  injectCanary: (payload) => ipcRenderer.invoke('canary:inject', payload),
  queryAdvisor: (payload) => ipcRenderer.invoke('advisor:query', payload),
  checkOllamaStatus: (payload) => ipcRenderer.invoke('ollama:status', payload),
})
