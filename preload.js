const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  getStatus: () => ipcRenderer.invoke('get-status'),
  getMode: () => ipcRenderer.invoke('get-mode'),
  blockInternet: () => ipcRenderer.invoke('block-internet'),
  unblockInternet: (password) => ipcRenderer.invoke('unblock-internet', password),
  getAllowedSites: () => ipcRenderer.invoke('get-allowed-sites'),
  getBlockedSites: () => ipcRenderer.invoke('get-blocked-sites'),
  addSite: (site) => ipcRenderer.invoke('add-site', site),
  removeSite: (site) => ipcRenderer.invoke('remove-site', site),
  getLogs: () => ipcRenderer.invoke('get-logs'),
  getConfig: () => ipcRenderer.invoke('get-config'),
  setListMode: (mode) => ipcRenderer.invoke('set-list-mode', mode),
  toggleAutostart: (enable) => ipcRenderer.invoke('toggle-autostart', enable),
  setPassword: (currentPassword, newPassword) => ipcRenderer.invoke('set-password', { currentPassword, newPassword }),
  onStatusUpdate: (callback) => ipcRenderer.on('status-update', (event, isBlocked) => callback(isBlocked))
});
