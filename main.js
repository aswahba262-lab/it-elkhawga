const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { execFile, execFileSync } = require('child_process');

let mainWindow;
let isBlocked = false;

// Packaged builds ship config/sites/scripts as extraResources next to app.asar,
// NOT inside it - app.asar is read-only and __dirname points inside it once packaged.
// Using resourcesPath here is the fix; the old code used __dirname unconditionally,
// which silently failed to read/write anything after install.
const basePath = app.isPackaged ? process.resourcesPath : __dirname;

const configPath = path.join(basePath, 'config.json');
const allowedSitesPath = path.join(basePath, 'allowed-sites.txt');
const blockedSitesPath = path.join(basePath, 'blocked-sites.txt');
const logPath = path.join(basePath, 'blocked-attempts.log');
const blockScriptPath = path.join(basePath, 'block-internet.ps1');
const allowScriptPath = path.join(basePath, 'allow-internet.ps1');
const enableAutostartScriptPath = path.join(basePath, 'enable-autostart.ps1');
const disableAutostartScriptPath = path.join(basePath, 'disable-autostart.ps1');
const buildModePath = path.join(basePath, 'build-mode.json');

// APP_MODE env var (used by `npm run start:client`) takes priority over the
// build-mode.json baked in at build time, which in turn defaults to 'admin'.
function readAppMode() {
  if (process.env.APP_MODE === 'admin' || process.env.APP_MODE === 'client') {
    return process.env.APP_MODE;
  }
  try {
    const raw = JSON.parse(fs.readFileSync(buildModePath, 'utf8'));
    if (raw.mode === 'admin' || raw.mode === 'client') return raw.mode;
  } catch (error) {
    // fall through to default
  }
  return 'admin';
}

const appMode = readAppMode();
const isAdmin = appMode === 'admin';

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 900,
    height: 700,
    minWidth: 800,
    minHeight: 600,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      devTools: isAdmin,
      preload: path.join(__dirname, 'preload.js')
    },
    title: isAdmin ? 'Internet Blocker Pro - Admin' : 'Internet Blocker Pro'
  });

  mainWindow.loadFile(isAdmin ? 'index.html' : 'client.html');
  mainWindow.setMenuBarVisibility(false);

  checkStatus();
}

// Check if internet is blocked by reading the proxy registry key.
// The old regex matched on exact column spacing from `reg query` output,
// which varies by Windows locale/version and silently always read as "unblocked".
function checkStatus() {
  try {
    const proxyReg = execFileSync('reg', [
      'query',
      'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings',
      '/v',
      'ProxyEnable'
    ], { encoding: 'utf8' });

    const match = proxyReg.match(/ProxyEnable\s+REG_DWORD\s+0x([0-9a-fA-F]+)/);
    isBlocked = !!match && parseInt(match[1], 16) === 1;

    if (mainWindow) {
      mainWindow.webContents.send('status-update', isBlocked);
    }
  } catch (error) {
    isBlocked = false;
    if (mainWindow) {
      mainWindow.webContents.send('status-update', false);
    }
  }
}

// Run a PowerShell script elevated (UAC), optionally feeding it a password.
// The password is NEVER interpolated into a command line/string - it's written
// to a short-lived temp file and the script reads it with -PasswordFile. The
// previous implementation built a `powershell -Command "..."` string by
// concatenating paths/values directly, which is a command-injection bug
// waiting to happen the moment any interpolated value contains a quote.
function runScriptAsAdmin(scriptPath, password) {
  return new Promise((resolve, reject) => {
    let passwordFile = null;
    let scriptArgs = `-ExecutionPolicy Bypass -File "${scriptPath}"`;

    if (password) {
      passwordFile = path.join(app.getPath('temp'), `ibp-${crypto.randomBytes(8).toString('hex')}.tmp`);
      fs.writeFileSync(passwordFile, password, { encoding: 'utf8', mode: 0o600 });
      scriptArgs += ` -PasswordFile "${passwordFile}"`;
    }

    const innerCommand = `Start-Process powershell -ArgumentList '${scriptArgs.replace(/'/g, "''")}' -Verb RunAs -Wait`;
    const encodedCommand = Buffer.from(innerCommand, 'utf16le').toString('base64');

    const cleanup = () => {
      if (passwordFile) {
        fs.unlink(passwordFile, () => {});
      }
    };

    execFile('powershell', ['-NoProfile', '-EncodedCommand', encodedCommand], (error) => {
      cleanup();
      if (error) {
        reject(error);
        return;
      }
      setTimeout(() => {
        checkStatus();
        resolve(true);
      }, 1000);
    });
  });
}

function readAllowedSites() {
  try {
    const content = fs.readFileSync(allowedSitesPath, 'utf8');
    return content.split('\n')
      .map(line => line.trim())
      .filter(line => line && !line.startsWith('#'));
  } catch (error) {
    return [];
  }
}

function writeAllowedSites(sites) {
  const content = '# Allowed Sites\n# Auto-generated by Internet Blocker Pro\n\n' + sites.join('\n') + '\n';
  fs.writeFileSync(allowedSitesPath, content, 'utf8');
}

function readBlockedSites() {
  try {
    const content = fs.readFileSync(blockedSitesPath, 'utf8');
    return content.split('\n')
      .map(line => line.trim())
      .filter(line => line && !line.startsWith('#'));
  } catch (error) {
    return [];
  }
}

function readConfig() {
  try {
    return JSON.parse(fs.readFileSync(configPath, 'utf8'));
  } catch (error) {
    return { mode: 'whitelist', password_hash: '', log_file: 'blocked-attempts.log', auto_start: true };
  }
}

function writeConfig(config) {
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2), 'utf8');
}

// Actual action log - nothing in the old code ever wrote to blocked-attempts.log,
// so the "attempt log" advertised in the README never had any content.
function logAction(message) {
  try {
    const line = `[${new Date().toISOString()}] ${message}\n`;
    fs.appendFileSync(logPath, line, 'utf8');
  } catch (error) {
    // best-effort logging only
  }
}

function readLogs() {
  try {
    if (fs.existsSync(logPath)) {
      return fs.readFileSync(logPath, 'utf8');
    }
  } catch (error) {
    return '';
  }
  return '';
}

function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

// IPC handlers available to both admin and client builds
ipcMain.handle('get-status', () => {
  checkStatus();
  return isBlocked;
});

ipcMain.handle('get-mode', () => appMode);

ipcMain.handle('get-allowed-sites', () => readAllowedSites());

ipcMain.handle('get-logs', () => (isAdmin ? readLogs() : ''));

ipcMain.handle('block-internet', async () => {
  try {
    await runScriptAsAdmin(blockScriptPath);
    logAction('BLOCK internet - success');
    return { success: true };
  } catch (error) {
    logAction(`BLOCK internet - failed: ${error.message}`);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('unblock-internet', async (event, password) => {
  try {
    await runScriptAsAdmin(allowScriptPath, password);
    logAction('UNBLOCK internet - success');
    return { success: true };
  } catch (error) {
    logAction(`UNBLOCK internet - failed (wrong password or cancelled): ${error.message}`);
    return { success: false, error: error.message };
  }
});

// Admin-only handlers. These are only *registered* in admin mode, so a client
// build has no IPC channel to reach them at all, even from devtools.
if (isAdmin) {
  ipcMain.handle('get-blocked-sites', () => readBlockedSites());

  ipcMain.handle('add-site', (event, site) => {
    const sites = readAllowedSites();
    const clean = String(site || '').trim();
    if (clean && !sites.includes(clean)) {
      sites.push(clean);
      writeAllowedSites(sites);
      logAction(`Site added to allowlist: ${clean}`);
    }
    return sites;
  });

  ipcMain.handle('remove-site', (event, site) => {
    let sites = readAllowedSites();
    sites = sites.filter(s => s !== site);
    writeAllowedSites(sites);
    logAction(`Site removed from allowlist: ${site}`);
    return sites;
  });

  ipcMain.handle('get-config', () => {
    const config = readConfig();
    return {
      mode: config.mode || 'whitelist',
      auto_start: !!config.auto_start,
      has_password: !!config.password_hash
    };
  });

  ipcMain.handle('set-list-mode', (event, mode) => {
    if (mode !== 'whitelist' && mode !== 'blacklist') {
      return { success: false, error: 'Invalid mode' };
    }
    const config = readConfig();
    config.mode = mode;
    writeConfig(config);
    logAction(`List mode changed to: ${mode}`);
    return { success: true };
  });

  ipcMain.handle('toggle-autostart', async (event, enable) => {
    try {
      const scriptPath = enable ? enableAutostartScriptPath : disableAutostartScriptPath;
      await runScriptAsAdmin(scriptPath);
      const config = readConfig();
      config.auto_start = !!enable;
      writeConfig(config);
      logAction(`Autostart ${enable ? 'enabled' : 'disabled'}`);
      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  });

  // Changing the password now requires the current one (if any is set).
  // The old handler accepted any new password with no verification at all,
  // meaning anyone with the app open (including the employee it's meant to
  // restrict) could silently overwrite the admin password.
  ipcMain.handle('set-password', (event, { currentPassword, newPassword }) => {
    try {
      const config = readConfig();

      if (config.password_hash) {
        if (!currentPassword || hashPassword(currentPassword) !== config.password_hash) {
          return { success: false, error: 'Current password is incorrect' };
        }
      }

      if (!newPassword || newPassword.length < 4) {
        return { success: false, error: 'Password too short' };
      }

      config.password_hash = hashPassword(newPassword);
      writeConfig(config);
      logAction('Password changed');
      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  });
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});
