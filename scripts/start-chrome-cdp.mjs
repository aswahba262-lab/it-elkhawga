import { spawn } from 'node:child_process';
import http from 'node:http';
import fs from 'node:fs';

fs.mkdirSync('C:\\temp\\chrome-cdp', { recursive: true });

const chrome = spawn('C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', [
  '--headless=new',
  '--remote-debugging-port=9222',
  '--remote-allow-origins=*',
  '--user-data-dir=C:\\temp\\chrome-cdp',
  '--window-size=1280,900',
  'http://localhost:3000'
]);

chrome.on('exit', (code) => {
  console.log('Chrome exited with code', code);
  process.exit(code || 0);
});

const check = () => {
  http.get('http://127.0.0.1:9222/json/version', (res) => {
    let data = '';
    res.on('data', chunk => data += chunk);
    res.on('end', () => {
      try {
        const json = JSON.parse(data);
        const wsUrl = new URL(json.webSocketDebuggerUrl);
        const portFile = '9222\n' + wsUrl.pathname + '\n';
        fs.writeFileSync('C:\\Users\\IT APP\\AppData\\Local\\Google\\Chrome\\User Data\\DevToolsActivePort', portFile, { encoding: 'ascii' });
        console.log('Chrome CDP ready! Wrote DevToolsActivePort:');
        console.log(portFile);
      } catch (e) {
        console.error('Parse error:', e);
      }
    });
  }).on('error', () => {
    setTimeout(check, 300);
  });
};

check();
