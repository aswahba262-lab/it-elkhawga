// Writes build-mode.json so main.js knows whether it is the admin or client build.
// Run automatically by the build:admin / build:client / start:admin / start:client npm scripts.
const fs = require('fs');
const path = require('path');

const mode = process.argv[2];

if (mode !== 'admin' && mode !== 'client') {
  console.error('Usage: node scripts/set-mode.js <admin|client>');
  process.exit(1);
}

const target = path.join(__dirname, '..', 'build-mode.json');
fs.writeFileSync(target, JSON.stringify({ mode }, null, 2) + '\n', 'utf8');
console.log(`build-mode.json set to "${mode}"`);
