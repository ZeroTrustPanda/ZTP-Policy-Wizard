/**
 * ZTP Policy Wizard — standalone launcher.
 * Starts the wizard on 127.0.0.1 (this computer only), opens the default browser,
 * and keeps running until the window is closed or Ctrl+C is pressed.
 */
const net = require('net');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');

// The compiled UI is embedded in the executable
global.__ZTP_EMBEDDED_HTML__ = require('./dist/ui-bundle.js');

function freePort(start = 3000, end = 3020) {
  return new Promise((resolve) => {
    const tryPort = (p) => {
      const s = net.createServer();
      s.once('error', () => (p < end ? tryPort(p + 1) : resolve(0)));
      s.once('listening', () => s.close(() => resolve(p)));
      s.listen(p, '127.0.0.1');
    };
    tryPort(start);
  });
}

function openBrowser(url) {
  const done = (err) => { if (err) console.log(`  Could not open a browser automatically. Open ${url} yourself.`); };
  if (process.platform === 'win32') execFile('cmd', ['/c', 'start', '', url], { windowsHide: true }, done);
  else if (process.platform === 'darwin') execFile('open', [url], done);
  else execFile('xdg-open', [url], done);
}

(async () => {
  const port = Number(process.env.ZTP_PORT) || await freePort();
  process.env.ZTP_HOST = process.env.ZTP_HOST || '127.0.0.1';
  process.env.ZTP_PORT = String(port);
  process.env.ZTP_LOG_DIR = process.env.ZTP_LOG_DIR || path.join(os.homedir(), 'ZTP-Wizard', 'logs');

  global.__ZTP_ON_LISTEN__ = ({ host, port, version, logDir }) => {
    const url = `http://${host === '0.0.0.0' ? '127.0.0.1' : host}:${port}`;
    console.log('');
    console.log(`  ZTP Policy Wizard v${version} (standalone)`);
    console.log(`  Running at ${url}  (this computer only)`);
    console.log(`  Logs: ${logDir}`);
    console.log('');
    console.log('  Keep this window open while you use the wizard.');
    console.log('  Close it (or press Ctrl+C) to stop.');
    console.log('');
    if (!process.env.ZTP_NO_BROWSER) openBrowser(url);
  };

  require('../server/index.js');
})();
