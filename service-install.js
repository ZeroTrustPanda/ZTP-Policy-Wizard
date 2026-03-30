/**
 * Windows Service installer for ZTP Policy Wizard
 * 
 * Usage:
 *   npm install -g node-windows
 *   node service-install.js
 * 
 * To uninstall:
 *   node service-uninstall.js
 */

try {
  const Service = require('node-windows').Service;
  const path = require('path');

  const svc = new Service({
    name: 'ZTP Policy Wizard',
    description: 'Zscaler Template Policy Configuration Wizard',
    script: path.join(__dirname, 'server', 'index.js'),
    env: [
      { name: 'ZTP_PORT', value: '3000' },
      { name: 'ZTP_HOST', value: '0.0.0.0' }
    ]
  });

  svc.on('install', () => {
    console.log('Service installed successfully. Starting...');
    svc.start();
  });

  svc.on('start', () => {
    console.log('Service started. Access at http://localhost:3000');
  });

  svc.on('error', (err) => {
    console.error('Service error:', err);
  });

  svc.install();
} catch (e) {
  console.error('Error: node-windows package not found.');
  console.error('Install it with: npm install -g node-windows');
  console.error('Then run this script again.');
}
