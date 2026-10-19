/**
 * Where the wizard writes its logs.
 * Server install: ./logs next to the app (unchanged).
 * Standalone build: the launcher sets ZTP_LOG_DIR to a folder in the user's home directory,
 * because the folder holding the executable may be read-only (macOS) or Downloads.
 */
const path = require('path');
const fs = require('fs');

const LOG_DIR = process.env.ZTP_LOG_DIR || path.join(__dirname, '..', 'logs');
try { fs.mkdirSync(LOG_DIR, { recursive: true }); } catch (e) { /* reported when a write fails */ }

module.exports = { LOG_DIR };
