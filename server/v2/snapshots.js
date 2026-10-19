/**
 * v2.2: snapshots for one-click restore.
 * Every ZIA / ZPA apply records how to undo each change it made (create → delete, update → previous body).
 * Snapshots are kept as JSON files next to the logs (ZTP-Wizard/logs/snapshots) so a restore also works after
 * the wizard restarts. No secrets are stored: provisioning keys and passwords are removed before saving.
 * Restore runs the undo steps newest first (rules before the objects they reference), then activates ZIA.
 */
'use strict';
const fs = require('fs');
const path = require('path');
const { LOG_DIR } = require('../paths');

const DIR = path.join(LOG_DIR, 'snapshots');
const SECRET = /password|secret|provisioningKey|token/i;
const scrub = (o) => JSON.parse(JSON.stringify(o, (k, v) => (SECRET.test(k) && typeof v === 'string' ? undefined : v)));
const ID_RE = /^[0-9TZ-]+-(zia|zpa)-[A-Za-z0-9_-]{1,20}$/;

function save({ product, prefix, undo, tenant }) {
  if (!undo || !undo.length) return null;
  fs.mkdirSync(DIR, { recursive: true });
  const at = new Date().toISOString();
  const id = `${at.replace(/[:.]/g, '-')}-${product}-${prefix || 'none'}`;
  fs.writeFileSync(path.join(DIR, `${id}.json`), JSON.stringify({ id, at, product, prefix, tenant: tenant || null, steps: scrub(undo) }, null, 1));
  return id;
}

function listAll(prefix) {
  let files = [];
  try { files = fs.readdirSync(DIR).filter(f => f.endsWith('.json')); } catch (e) { return []; }
  return files.map(f => { try { const j = JSON.parse(fs.readFileSync(path.join(DIR, f), 'utf8')); return { id: j.id, at: j.at, product: j.product, prefix: j.prefix, tenant: j.tenant, steps: j.steps.length, restoredAt: j.restoredAt || null }; } catch (e) { return null; } })
    .filter(Boolean).filter(s => !prefix || s.prefix === prefix).sort((a, b) => (a.at < b.at ? 1 : -1));
}

function load(id) {
  if (!ID_RE.test(String(id))) throw Object.assign(new Error('Unknown snapshot'), { status: 404 });
  const f = path.join(DIR, `${id}.json`);
  if (!fs.existsSync(f)) throw Object.assign(new Error('Unknown snapshot'), { status: 404 });
  return JSON.parse(fs.readFileSync(f, 'utf8'));
}

/** Undo one snapshot. dryRun lists the steps; otherwise runs them newest first and reports each. */
async function restore(id, { client, zpa, dryRun, logger }) {
  const snap = load(id);
  const steps = snap.steps.slice().reverse();
  const results = [];
  for (const st of steps) {
    const label = st.label || st.path;
    if (dryRun) { results.push({ label, action: st.op === 'DELETE' ? 'DELETE' : 'PUT BACK' }); continue; }
    try {
      if (snap.product === 'zia') {
        try { await client.apiCall(st.op, st.path, st.op === 'PUT' ? st.body : null); }
        catch (e) {
          // some settings fields sit behind tenant feature flags (seen on ATP): put the rest back without them
          if (st.op !== 'PUT' || !/feature flag/i.test(e.message)) throw e;
          const slim = { ...st.body }; for (const k of Object.keys(slim)) if (/mcp|agentic|genai|aiApp/i.test(k)) delete slim[k];
          await client.apiCall('PUT', st.path, slim);
        }
      }
      else await zpa.apiCall(st.op, st.path, st.op === 'PUT' ? st.body : null);
      results.push({ label, action: st.op === 'DELETE' ? 'DELETED' : 'PUT BACK' });
      if (logger) logger.logPolicyApply('Restore', label, st.op === 'DELETE' ? 'DELETE' : 'RESTORE', { success: true });
    } catch (e) {
      const gone = /404|not found|NOT_FOUND|resource.not.found/i.test(e.message) && st.op === 'DELETE';
      results.push({ label, action: gone ? 'ALREADY GONE' : 'FAILED', error: gone ? undefined : e.message });
      if (logger && !gone) logger.logPolicyApply('Restore', label, 'FAILED', { error: e.message });
    }
  }
  let activated = null;
  if (!dryRun && snap.product === 'zia') { try { await client.apiCall('POST', '/api/v1/status/activate'); activated = true; } catch (e) { activated = false; } }
  if (!dryRun) {
    try { const full = load(id); full.restoredAt = new Date().toISOString(); fs.writeFileSync(path.join(DIR, `${id}.json`), JSON.stringify(full, null, 1)); } catch (e) { /* listing only */ }
  }
  return { id, product: snap.product, prefix: snap.prefix, at: snap.at, results, activated };
}

module.exports = { save, listAll, load, restore, DIR };
