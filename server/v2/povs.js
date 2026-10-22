/**
 * v2.4: Active POVs — one local folder per customer POV, so several POVs can run side by side and each one can be resumed.
 *
 *   ZTP-Wizard/povs/<id>/pov.json        plan, resume point (guide), runs, tests, success criteria, timeline, notes, follow-ups
 *   ZTP-Wizard/povs/_archive/<id>/       archived POVs
 *   ZTP-Wizard/pov-templates/<id>.json   saved templates (choices only: no customer, tenant or prefix)
 *
 * Never stored: API credentials, provisioning keys, tamper / one-time passwords, tokens. A POV only remembers its
 * tenant's vanity domain and cloud, and a POV can only be opened in a session signed in to that same tenant.
 */
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { LOG_DIR } = require('../paths');

const BASE = path.dirname(LOG_DIR);
const DIR = process.env.ZTP_POV_DIR || path.join(BASE, 'povs');
const ARCHIVE = path.join(DIR, '_archive');
const TPL_DIR = process.env.ZTP_POV_TEMPLATE_DIR || path.join(BASE, 'pov-templates');
const ID_RE = /^[a-z0-9-]{3,60}$/;
const STATUSES = ['planning', 'built', 'testing', 'wrapping-up', 'closed'];
const QUIET_DAYS = 7;

const SECRET_KEY = /password|secret|provisioningKey|token|otp|clientSecret/i;
/** Deep copy without secret-looking string values (structure kept, so the UI still knows a value was there). */
const scrub = (o) => (o === undefined ? undefined : JSON.parse(JSON.stringify(o, (k, v) => (SECRET_KEY.test(k) && typeof v === 'string' ? undefined : v))));
const slug = (s) => String(s || 'pov').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40) || 'pov';
const now = () => new Date().toISOString();
const tenantKey = (t) => (t && t.vanity ? `${String(t.vanity).toLowerCase()}@${String(t.cloud || 'production').toLowerCase()}` : '');
const emptyRuns = () => ({ zia: [], zcc: [], zpa: [], zdx: [], aiguard: [] });

function fileOf(id) {
  if (!ID_RE.test(String(id))) throw Object.assign(new Error('Unknown POV'), { status: 404 });
  return path.join(DIR, id, 'pov.json');
}
function load(id) {
  const f = fileOf(id);
  if (!fs.existsSync(f)) throw Object.assign(new Error('Unknown POV'), { status: 404 });
  return JSON.parse(fs.readFileSync(f, 'utf8'));
}
function save(pov) {
  const f = fileOf(pov.id);
  fs.mkdirSync(path.dirname(f), { recursive: true });
  pov.updatedAt = now();
  const tmp = f + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(scrub(pov), null, 1));
  fs.renameSync(tmp, f);
  return pov;
}

function create({ customerName, prefix, tenant, guide, templateId }) {
  if (!String(customerName || '').trim()) throw Object.assign(new Error('Enter the customer name.'), { status: 400 });
  fs.mkdirSync(DIR, { recursive: true });
  let id = `${slug(customerName)}-${crypto.randomBytes(2).toString('hex')}`;
  while (fs.existsSync(path.join(DIR, id))) id = `${slug(customerName)}-${crypto.randomBytes(2).toString('hex')}`;
  const pov = {
    id, customerName: String(customerName).trim().slice(0, 120), prefix: String(prefix || '').slice(0, 20),
    tenant: { vanity: tenant.vanity, cloud: tenant.cloud || 'production' }, status: 'planning',
    createdAt: now(), updatedAt: now(), lastActivityAt: now(), templateId: templateId || null,
    guide: guide || null, runs: emptyRuns(), testResults: {}, intake: null,
    criteria: [], timeline: { kickoff: null, checkins: [], end: null }, notes: [], followUps: []
  };
  return save(pov);
}

/** Small summary for the sidebar list. */
function summary(p, runbookFn) {
  const runs = p.runs || emptyRuns();
  const tests = runbookFn ? runbookFn(runs, p.testResults || {}) : [];
  const last = p.lastActivityAt || p.updatedAt;
  const days = Math.floor((Date.now() - new Date(last).getTime()) / 86400000);
  const dates = [p.timeline && p.timeline.kickoff && { date: p.timeline.kickoff, label: 'Kickoff' },
    ...((p.timeline && p.timeline.checkins) || []).map(c => ({ date: c.date, label: c.label || 'Check-in' })),
    p.timeline && p.timeline.end && { date: p.timeline.end, label: 'POV ends' }].filter(x => x && x.date);
  const today = new Date().toISOString().slice(0, 10);
  const next = dates.filter(d => d.date >= today).sort((a, b) => (a.date < b.date ? -1 : 1))[0] || null;
  return {
    id: p.id, customerName: p.customerName, prefix: p.prefix, tenant: p.tenant, status: p.status, updatedAt: p.updatedAt, lastActivityAt: last,
    daysQuiet: days, quiet: p.status !== 'closed' && days >= QUIET_DAYS,
    resume: p.guide && p.guide.stageLabel ? p.guide.stageLabel : null,
    runs: ['zia', 'zcc', 'zpa', 'zdx', 'aiguard'].reduce((n, k) => n + ((runs[k] || []).length), 0),
    tests: { total: tests.length, pass: tests.filter(t => t.result && t.result.status === 'pass').length, fail: tests.filter(t => t.result && t.result.status === 'fail').length },
    criteria: { total: (p.criteria || []).length, met: (p.criteria || []).filter(c => c.status === 'met').length },
    openFollowUps: (p.followUps || []).filter(f => !f.done).length,
    next
  };
}

function listAll(runbookFn) {
  let dirs = [];
  try { dirs = fs.readdirSync(DIR, { withFileTypes: true }).filter(d => d.isDirectory() && d.name !== '_archive').map(d => d.name); } catch (e) { return []; }
  return dirs.map(id => { try { return summary(load(id), runbookFn); } catch (e) { return null; } }).filter(Boolean)
    .sort((a, b) => (a.lastActivityAt < b.lastActivityAt ? 1 : -1));
}

function archive(id) {
  fileOf(id);
  fs.mkdirSync(ARCHIVE, { recursive: true });
  const dest = path.join(ARCHIVE, `${id}-${Date.now()}`);
  fs.renameSync(path.join(DIR, id), dest);
  return { archived: true };
}

const EDITABLE = ['customerName', 'prefix', 'status', 'criteria', 'timeline', 'notes', 'followUps', 'guide'];
function update(id, patch) {
  const p = load(id);
  for (const k of EDITABLE) if (patch[k] !== undefined) p[k] = patch[k];
  if (!STATUSES.includes(p.status)) p.status = 'planning';
  p.criteria = (p.criteria || []).slice(0, 100).map(c => ({ id: c.id || crypto.randomBytes(3).toString('hex'), text: String(c.text || '').slice(0, 300), status: ['pending', 'met', 'not-met'].includes(c.status) ? c.status : 'pending', testIds: (c.testIds || []).slice(0, 20), note: String(c.note || '').slice(0, 500) }));
  p.notes = (p.notes || []).slice(-500).map(n => ({ at: n.at || now(), text: String(n.text || '').slice(0, 4000) }));
  p.followUps = (p.followUps || []).slice(0, 200).map(f => ({ id: f.id || crypto.randomBytes(3).toString('hex'), text: String(f.text || '').slice(0, 400), done: !!f.done, source: f.source === 'wizard' ? 'wizard' : 'me', due: f.due || null }));
  const t = p.timeline || {};
  p.timeline = { kickoff: t.kickoff || null, end: t.end || null, checkins: (t.checkins || []).slice(0, 50).map(c => ({ date: c.date || null, label: String(c.label || 'Check-in').slice(0, 80) })) };
  if (patch.guide !== undefined || patch.notes !== undefined) p.lastActivityAt = now();
  return save(p);
}

/** Copy the session's runs / tests / intake into the POV (called after every change while a POV is open). */
function syncFromSession(id, st) {
  const p = load(id);
  const before = JSON.stringify([p.runs, p.testResults]);
  p.runs = scrub(st.runs) || emptyRuns();
  p.testResults = scrub(st.testResults) || {};
  if (st.intake) p.intake = scrub(st.intake);
  if (st.prefix && !p.prefix) p.prefix = st.prefix;
  // wizard follow-ups from the latest ZPA run, added once
  const zpa = (p.runs.zpa || []).slice(-1)[0];
  for (const text of (zpa && zpa.followUps) || []) if (!p.followUps.some(f => f.text === text)) p.followUps.push({ id: crypto.randomBytes(3).toString('hex'), text, done: false, source: 'wizard', due: null });
  // status moves forward on its own: something applied → built; a test result → testing
  const applied = ['zia', 'zcc', 'zpa', 'zdx', 'aiguard'].some(k => (p.runs[k] || []).length);
  if (p.status === 'planning' && applied) p.status = 'built';
  if ((p.status === 'planning' || p.status === 'built') && Object.keys(p.testResults || {}).length) p.status = 'testing';
  if (JSON.stringify([p.runs, p.testResults]) !== before) p.lastActivityAt = now();
  return save(p);
}

// ---------- templates ----------
const TPL_RE = /^[a-z0-9-]{3,60}$/;
function listTemplates() {
  let files = [];
  try { files = fs.readdirSync(TPL_DIR).filter(f => f.endsWith('.json')); } catch (e) { return []; }
  return files.map(f => { try { const t = JSON.parse(fs.readFileSync(path.join(TPL_DIR, f), 'utf8')); return { id: t.id, name: t.name, description: t.description, createdAt: t.createdAt, fromPov: t.fromPov || null }; } catch (e) { return null; } })
    .filter(Boolean).sort((a, b) => String(a.name).localeCompare(String(b.name)));
}
function loadTemplate(id) {
  if (!TPL_RE.test(String(id))) throw Object.assign(new Error('Unknown template'), { status: 404 });
  const f = path.join(TPL_DIR, `${id}.json`);
  if (!fs.existsSync(f)) throw Object.assign(new Error('Unknown template'), { status: 404 });
  return JSON.parse(fs.readFileSync(f, 'utf8'));
}
function saveTemplate({ name, description, choices, fromPov }) {
  if (!String(name || '').trim()) throw Object.assign(new Error('Name the template.'), { status: 400 });
  fs.mkdirSync(TPL_DIR, { recursive: true });
  const id = `${slug(name)}-${crypto.randomBytes(2).toString('hex')}`;
  const t = { id, name: String(name).trim().slice(0, 80), description: String(description || '').slice(0, 300), createdAt: now(), fromPov: fromPov || null, choices: scrub(choices || {}) };
  fs.writeFileSync(path.join(TPL_DIR, `${id}.json`), JSON.stringify(t, null, 1));
  return t;
}
function deleteTemplate(id) {
  if (!TPL_RE.test(String(id))) throw Object.assign(new Error('Unknown template'), { status: 404 });
  fs.rmSync(path.join(TPL_DIR, `${id}.json`), { force: true });
  return { deleted: true };
}

function exportPov(id) { const p = load(id); return { format: 'ztp-pov', version: 1, exportedAt: now(), pov: scrub(p) }; }
function importPov(data) {
  if (!data || data.format !== 'ztp-pov' || !data.pov || !data.pov.customerName) throw Object.assign(new Error('This is not an exported POV file.'), { status: 400 });
  const src = data.pov;
  const p = create({ customerName: src.customerName, prefix: src.prefix, tenant: src.tenant || {}, guide: src.guide });
  const q = load(p.id);
  Object.assign(q, { status: src.status, criteria: src.criteria || [], timeline: src.timeline || {}, notes: src.notes || [], followUps: src.followUps || [],
    runs: scrub(src.runs) || emptyRuns(), testResults: src.testResults || {}, intake: src.intake || null, createdAt: src.createdAt || q.createdAt, lastActivityAt: src.lastActivityAt || q.lastActivityAt });
  save(q);
  return update(p.id, {});
}

module.exports = { DIR, TPL_DIR, STATUSES, scrub, tenantKey, create, load, save, update, listAll, summary, archive, syncFromSession,
  listTemplates, loadTemplate, saveTemplate, deleteTemplate, exportPov, importPov, emptyRuns };
