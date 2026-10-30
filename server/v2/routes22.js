/**
 * v2.2 routes: live progress, rate limits, readiness, intake, POV tests (runbook / prove it / DLP kit),
 * Client Connector devices + one-time passwords + install builder, snapshots / restore, drift check, update check.
 * Registered from routes.js (shares its session helpers).
 */
'use strict';
const https = require('https');
const { readiness } = require('./readiness');
const intake = require('./intake');
const tests = require('./pov-tests');
const prove = require('./prove');
const kit = require('./test-kit');
const pack = require('./compliance-pack');
const povs = require('./povs');
const snapshots = require('./snapshots');
const install = require('../zcc-install');
const { gate } = require('../rate-limit');

const list = (r) => (Array.isArray(r) ? r : (r && (r.list || r.items)) || []);
const APP_VERSION = require('../../package.json').version;

function register(app, requireAuth, { v2, rememberPlan, checkPlan, zpaOf, countActions, runZia, runZpa }) {
  app.locals.recordZdxRun = (session, entry) => { const s = v2(session); s.runs.zdx = s.runs.zdx || []; s.runs.zdx.push({ at: new Date().toISOString(), ...entry }); };

  // ---------- live progress (17): newline-delimited JSON, one line per object as it is created / updated ----------
  app.get('/api/v2/events', requireAuth, (req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/x-ndjson', 'Cache-Control': 'no-store', 'X-Accel-Buffering': 'no' });
    res.write(JSON.stringify({ hello: true, at: new Date().toISOString() }) + '\n');
    const off = req.session.logger.subscribe((ev) => { try { res.write(JSON.stringify(ev) + '\n'); } catch (e) { /* closed */ } });
    const beat = setInterval(() => { try { res.write('{"beat":1}\n'); } catch (e) { /* closed */ } }, 15000);
    const end = () => { off(); clearInterval(beat); };
    req.on('close', end); res.on('close', end);
  });

  // ---------- rate limits (16) ----------
  app.get('/api/v2/ratelimits', requireAuth, (req, res) => {
    const c = req.session.client;
    res.json({ zcc: gate(c, 'Client Connector').status(), zdx: gate(c, 'ZDX').status() });
  });

  // ---------- readiness (1) ----------
  app.get('/api/v2/readiness', requireAuth, async (req, res) => {
    const s = req.session;
    try {
      const st = v2(s);
      const q = req.query || {};
      const wants = q.products ? Object.fromEntries(['zia', 'zpa', 'zcc', 'zdx', 'aiguard'].map(k => [k, String(q.products).split(',').includes(k)]))
        : (st.intake && st.intake.products) ? { zcc: true, ...st.intake.products } : null;
      const r = await readiness({ client: s.client, zccClient: s.zccClient, zdxClient: s.zdxClient, zpa: s.client.authMode === 'oneapi' ? zpaOf(s) : null, licensing: st.licensing, wants });
      s.logger.log('V2_READINESS', r.counts);
      res.json(r);
    } catch (e) { res.status(502).json({ error: e.message }); }
  });

  // ---------- intake (2) ----------
  app.get('/api/v2/intake/presets', (req, res) => res.json(intake.catalog()));
  app.post('/api/v2/intake/preset', (req, res) => {
    const b = req.body || {};
    const errors = intake.validateIntake({ domain: b.domain });
    if (errors.length) return res.status(400).json({ error: errors.join(' ') });
    res.json({ preset: intake.preset(String(b.id || 'BLANK'), b.domain), suggestedPrefix: intake.suggestPrefix(b.customerName) });
  });
  app.post('/api/v2/intake', requireAuth, (req, res) => {
    const b = req.body || {};
    const errors = intake.validateIntake(b);
    if (errors.length) return res.status(400).json({ error: errors.join(' ') });
    v2(req.session).intake = { ...b, savedAt: new Date().toISOString() };
    req.session.logger.log('V2_INTAKE', { preset: b.presetId, apps: (b.apps || []).length, products: b.products });
    res.json({ ok: true });
  });
  app.get('/api/v2/intake', requireAuth, (req, res) => res.json(v2(req.session).intake || null));

  // ---------- POV tests (7, 8, 9) ----------
  app.get('/api/v2/tests', requireAuth, (req, res) => {
    const s = v2(req.session);
    res.json({ tests: tests.runbook(s.runs, s.testResults || {}) });
  });
  app.post('/api/v2/tests/:id', requireAuth, (req, res) => {
    const s = v2(req.session);
    if (!tests.TESTS.some(t => t.id === req.params.id)) return res.status(404).json({ error: 'Unknown test' });
    const status = ['pass', 'fail', 'skip'].includes(req.body && req.body.status) ? req.body.status : null;
    s.testResults = s.testResults || {};
    if (!status) delete s.testResults[req.params.id];
    else s.testResults[req.params.id] = { status, note: String((req.body || {}).note || '').slice(0, 500), at: new Date().toISOString() };
    res.json({ ok: true, result: s.testResults[req.params.id] || null });
  });
  // v2.6: Prove it for every policy type (URL filtering, threat, cloud apps, firewall, DNS); built-in destinations + your own
  // v2.8: SSL and bypass coverage. Facts are read once and kept for five minutes (Client Connector allows about 100 calls an hour).
  const coverage = require('./coverage');
  async function coverageFacts(session, fresh = false) {
    const st = v2(session);
    if (!fresh && st.coverage && Date.now() - st.coverage.at < 5 * 60e3) return st.coverage.facts;
    const facts = await coverage.readFacts(session.client, session.client && session.client.authMode === 'oneapi' ? (session.zccClient || null) : null);
    st.coverage = { at: Date.now(), facts };
    return facts;
  }
  app.get('/api/v2/coverage', requireAuth, async (req, res) => {
    try {
      const facts = await coverageFacts(req.session, req.query.fresh === '1');
      const out = coverage.summarize(facts);
      v2(req.session).coverageSummary = { at: new Date().toISOString(), headline: out.headline, items: out.items.map(i => ({ severity: i.severity, area: i.area, title: i.title })) };
      res.json(out);
    } catch (e) { res.status(e.status || 502).json({ error: e.message }); }
  });
  // v2.8: POV posture score (read-only). stage 'start' or 'end' keeps the result with the POV for the before / after readout.
  const posture = require('./posture');
  app.get('/api/v2/posture', requireAuth, (req, res) => {
    const st = v2(req.session), p = st.posture || {};
    res.json({ start: p.start || null, end: p.end || null, compare: posture.compare(p.start, p.end) });
  });
  app.post('/api/v2/posture', requireAuth, async (req, res) => {
    try {
      const s = req.session, st = v2(s);
      const stage = ['start', 'end'].includes((req.body || {}).stage) ? req.body.stage : null;
      const r = await posture.assess(s.client, s.client && s.client.authMode === 'oneapi' ? (s.zccClient || null) : null);
      if (stage) { st.posture = { ...(st.posture || {}), [stage]: r }; }
      s.logger.log('V2_POSTURE', { stage, score: r.score, maturity: r.maturity });
      const p = st.posture || {};
      res.json({ result: r, start: p.start || null, end: p.end || null, compare: posture.compare(p.start, p.end) });
    } catch (e) { res.status(e.status || 502).json({ error: e.message }); }
  });
  app.get('/api/v2/prove/catalog', (req, res) => res.json({ catalog: prove.CATALOG }));
  app.post('/api/v2/prove', requireAuth, async (req, res) => {
    try {
      const b = req.body || {};
      const type = b.type || 'url';
      const target = String(b.target || b.url || '').trim().slice(0, 500);
      const EXP = ['BLOCK', 'ALLOW', 'CAUTION', 'ISOLATE', 'INSPECTED', 'NOT_INSPECTED', 'ANY'];
      const expect = EXP.includes(String(b.expect || '').toUpperCase()) ? String(b.expect).toUpperCase() : null;
      const facts = await coverageFacts(req.session).catch(() => null);
      const [match, ins] = await Promise.all([prove.prove(req.session.client, { type, target, appType: b.appType ? String(b.appType) : null, doh: !!b.doh, expect }, { facts }), tests.insights(req.session.client)]);
      res.json({ ...match, host: match.target, insights: ins });
    } catch (e) { res.status(e.status || 502).json({ error: e.message }); }
  });
  app.get('/api/v2/dlp-kit', (req, res) => res.json({ files: tests.dlpKit() }));

  // v2.6: the test kit follows the POV: only what it covers (DLP for its vertical + generic PII, malware, sandbox)
  const kitInputs = async (req) => {
    const st = req.session && req.session.v2;
    let pov = null;
    const id = String(req.query.povId || (st && st.povId) || '');
    if (id) { try { pov = povs.load(id); } catch (e) { pov = null; } }
    const gd = (pov && pov.guide) || {};
    let subs = st && st.subsCache;
    if (!subs && req.session && req.session.client) {
      try { subs = list(await req.session.client.apiCall('GET', '/api/v1/subscriptions')).filter(x => x.subscribed !== false).map(x => String(x.id)); if (st) st.subsCache = subs; } catch (e) { subs = null; }
    }
    return { ziaScope: (gd.pov && gd.pov.scope) || null, products: (gd.g && gd.g.scope) || null, presetId: (gd.g && gd.g.presetId) || (st && st.intake && st.intake.presetId) || null,
      runs: (pov && pov.runs) || (st && st.runs) || {}, subs };
  };
  const softAuth = (req, res, next) => { if (!req.headers['x-session-id']) return next(); const soft = { status: () => ({ json: () => next() }) }; return requireAuth(req, soft, next); };
  app.get('/api/v2/test-kit', softAuth, async (req, res) => {
    try {
      const inp = await kitInputs(req);
      const out = kit.catalog(inp);
      // v2.7: test files for the POV's compliance profile (one per DLP rule of the profile)
      const pi = packInput(req);
      if (pi && out.sections.some(x => x.id === 'dlp')) {
        try { const l = pack.list(pi); out.profile = l.profile; out.sections.unshift({ id: 'profile', title: `${l.profile.name} test files`, how: 'One file per DLP rule of the compliance profile. Upload each to https://dlptest.com/http-post/ through ZIA: Block mode blocks it and the incident names the rule.', files: l.testFiles.map(f => ({ ...f, primary: true })) }); } catch (e) { /* unknown profile */ }
      }
      res.json(out);
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // ---------- v2.7 compliance pack: mapping report, policy export, test plan by control ----------
  // Built from the POV's own choices (its guide) or, on the rules page before a POV is saved, from the posted choices.
  function packInput(req) {
    const st = req.session && req.session.v2;
    const id = String(req.query.povId || (st && st.povId) || '');
    let p = null;
    if (id) { try { p = povs.load(id); } catch (e) { p = null; } }
    const gd = (p && p.guide) || {};
    const baseline = (gd.pov && gd.pov.baseline) || (gd.g && gd.g.baseline) || null;
    if (!baseline) return null;
    return { baseline, scope: (gd.pov && gd.pov.scope) || {}, prefix: (p && p.prefix) || (gd.g && gd.g.prefix) || 'POV', customerName: (p && p.customerName) || (gd.g && gd.g.customerName) || '',
      disabledRules: (gd.pov && gd.pov.disabledRules) || {}, actionSettings: (gd.pov && gd.pov.actionSettings) || null, settingOverrides: (gd.pov && gd.pov.settingOverrides) || {},
      products: (gd.g && gd.g.scope) || null, editions: (st && st.licensing && st.licensing.editions) || null };
  }
  const sendFile = (res, f) => { res.setHeader('Content-Type', f.type + (/^text|json/.test(f.type) ? '; charset=utf-8' : '')); res.setHeader('Content-Disposition', `attachment; filename="${f.name}"`); res.setHeader('Cache-Control', 'no-store'); res.send(f.content); };
  app.get('/api/v2/compliance-pack', softAuth, (req, res) => {
    try { const i = packInput(req); if (!i) return res.status(404).json({ error: 'This POV has no compliance profile yet (choose it on Customer intake).' }); res.json(pack.list(i)); }
    catch (e) { res.status(e.status || 500).json({ error: e.message }); }
  });
  app.get('/api/v2/compliance-pack/file/:id', softAuth, (req, res) => {
    try { const i = packInput(req); if (!i) return res.status(404).json({ error: 'This POV has no compliance profile yet.' }); sendFile(res, pack.build(req.params.id, i)); }
    catch (e) { res.status(e.status || 500).json({ error: e.message }); }
  });
  app.post('/api/v2/compliance-pack/file/:id', requireAuth, (req, res) => {
    try {
      const b = req.body || {};
      if (!b.baseline) return res.status(400).json({ error: 'baseline is required.' });
      const st = req.session && req.session.v2;
      sendFile(res, pack.build(req.params.id, { ...b, editions: (st && st.licensing && st.licensing.editions) || null }));
    } catch (e) { res.status(e.status || 500).json({ error: e.message }); }
  });
  app.get('/api/v2/test-kit/file/:id', (req, res) => {
    try {
      const f = /^cp-/.test(req.params.id) ? pack.profileFile(req.params.id) : kit.file(req.params.id);
      res.setHeader('Content-Type', f.type);
      res.setHeader('Content-Disposition', `attachment; filename="${f.name}"`);
      res.setHeader('Cache-Control', 'no-store');
      res.send(f.encoding === 'base64' ? Buffer.from(f.content, 'base64') : f.content);
    } catch (e) { res.status(e.status || 500).json({ error: e.message }); }
  });

  // ---------- Client Connector devices, one-time passwords, install builder (10) ----------
  app.get('/api/v2/zcc/devices', requireAuth, async (req, res) => {
    try {
      const all = [];
      for (let page = 1; page <= 5; page++) {
        const d = list(await req.session.zccClient.apiCall('GET', `/zcc/papi/public/v1/getDevices?page=${page}&pageSize=500`));
        all.push(...d);
        if (d.length < 500) break;
      }
      res.json({ devices: all.map(d => ({ udid: d.udid, user: d.user, hostname: d.machineHostname, os: d.osVersion, platform: d.type === 3 ? 'Windows' : d.type === 4 ? 'macOS' : d.type === 1 ? 'iOS' : d.type === 2 ? 'Android' : d.type === 5 ? 'Linux' : String(d.type),
        state: d.registrationState, agent: d.agentVersion, policy: d.policyName, lastSeen: d.last_seen_time || d.keepAliveTime || null, tunnel: d.tunnelVersion || null })) });
    } catch (e) { res.status(e.status || 502).json({ error: e.message, rateLimitedUntil: e.rateLimitedUntil }); }
  });
  app.post('/api/v2/zcc/devices/otp', requireAuth, async (req, res) => {
    const udid = String((req.body || {}).udid || '');
    if (!/^[A-Za-z0-9:._-]{4,200}$/.test(udid)) return res.status(400).json({ error: 'Pick a device.' });
    try {
      const r = await req.session.zccClient.apiCall('GET', `/zcc/papi/public/v1/getOtp?udid=${encodeURIComponent(udid)}`);
      // The one-time password goes to the browser only; it is never logged.
      req.session.logger.log('ZCC_OTP', { device: udid.slice(0, 6) + '…' });
      const otp = r && (r.otp || r.OTP || r.password || (typeof r === 'string' ? r : null));
      const extra = r && typeof r === 'object' ? Object.fromEntries(Object.entries(r).filter(([k, v]) => /otp|password/i.test(k) && typeof v === 'string')) : {};
      res.json({ otp, passwords: extra });
    } catch (e) { res.status(e.status || 502).json({ error: e.message, rateLimitedUntil: e.rateLimitedUntil }); }
  });
  app.get('/api/v2/zcc/install/catalog', (req, res) => res.json(install.catalog()));
  app.get('/api/v2/zcc/install/tokens/:platform', requireAuth, async (req, res) => {
    try {
      const dt = req.params.platform === 'macos' ? 4 : 3;
      const p = list(await req.session.zccClient.getAppProfiles(dt));
      res.json(p.filter(x => x.policyToken).map(x => ({ id: x.id, name: x.name, active: !!Number(x.active), ruleOrder: x.ruleOrder, policyToken: x.policyToken })));
    } catch (e) { res.status(e.status || 502).json({ error: e.message, rateLimitedUntil: e.rateLimitedUntil }); }
  });
  app.post('/api/v2/zcc/install/build', (req, res) => {
    const b = req.body || {};
    const platform = b.platform === 'macos' ? 'macos' : 'windows';
    const type = platform === 'macos' ? 'app' : b.installerType === 'exe' ? 'exe' : 'msi';
    const params = install.collectParams(platform, type, b.values || {});
    const issues = install.validateParams(platform, type, params);
    const name = String(b.installerName || (platform === 'macos' ? 'Zscaler-osx-installer.app' : `Zscaler-windows-installer.${type}`)).replace(/[\\/:*?"<>|]/g, '_').slice(0, 120);
    const cmd = install.buildCommand({ platform, installerType: type, installerPath: name, params, silent: b.silent !== false, debug: b.debug !== false });
    const ok = !issues.some(i => i[0] === 'ERROR');
    const script = !ok ? null : platform === 'macos'
      ? { name: 'install-zcc.command', content: install.buildMacScript({ installerName: name, params, version: APP_VERSION }) }
      : { name: 'install-zcc.bat', content: install.buildBat({ installerType: type, installerName: name, params, silent: b.silent !== false, debug: b.debug !== false, version: APP_VERSION }) };
    res.json({ ok, platform, installerType: type, issues, command: platform === 'macos' ? `sudo ${cmd.displayMasked}` : cmd.displayMasked,
      params: Object.fromEntries(Object.entries(params).map(([k, v]) => [k, install.isSecret(k) ? '********' : v])), script });
  });

  // ---------- snapshots and restore (13) ----------
  app.get('/api/v2/snapshots', requireAuth, (req, res) => res.json(snapshots.listAll(String(req.query.prefix || '') || null)));
  app.post('/api/v2/snapshots/:id/restore', requireAuth, async (req, res) => {
    const s = req.session;
    try {
      const id = req.params.id;
      const input = { id };
      if ((req.body || {}).dryRun !== false) {
        const r = await snapshots.restore(id, { client: s.client, zpa: zpaOf(s), dryRun: true });
        return res.json({ ...r, planId: rememberPlan(s, 'restore', input) });
      }
      const bad = checkPlan(s, 'restore', input, req.body.planId);
      if (bad) return res.status(409).json({ error: bad });
      const r = await snapshots.restore(id, { client: s.client, zpa: zpaOf(s), dryRun: false, logger: s.logger });
      s.logger.log('V2_RESTORE', { id, counts: r.results.reduce((c, x) => { c[x.action] = (c[x.action] || 0) + 1; return c; }, {}) });
      res.json(r);
    } catch (e) { res.status(e.status || 502).json({ error: e.message }); }
  });

  // ---------- drift (14): re-plan the last applied ZIA and ZPA runs; any Create / Update is a change made since ----------
  app.post('/api/v2/drift', requireAuth, async (req, res) => {
    const s = req.session, st = v2(s);
    const out = { at: new Date().toISOString(), products: [] };
    try {
      const zia = (st.runs.zia || []).slice(-1)[0];
      if (zia) {
        const run = await runZia(s.client, zia.template, { dryRun: true });
        out.products.push({ product: 'ZIA', since: zia.at, drift: run.ledger.filter(e => e.action === 'CREATE' || e.action === 'UPDATE').map(e => ({ ...e, why: e.action === 'CREATE' ? 'missing (deleted since the run)' : 'changed since the run' })), unchanged: run.ledger.filter(e => e.action === 'NO_CHANGE').length });
      }
      const zpa = (st.runs.zpa || []).slice(-1)[0];
      if (zpa && zpa.input) {
        const run = await runZpa(zpaOf(s), zpa.input, { dryRun: true });
        out.products.push({ product: 'ZPA', since: zpa.at, drift: run.ledger.filter(e => e.action === 'CREATE' || e.action === 'UPDATE').map(e => ({ ...e, why: e.action === 'CREATE' ? 'missing (deleted since the run)' : 'changed since the run' })), unchanged: run.ledger.filter(e => e.action === 'NO_CHANGE').length });
      }
      if (!out.products.length) out.note = 'Nothing applied yet in this session. Run ZIA or ZPA first, then check for drift later.';
      s.logger.log('V2_DRIFT', { products: out.products.map(p => `${p.product}:${p.drift.length}`) });
      res.json(out);
    } catch (e) { res.status(e.status || 502).json({ error: e.message }); }
  });

  // ---------- update check (20): compares with the version on GitHub main (cached for an hour) ----------
  let updateCache = null;
  app.get('/api/v2/update-check', (req, res) => {
    if (updateCache && Date.now() - updateCache.at < 3600e3) return res.json(updateCache.body);
    const done = (body) => { updateCache = { at: Date.now(), body }; res.json(body); };
    const r = https.get('https://raw.githubusercontent.com/ZeroTrustPanda/ZTP-Policy-Wizard/main/package.json', { timeout: 6000, headers: { 'User-Agent': 'ZTP-Policy-Wizard' } }, (resp) => {
      let data = '';
      resp.on('data', (c) => { data += c; if (data.length > 100000) resp.destroy(); });
      resp.on('end', () => {
        try {
          const latest = JSON.parse(data).version;
          const newer = cmp(latest, APP_VERSION) > 0;
          done({ current: APP_VERSION, latest, newer, downloads: newer ? 'https://github.com/ZeroTrustPanda/ZTP-Policy-Wizard/tree/standalone#readme' : null });
        } catch (e) { done({ current: APP_VERSION, latest: null, newer: false }); }
      });
    });
    r.on('timeout', () => r.destroy());
    r.on('error', () => res.json({ current: APP_VERSION, latest: null, newer: false, offline: true }));
  });
}

function cmp(a, b) {
  const pa = String(a || '0').split('.').map(Number), pb = String(b || '0').split('.').map(Number);
  for (let i = 0; i < 3; i++) { if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0); }
  return 0;
}

module.exports = { register, cmp };
