/**
 * Policy Wizard 2.0 routes. Mounted from server/index.js with the app's requireAuth.
 * GLB-03 is enforced here: every apply needs the planId of a dry run of the identical input.
 */
const crypto = require('crypto');
const COPY = require('./copy');
const { SCOPE_ITEMS, EXCLUSIVE_GROUPS, normalizeScope, detectLicensing, scopeWarnings } = require('./scope');
const fw = require('./frameworks');
const areas = require('./zia-areas');
const { runZia } = require('./zia-engine');
const { parseBulkCsv, validateBulkApps, ZPAClient, runZpa, validateZpaInput, APP_SEGMENT_DEFAULTS, SAN_JOSE, POLICY_DEFAULTS, listZpaObjects, deleteZpaObjects, DELETE_ORDER } = require('./zpa');
const { buildReport } = require('./report');
const { LIST_KEYS, LIST_LABELS, validateProfileLists } = require('./validate');
const { resolveForTenant } = require('../tenant-resolve');

const PREFIX_RE = /^[A-Za-z0-9_-]{1,20}$/;
const stable = (v) => JSON.stringify(v, (k, x) => (k === 'generatedAt' || k === 'catalog' ? undefined : x));
const hash = (v) => crypto.createHash('sha256').update(stable(v)).digest('hex').slice(0, 24);

function v2(session) {
  if (!session.v2) session.v2 = { plans: {}, runs: { zia: [], zcc: [], zpa: [] }, licensing: null };
  return session.v2;
}
function rememberPlan(session, kind, input) {
  const id = `${kind}-${hash(input)}`;
  v2(session).plans[id] = Date.now();
  return id;
}
function checkPlan(session, kind, input, planId) {
  const id = `${kind}-${hash(input)}`;
  const t = v2(session).plans[id];
  if (!planId || planId !== id || !t) return 'Run the dry run first. Changes are only applied after you have reviewed a dry run of exactly these settings.';
  if (Date.now() - t > 60 * 60 * 1000) return 'The dry run is more than an hour old. Run it again before applying.';
  return null;
}

function registerV2Routes(app, requireAuth) {
  // Everything the 2.0 UI needs that does not depend on the tenant (copy is editable in one place: copy.js)
  app.get('/api/v2/meta', (req, res) => {
    res.json({
      copy: COPY, scopeItems: SCOPE_ITEMS, exclusiveGroups: EXCLUSIVE_GROUPS, baselines: fw.listBaselines(),
      aiPromptApps: areas.AI_PROMPT_APPS, sandboxGroups: areas.SANDBOX_ADVANCED_GROUPS.map(g => ({ key: g.key, label: g.label, tier: g.tier })),
      zpaDefaults: APP_SEGMENT_DEFAULTS, zpaLocation: SAN_JOSE, zccListKeys: LIST_KEYS, zccListLabels: LIST_LABELS,
      zpaDeleteOrder: DELETE_ORDER
    });
  });

  // GLB-08: licensing and the Endpoint DLP prerequisite
  app.get('/api/v2/licensing', requireAuth, async (req, res) => {
    try {
      const lic = await detectLicensing({ client: req.session.client, zccClient: req.session.zccClient });
      v2(req.session).licensing = lic;
      res.json(lic);
    } catch (e) { res.status(502).json({ error: e.message }); }
  });

  // Global prefix (GLB-02): kept on the session so every product uses the same one
  app.post('/api/v2/prefix', requireAuth, (req, res) => {
    const p = String((req.body || {}).prefix || '').trim();
    if (!PREFIX_RE.test(p)) return res.status(400).json({ error: 'Prefix must be 1–20 letters, numbers, hyphens or underscores.' });
    v2(req.session).prefix = p;
    res.json({ prefix: p });
  });

  // ---------- ZIA ----------
  function genInput(body, session) {
    const b = body || {};
    const prefix = String(b.prefix || v2(session).prefix || '').trim();
    if (!PREFIX_RE.test(prefix)) throw Object.assign(new Error('Set a global prefix first (1–20 letters, numbers, hyphens or underscores).'), { status: 400 });
    if (!b.baseline) throw Object.assign(new Error('Choose a baseline framework.'), { status: 400 });
    return { baseline: b.baseline, scope: normalizeScope(b.scope), prefix, disabledRules: b.disabledRules || {}, actionSettings: b.actionSettings || { policy: {}, rules: {} },
      settingOverrides: b.settingOverrides || {}, cbiProfile: b.cbiProfile || null, sslCertificate: b.sslCertificate || null };
  }

  app.post('/api/v2/zia/generate', requireAuth, (req, res) => {
    try { res.json(fw.generate(genInput(req.body, req.session))); }
    catch (e) { res.status(e.status || 500).json({ error: e.message }); }
  });

  app.post('/api/v2/zia/plan', requireAuth, async (req, res) => {
    const { client, logger } = req.session;
    try {
      const input = genInput(req.body, req.session);
      const template = fw.generate(input);
      const resolved = await resolveForTenant(client, template, { cbiProfile: input.cbiProfile });
      const run = await runZia(client, resolved.template, { dryRun: true, logger });
      let lic = v2(req.session).licensing;
      if (!lic) { lic = await detectLicensing({ client, zccClient: req.session.zccClient }).catch(() => null); v2(req.session).licensing = lic; }
      const planId = rememberPlan(req.session, 'zia', input);
      logger.log('V2_ZIA_DRY_RUN', { baseline: input.baseline, scope: input.scope, counts: countActions(run.ledger) });
      res.json({
        planId, ledger: run.ledger, counts: countActions(run.ledger),
        warnings: [...scopeWarnings(input.scope, lic).map(w => w.text), ...resolved.warnings, ...run.warnings, ...template.generationNotes],
        errors: resolved.errors, resolved: resolved.info, template: resolved.template
      });
    } catch (e) { res.status(e.status || 502).json({ error: e.message }); }
  });

  app.post('/api/v2/zia/apply', requireAuth, async (req, res) => {
    const { client, logger } = req.session;
    try {
      const input = genInput(req.body, req.session);
      const bad = checkPlan(req.session, 'zia', input, req.body.planId);
      if (bad) return res.status(409).json({ error: bad });
      const template = fw.generate(input);
      const resolved = await resolveForTenant(client, template, { cbiProfile: input.cbiProfile });
      const run = await runZia(client, resolved.template, { dryRun: false, logger });   // GLB-04: activates when anything was written
      const lic = v2(req.session).licensing;
      const warnings = [...scopeWarnings(input.scope, lic).map(w => w.text), ...resolved.warnings, ...run.warnings];
      v2(req.session).runs.zia.push({ at: new Date().toISOString(), template: resolved.template, ledger: run.ledger, warnings, activated: run.activated });
      logger.log('V2_ZIA_APPLY', { baseline: input.baseline, counts: countActions(run.ledger), activated: run.activated });
      res.json({ ledger: run.ledger, counts: countActions(run.ledger), warnings, activated: run.activated });
    } catch (e) { res.status(e.status || 502).json({ error: e.message }); }
  });

  // ---------- ZCC run log (the existing Mobile Admin routes call this after each apply) ----------
  app.locals.recordZccRun = (session, entry) => { v2(session).runs.zcc.push({ at: new Date().toISOString(), ...entry }); };
  app.locals.rememberPlan = rememberPlan;
  app.locals.checkPlan = checkPlan;

  // ZCC-03: predefined IP-based app bypasses, live from the tenant
  app.get('/api/v2/zcc/bypass-apps', requireAuth, async (req, res) => {
    try {
      const r = await req.session.zccClient.apiCall('GET', '/zcc/papi/public/v1/predefined-ip-based-apps');
      const items = (r && (r.appServiceContracts || r.list)) || (Array.isArray(r) ? r : []);
      res.json(items.map(a => ({ id: a.id, name: a.appName || a.name, active: a.active !== false })));
    } catch (e) { res.status(502).json({ error: e.message }); }
  });
  // ZCC-07: current list values of the template the user picked (shown as defaults; "None" when empty)
  app.post('/api/v2/zcc/list-defaults/:platform', requireAuth, (req, res) => {
    try {
      const { buildAppProfileBody, readProfileLists } = require('../zcc-templates');
      const b = req.body || {};
      const { body } = buildAppProfileBody({ platform: req.params.platform, name: 'preview', ruleOrder: 1, templateId: b.templateId || 'BEST_PRACTICE', enabledSettings: b.enabledSettings || null });
      res.json(readProfileLists(body));
    } catch (e) { res.status(400).json({ error: e.message }); }
  });
  app.post('/api/v2/zcc/validate-lists', (req, res) => res.json({ errors: validateProfileLists((req.body || {}).lists) }));

  // ---------- ZPA ----------
  const zpaOf = (session) => { if (!session.zpaClient) session.zpaClient = new ZPAClient(session.client, session.zccClient); return session.zpaClient; };

  app.get('/api/v2/zpa/context', requireAuth, async (req, res) => {
    try {
      const zpa = zpaOf(req.session);
      const groups = await zpa.listAll('/appConnectorGroup');
      res.json({ connectorGroups: groups.map(g => ({ id: String(g.id), name: g.name, location: g.location })), defaults: APP_SEGMENT_DEFAULTS, location: SAN_JOSE });
    } catch (e) { res.status(502).json({ error: e.message }); }
  });
  function zpaInput(body, session) {
    const b = body || {};
    const prefix = String(b.prefix || v2(session).prefix || '').trim();
    if (!PREFIX_RE.test(prefix)) throw Object.assign(new Error('Set a global prefix first.'), { status: 400 });
    return { prefix, domains: b.domains || '', tcpPorts: b.tcpPorts ?? '1-52, 54-65535', udpPorts: b.udpPorts ?? '1-52, 54-65535',
      settings: { ...APP_SEGMENT_DEFAULTS, ...(b.settings || {}) }, connectorGroupId: b.connectorGroupId || null, descriptions: b.descriptions || {},
      policies: { ...POLICY_DEFAULTS, ...(b.policies && typeof b.policies === 'object' ? { timeout: b.policies.timeout !== false, inspection: b.policies.inspection !== false, isolation: b.policies.isolation !== false } : {}) },
      pra: { rdpHost: String((b.pra || {}).rdpHost || '').trim().slice(0, 253), sshHost: String((b.pra || {}).sshHost || '').trim().slice(0, 253), portalId: (b.pra || {}).portalId ? String(b.pra.portalId) : null },
      apps: Array.isArray(b.apps) ? b.apps.slice(0, 500).map(a => ({ name: String(a.name || ''), destinations: Array.isArray(a.destinations) ? a.destinations.map(String) : String(a.destinations || ''),
        tcpPorts: String(a.tcpPorts || ''), udpPorts: String(a.udpPorts || ''), row: a.row, settings: a.settings && typeof a.settings === 'object' ? a.settings : {} })) : null };
  }
  // ZPA bulk upload: parse a CSV (Application Name, Destinations, Ports) into applications and validate them
  app.post('/api/v2/zpa/parse-csv', requireAuth, (req, res) => {
    const text = String((req.body || {}).text || '');
    if (text.length > 2_000_000) return res.status(413).json({ error: 'The file is too large (2 MB limit).' });
    const parsed = parseBulkCsv(text);
    const v = validateBulkApps(parsed.apps);
    res.json({ apps: parsed.apps, errors: [...parsed.errors, ...v.errors] });
  });
  app.post('/api/v2/zpa/validate', (req, res) => { const v = validateZpaInput(req.body || {}); res.json({ errors: v.errors }); });
  app.post('/api/v2/zpa/plan', requireAuth, async (req, res) => {
    try {
      const input = zpaInput(req.body, req.session);
      const run = await runZpa(zpaOf(req.session), input, { dryRun: true, logger: req.session.logger });
      if (run.errors.length) return res.status(400).json({ error: run.errors.join(' '), errors: run.errors });
      res.json({ planId: rememberPlan(req.session, 'zpa', input), ledger: run.ledger, counts: countActions(run.ledger), warnings: run.warnings, names: run.names, followUps: run.followUps });
    } catch (e) { res.status(e.status || 502).json({ error: e.message }); }
  });
  app.post('/api/v2/zpa/apply', requireAuth, async (req, res) => {
    try {
      const input = zpaInput(req.body, req.session);
      const bad = checkPlan(req.session, 'zpa', input, req.body.planId);
      if (bad) return res.status(409).json({ error: bad });
      const run = await runZpa(zpaOf(req.session), input, { dryRun: false, logger: req.session.logger });
      v2(req.session).runs.zpa.push({ at: new Date().toISOString(), ledger: run.ledger, warnings: run.warnings, secrets: run.secrets, names: run.names, followUps: run.followUps });
      req.session.logger.log('V2_ZPA_APPLY', { counts: countActions(run.ledger), provisioningKey: run.secrets.provisioningKey ? '<redacted>' : 'not available' });
      // ZPA-04: the key goes to the browser once, for the masked reveal/copy field and the report
      res.json({ ledger: run.ledger, counts: countActions(run.ledger), warnings: run.warnings, names: run.names, followUps: run.followUps,
        provisioningKey: run.secrets.provisioningKey || null });
    } catch (e) { res.status(e.status || 502).json({ error: e.message }); }
  });

  // ---------- Bulk managers (BRM) ----------
  app.get('/api/v2/zpa/objects', requireAuth, async (req, res) => {
    try { res.json(await listZpaObjects(zpaOf(req.session), String(req.query.prefix || ''))); }
    catch (e) { res.status(502).json({ error: e.message }); }
  });
  app.post('/api/v2/zpa/delete', requireAuth, async (req, res) => {
    try {
      const prefix = v2(req.session).prefix;
      if (!prefix) return res.status(400).json({ error: 'Set the global prefix first. The bulk manager only deletes objects named with it.' });
      // Never trust names from the browser: delete only objects that exist now and are named "<prefix>-…" (BRM-03)
      const current = (await listZpaObjects(zpaOf(req.session), prefix)).filter(o => !o.error);
      const allowed = new Map(current.map(o => [`${o.kind}:${o.id}`, o]));
      const asked = ((req.body || {}).items || []).map(i => `${i.kind}:${String(i.id)}`);
      const refused = asked.filter(k => !allowed.has(k));
      if (refused.length) return res.status(400).json({ error: `Only objects named "${prefix}-…" can be deleted here. Not allowed: ${refused.length} item(s).` });
      const items = asked.map(k => { const o = allowed.get(k); return { kind: o.kind, id: o.id, name: o.name }; });
      if (!items.length) return res.status(400).json({ error: 'Select at least one object.' });
      if (req.body.dryRun) return res.json({ planId: rememberPlan(req.session, 'zpa-del', items), results: await deleteZpaObjects(zpaOf(req.session), items, { dryRun: true }) });
      const bad = checkPlan(req.session, 'zpa-del', items, req.body.planId);
      if (bad) return res.status(409).json({ error: bad });
      res.json({ results: await deleteZpaObjects(zpaOf(req.session), items, { dryRun: false, logger: req.session.logger }) });
    } catch (e) { res.status(502).json({ error: e.message }); }
  });

  app.get('/api/v2/zdx/objects', requireAuth, async (req, res) => {
    const zdx = req.session.zdxClient;
    if (!zdx) return res.status(400).json({ error: 'ZDX needs a OneAPI sign-in.' });
    const filter = String(req.query.filter || '').toLowerCase();
    const SYSTEM_COLLECTIONS = /^(Unified Communication Collection|Predefined Apps Collection|Custom Apps Collection)$/;
    try {
      const out = [];
      for (const a of await zdx.listApps()) {
        if (a.type === 'PREDEFINED') continue;
        if (filter && !String(a.name).toLowerCase().includes(filter)) continue;
        let probes = [];
        try { probes = await zdx.listAppMonitors(a.id); } catch (e) { /* count unknown */ }
        out.push({ kind: 'app', id: String(a.id), name: a.name, detail: `${a.type} application · ${probes.length} probe(s)` });
      }
      for (const c of await zdx.listCollections()) {
        if (SYSTEM_COLLECTIONS.test(c.name)) continue;
        if (filter && !String(c.name).toLowerCase().includes(filter)) continue;
        out.push({ kind: 'collection', id: String(c.id), name: c.name, detail: 'Collection' });
      }
      res.json(out);
    } catch (e) { res.status(502).json({ error: e.zdxMessage || e.message }); }
  });
  app.post('/api/v2/zdx/delete', requireAuth, async (req, res) => {
    const zdx = req.session.zdxClient;
    if (!zdx) return res.status(400).json({ error: 'ZDX needs a OneAPI sign-in.' });
    // Re-read the tenant: only custom applications and non-system collections can be deleted
    const SYSTEM = /^(Unified Communication Collection|Predefined Apps Collection|Custom Apps Collection)$/;
    let apps = [], cols = [];
    try { apps = (await zdx.listApps()).filter(a => a.type !== 'PREDEFINED'); cols = (await zdx.listCollections()).filter(c => !SYSTEM.test(c.name)); }
    catch (e) { return res.status(502).json({ error: e.zdxMessage || e.message }); }
    const allowed = new Map([...apps.map(a => [`app:${a.id}`, { kind: 'app', id: String(a.id), name: a.name }]), ...cols.map(c => [`collection:${c.id}`, { kind: 'collection', id: String(c.id), name: c.name }])]);
    const asked = ((req.body || {}).items || []).map(i => `${i.kind}:${String(i.id)}`);
    if (asked.some(k => !allowed.has(k))) return res.status(400).json({ error: 'Only custom applications and collections that still exist can be deleted.' });
    const items = asked.map(k => allowed.get(k)).sort((a, b) => (a.kind === b.kind ? 0 : a.kind === 'app' ? -1 : 1));   // applications (and probes) first
    if (!items.length) return res.status(400).json({ error: 'Select at least one object.' });
    if (req.body.dryRun) return res.json({ planId: rememberPlan(req.session, 'zdx-del', items), results: items.map(i => ({ ...i, action: 'DELETE' })) });
    const bad = checkPlan(req.session, 'zdx-del', items, req.body.planId);
    if (bad) return res.status(409).json({ error: bad });
    const results = [];
    for (const it of items) {
      try {
        if (it.kind === 'app') {
          const mons = await zdx.listAppMonitors(it.id).catch(() => []);
          const isPath = (m) => /TRACE|PATH/i.test(String(m.type || ''));
          for (const m of mons.filter(isPath)) await zdx.deleteMonitor(it.id, m.id);
          for (const m of mons.filter(x => !isPath(x))) await zdx.deleteMonitor(it.id, m.id);
          await zdx.deleteApp(it.id);
        } else await zdx.deleteCollection(it.id);
        results.push({ ...it, action: 'DELETED' });
        req.session.logger.log('ZDX_APPLY', { action: 'BULK_DELETE', kind: it.kind, id: it.id, name: it.name });
      } catch (e) { results.push({ ...it, action: 'FAILED', error: e.zdxMessage || e.message }); }
    }
    res.json({ results });
  });

  // ---------- Report (§9) ----------
  app.post('/api/v2/report', requireAuth, (req, res) => {
    const s = v2(req.session);
    const lic = s.licensing;
    const report = buildReport({ runs: s.runs, prefix: s.prefix || '', tenant: req.session.client.vanityDomain || req.session.client.baseUrl,
      licensing: lic, endpointWarning: lic ? lic.endpointDlpEnabledInZcc !== true : true, includeSecrets: (req.body || {}).includeSecrets !== false });
    req.session.logger.log('V2_REPORT', { containsSecret: report.containsSecret });
    res.json(report);
  });
  app.get('/api/v2/runs', requireAuth, (req, res) => {
    const s = v2(req.session);
    res.json({ prefix: s.prefix || null, zia: s.runs.zia.length, zcc: s.runs.zcc.length, zpa: s.runs.zpa.length });
  });
}

function countActions(ledger) {
  const c = {};
  for (const e of ledger || []) c[e.action] = (c[e.action] || 0) + 1;
  return c;
}

module.exports = { registerV2Routes, hash };
