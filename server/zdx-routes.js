/**
 * Digital Experience (ZDX) module routes (v1.8.0)
 *
 *   GET    /api/zdx/catalog                         templates + predefined apps (with tenant state) + options
 *   POST   /api/zdx/dryrun                          read-only plan: checks, ordered steps, warnings
 *   POST   /api/zdx/apply                           run the plan, read back and verify, roll back failed custom apps
 *   GET    /api/zdx/overview                        configured apps with their probes (Manage screen)
 *   POST   /api/zdx/apps/:key/:action               activate | deactivate an app
 *   POST   /api/zdx/apps/:key/monitors/:mid/:action activate | deactivate a probe
 *   DELETE /api/zdx/apps/:id?confirmName=           delete a custom/network app (probes first)
 *   DELETE /api/zdx/apps/:key/monitors/:mid?confirmName=  delete a probe of a custom/network app
 *
 * Order rules learned on the live API (2026-10-12):
 *   - custom apps: create inactive -> Web probe -> CloudPath probe (followWebMonitor) -> activate app
 *   - predefined apps: create with prefix (ZDX adds its own Web + CloudPath probes) -> activate app -> Web -> CloudPath
 *   - deactivate / delete in reverse: CloudPath before Web (an active CloudPath probe blocks its Web probe)
 *   - a brand-new ZDX tenant has no "Custom Apps Collection" (the portal creates it with the first custom
 *     app), so the plan starts with a setup step that creates it (v1.8.2, proven on a fresh tenant)
 */
const { ZDXClient } = require('./zdx-client');
const T = require('./zdx-templates');

const PREFIX_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i;
const NAME_RE = /^[\w .()\-:/&+]{1,64}$/;

const COLLECTION_DEFAULTS = {
  custom: { name: 'Custom Apps Collection', description: 'Custom applications (created by ZTP Policy Wizard)' },
  predefined: { name: 'Predefined Apps Collection', description: 'Collection for Predefined Applications (created by ZTP Policy Wizard)' }
};

function findCollection(collections, kind) {
  const want = kind === 'custom' ? 'custom apps collection' : 'predefined apps collection';
  return collections.find(c => String(c.name).toLowerCase() === want)
    || collections.find(c => String(c.name).toLowerCase().includes(kind === 'custom' ? 'custom' : 'predefined'));
}

const isWeb = (m) => m.type === 'WEB';
const isPath = (m) => m.type === 'TRACERT' || m.type === 'TRACERT_V2' || m.type === 'HIFI_MTR';

/**
 * Read-only plan. Returns { ok, checks, warnings, apps: [{ kind, key, name, steps: [...] }], _ctx }.
 * Each step: { op, label, detail } where op is one of
 *   createPredefined | createCustom | createWeb | createCloudPath | activateApp | activateWeb | activateCloudPath | none
 */
async function planZdx(zdx, input) {
  const checks = [];
  const warnings = [];
  const out = [];
  const predefinedIn = Array.isArray(input?.predefined) ? input.predefined : [];
  const customIn = Array.isArray(input?.custom) ? input.custom : [];

  let apps = [], supported = [], collections = [], monitors = [];
  try {
    [apps, supported, collections, monitors] = await Promise.all([zdx.listApps(), zdx.listSupported('PREDEFINED'), zdx.listCollections(), zdx.listAllMonitors()]);
    checks.push({ name: 'ZDX API reachable', status: 'pass', detail: `${apps.length} configured apps, ${monitors.length} probes in the tenant` });
  } catch (e) {
    checks.push({ name: 'ZDX API reachable', status: 'fail', detail: `${e.message}. The API client needs the ZDX scope in ZIdentity.` });
    return { ok: false, checks, warnings, apps: out, _ctx: null };
  }

  if (!predefinedIn.length && !customIn.length) {
    checks.push({ name: 'Something to do', status: 'fail', detail: 'Pick at least one predefined app or add a custom app.' });
  }

  const colPre = findCollection(collections, 'predefined');
  const colCus = findCollection(collections, 'custom');
  const missingCol = new Set();   // collections a new ZDX tenant doesn't have yet; created by a setup step

  // ---- Predefined apps
  for (const p of predefinedIn) {
    const provider = String(p.provider || '').toUpperCase();
    const sup = supported.find(s => s.provider === provider);
    const label = T.PREDEFINED_INFO[provider]?.label || sup?.name || provider;
    const entry = { kind: 'predefined', key: provider, name: label, steps: [] };
    out.push(entry);
    if (!sup) { checks.push({ name: `${label}: supported`, status: 'fail', detail: `${provider} is not offered by ZDX for this tenant` }); continue; }
    const wantWeb = p.web !== false;
    const wantPath = !!p.cloudpath && wantWeb;
    Object.assign(entry, { wantWeb, wantPath });
    if (p.cloudpath && !wantWeb) warnings.push(`${label}: a CloudPath probe follows the Web probe, so it is only turned on together with the Web probe.`);

    const existing = apps.find(a => a.type === 'PREDEFINED' && a.provider === provider);
    const needsPrefix = String(sup.host || '').includes('<prefix>');
    const prefix = needsPrefix ? String(p.prefix || '').trim() : String(sup.host || '').split('.')[0];
    entry.host = needsPrefix ? String(sup.host).replace('<prefix>', prefix || '<prefix>') : sup.host;

    if (!existing) {
      if (needsPrefix && !prefix) {   // e.g. Zoom or Webex picked by the template without the customer's account prefix: left out, not failed
        warnings.push(`${label} left out: enter the customer's ${label} prefix (the part before ${String(sup.host).replace('<prefix>', '')}) to monitor it.`);
        entry.steps.push({ op: 'none', label: 'Left out: no prefix entered' });
        continue;
      }
      if (needsPrefix && !PREFIX_RE.test(prefix)) {
        checks.push({ name: `${label}: tenant prefix`, status: 'fail', detail: `Enter the customer's ${label} prefix (the part before ${String(sup.host).replace('<prefix>', '')}).` });
        continue;
      }
      if (!colPre) missingCol.add('predefined');
      entry.prefix = prefix;
      entry.steps.push({ op: 'createPredefined', label: `Set up ${label} (${entry.host})`, detail: 'ZDX adds its own Web and CloudPath probes for this app' });
      entry.steps.push({ op: 'activateApp', label: `Turn on ${label}` });
      if (wantWeb) entry.steps.push({ op: 'activateWeb', label: 'Turn on the Zscaler Web probe' });
      if (wantPath) entry.steps.push({ op: 'activateCloudPath', label: 'Turn on the Zscaler CloudPath probe' });
      checks.push({ name: `${label}: plan`, status: 'pass', detail: `Not set up yet — will be created for ${entry.host} and turned on` });
      continue;
    }

    entry.appId = existing.id;
    if (needsPrefix && p.prefix && existing.prefix && p.prefix !== existing.prefix) {
      warnings.push(`${label} is already set up with prefix "${existing.prefix}"; it is kept (the prefix you entered is ignored).`);
    }
    let mons = [];
    try { mons = await zdx.listAppMonitors(provider); } catch (e) { warnings.push(`${label}: could not list probes (${e.message})`); }
    const web = mons.find(isWeb), path = mons.find(isPath);
    entry.monitors = { web: web ? { id: web.id, name: web.name, active: !!web.active } : null, cloudpath: path ? { id: path.id, name: path.name, active: !!path.active } : null };
    if (!existing.active) entry.steps.push({ op: 'activateApp', label: `Turn on ${label}` });
    if (wantWeb) {
      if (!web) warnings.push(`${label} has no Web probe in this tenant; turn it on in the ZDX portal.`);
      else if (!web.active) entry.steps.push({ op: 'activateWeb', label: `Turn on "${web.name}"`, mid: web.id });
    }
    if (wantPath) {
      if (!path) warnings.push(`${label} has no CloudPath probe in this tenant; turn it on in the ZDX portal.`);
      else if (!path.active) entry.steps.push({ op: 'activateCloudPath', label: `Turn on "${path.name}"`, mid: path.id });
    }
    if (!entry.steps.length) entry.steps.push({ op: 'none', label: 'Already on with the selected probes — no change' });
    checks.push({ name: `${label}: plan`, status: 'pass', detail: entry.steps.map(s => s.label).join(' → ') });
  }

  // ---- Custom apps
  const seenNames = new Set();
  for (const c of customIn) {
    const name = String(c.name || '').trim();
    const url = String(c.url || '').trim();
    const host = T.hostOf(url);
    const entry = { kind: 'custom', key: null, name: name || '(unnamed)', url, host, steps: [] };
    out.push(entry);
    if (!NAME_RE.test(name)) { checks.push({ name: `Custom app "${entry.name}": name`, status: 'fail', detail: 'Use 1–64 letters, numbers, spaces or - _ . ( ) : / & +' }); continue; }
    if (seenNames.has(name.toLowerCase())) { checks.push({ name: `Custom app "${name}": name`, status: 'fail', detail: 'Listed twice' }); continue; }
    seenNames.add(name.toLowerCase());
    if (!host) { checks.push({ name: `Custom app "${name}": URL`, status: 'fail', detail: 'Enter a full http:// or https:// URL' }); continue; }
    const frequency = T.PROBE_FREQUENCIES.includes(Number(c.frequency)) ? Number(c.frequency) : 300;
    const protocol = T.CLOUDPATH_PROTOCOLS.includes(c.protocol) ? c.protocol : 'ADAPTIVE';
    Object.assign(entry, { frequency, protocol, cloudpath: c.cloudpath !== false });

    const same = apps.find(a => a.type !== 'PREDEFINED' && String(a.name).toLowerCase() === name.toLowerCase());
    if (same) {
      const sameMons = monitors.filter(m => m.application?.id === same.id);
      const sameWeb = sameMons.find(m => isWeb(m) && T.hostOf(m.url) === host);
      if (sameWeb) {
        entry.appId = same.id;
        entry.steps.push({ op: 'none', label: `Already monitored by "${same.name}" (ID ${same.id}) — skipped` });
        checks.push({ name: `Custom app "${name}"`, status: 'pass', detail: `Already exists with a Web probe for ${host}; nothing to create` });
      } else {
        checks.push({ name: `Custom app "${name}": name`, status: 'fail', detail: `An app with this name already exists (ID ${same.id}) for a different URL. Choose another name.` });
      }
      continue;
    }
    const otherHost = monitors.find(m => isWeb(m) && T.hostOf(m.url) === host);
    if (otherHost) warnings.push(`${host} is already probed by "${otherHost.name}" in app "${otherHost.application?.name}". A second app will probe it too.`);
    if (!colCus) missingCol.add('custom');
    entry.steps.push({ op: 'createCustom', label: `Create custom app "${name}" (inactive)` });
    entry.steps.push({ op: 'createWeb', label: `Create Web probe for ${url}`, body: T.buildWebMonitor({ appName: name, url, frequency }) });
    if (entry.cloudpath) entry.steps.push({ op: 'createCloudPath', label: `Create CloudPath probe to ${host} (${protocol})`, body: T.buildCloudPathMonitor({ appName: name, host, frequency, protocol }) });
    entry.steps.push({ op: 'activateApp', label: `Turn on "${name}"` });
    checks.push({ name: `Custom app "${name}"`, status: 'pass', detail: `${host} · Web${entry.cloudpath ? ' + CloudPath' : ''} · every ${frequency / 60} min · all users` });
  }

  if (missingCol.size) {
    const setup = { kind: 'setup', key: 'collections', name: 'ZDX tenant setup', steps: [] };
    for (const k of ['predefined', 'custom']) {
      if (!missingCol.has(k)) continue;
      setup.steps.push({ op: 'createCollection', collectionKind: k, label: `Create the "${COLLECTION_DEFAULTS[k].name}" (new ZDX tenant)` });
      checks.splice(1, 0, { name: `"${COLLECTION_DEFAULTS[k].name}"`, status: 'pass', detail: 'Not in this tenant yet (new ZDX tenant) — will be created first' });
    }
    out.unshift(setup);
  }

  checks.push({ name: 'Who the probes run for', status: 'pass', detail: 'All users (no department, location or group scoping)' });
  const changes = out.reduce((n, a) => n + a.steps.filter(s => s.op !== 'none').length, 0);
  if (!changes && !checks.some(c => c.status === 'fail')) warnings.push('Everything selected is already on. Apply will make no changes.');
  return {
    ok: !checks.some(c => c.status === 'fail'), checks, warnings, apps: out, changes,
    _ctx: { colPre, colCus }
  };
}

/** Run one planned app. Returns { name, kind, ok, steps: [{label, ok, error}], created: {...}, rolledBack } */
async function runApp(zdx, entry, ctx) {
  const res = { name: entry.name, kind: entry.kind, ok: true, steps: [], created: {} };
  const step = async (label, fn) => {
    try { const r = await fn(); res.steps.push({ label, ok: true }); return r; }
    catch (e) { res.steps.push({ label, ok: false, error: e.zdxMessage || e.message }); res.ok = false; throw e; }
  };
  try {
    if (entry.kind === 'setup') {
      for (const s of entry.steps) {
        if (s.op !== 'createCollection') continue;
        const d = COLLECTION_DEFAULTS[s.collectionKind];
        const col = await step(s.label, () => zdx.createCollection({ name: d.name, type: 'END_USER', active: true, description: d.description, tags: [], filters: {} }));
        if (!col?.id) throw Object.assign(new Error('ZDX did not return the new collection'), { zdxMessage: 'ZDX did not return the new collection' });
        res.created[s.collectionKind === 'custom' ? 'customCollectionId' : 'predefinedCollectionId'] = col.id;
        ctx[s.collectionKind === 'custom' ? 'colCus' : 'colPre'] = { id: col.id, name: col.name || d.name };
      }
      return res;
    }
    if (entry.kind === 'predefined') {
      const key = entry.key;
      let monsById = entry.monitors || {};
      for (const s of entry.steps) {
        if (s.op === 'none') { res.steps.push({ label: s.label, ok: true, skipped: true }); continue; }
        if (s.op === 'createPredefined') {
          const app = await step(s.label, () => zdx.createApp({ type: 'PREDEFINED', provider: key, name: entry.name, prefix: entry.prefix, active: false, collection: { id: ctx.colPre.id, name: ctx.colPre.name } }));
          res.created.appId = app?.id;
          const mons = await zdx.listAppMonitors(key);
          const w = mons.find(isWeb), p = mons.find(isPath);
          monsById = { web: w ? { id: w.id, name: w.name } : null, cloudpath: p ? { id: p.id, name: p.name } : null };
        } else if (s.op === 'activateApp') {
          await step(s.label, () => zdx.activateApp(key));
        } else if (s.op === 'activateWeb') {
          const mid = s.mid || monsById.web?.id;
          if (!mid) throw Object.assign(new Error('ZDX did not create a Web probe for this app'), { zdxMessage: 'ZDX did not create a Web probe for this app' });
          await step(s.label, () => zdx.activateMonitor(key, mid));
        } else if (s.op === 'activateCloudPath') {
          const mid = s.mid || monsById.cloudpath?.id;
          if (!mid) throw Object.assign(new Error('ZDX did not create a CloudPath probe for this app'), { zdxMessage: 'ZDX did not create a CloudPath probe for this app' });
          await step(s.label, () => zdx.activateMonitor(key, mid));
        }
      }
      return res;
    }

    // custom
    let appId = null, webId = null;
    for (const s of entry.steps) {
      if (s.op === 'none') { res.steps.push({ label: s.label, ok: true, skipped: true }); continue; }
      if (s.op === 'createCustom') {
        const app = await step(s.label, () => zdx.createApp({ type: 'CUSTOM', name: entry.name, description: 'Created by ZTP Policy Wizard (Zscaler POV best practice)', active: false, collection: { id: ctx.colCus.id, name: ctx.colCus.name } }));
        appId = app?.id; res.created.appId = appId;
      } else if (s.op === 'createWeb') {
        const m = await step(s.label, () => zdx.createMonitor(appId, s.body));
        webId = m?.id; res.created.webId = webId;
      } else if (s.op === 'createCloudPath') {
        const m = await step(s.label, () => zdx.createMonitor(appId, { ...s.body, followWebMonitor: { id: Number(webId) } }));
        res.created.cloudPathId = m?.id;
      } else if (s.op === 'activateApp') {
        await step(s.label, () => zdx.activateApp(appId));
      }
    }
    return res;
  } catch (e) {
    // Roll back a half-created custom app so a failed run leaves nothing behind
    if (entry.kind === 'custom' && res.created.appId) {
      const rb = [];
      try { if (res.created.cloudPathId) { await zdx.deleteMonitor(res.created.appId, res.created.cloudPathId); rb.push('CloudPath probe'); } } catch (x) { /* reported below */ }
      try { if (res.created.webId) { await zdx.deleteMonitor(res.created.appId, res.created.webId); rb.push('Web probe'); } } catch (x) { /* reported below */ }
      try { await zdx.deleteApp(res.created.appId); rb.push('app'); } catch (x) { rb.push(`app NOT removed (ID ${res.created.appId}): ${x.message}`); }
      res.rolledBack = rb.join(', ');
    }
    return res;
  }
}

/** Read the tenant back and check every app the plan touched. */
async function verifyZdx(zdx, plan, results) {
  const [apps, monitors] = await Promise.all([zdx.listApps(), zdx.listAllMonitors()]);
  const rows = [];
  for (const entry of plan.apps) {
    if (entry.kind === 'setup') continue;
    const r = results.find(x => x.name === entry.name && x.kind === entry.kind);
    if (!r || !r.ok) continue;
    const app = entry.kind === 'predefined'
      ? apps.find(a => a.type === 'PREDEFINED' && a.provider === entry.key)
      : apps.find(a => String(a.id) === String(r.created.appId || entry.appId));
    rows.push({ app: entry.name, check: 'App is on', ok: !!app?.active, detail: app ? `ID ${app.id}` : 'not found' });
    if (!app) continue;
    const mons = monitors.filter(m => m.application?.id === app.id);
    const web = mons.find(isWeb), path = mons.find(isPath);
    const wantWeb = entry.kind === 'custom' ? true : entry.wantWeb;
    const wantPath = entry.kind === 'custom' ? entry.cloudpath : entry.wantPath;
    if (wantWeb) rows.push({ app: entry.name, check: 'Web probe is on', ok: !!web?.active, detail: web ? `${web.name} · ${web.url}` : 'not found' });
    if (wantPath) rows.push({ app: entry.name, check: 'CloudPath probe is on', ok: !!path?.active, detail: path ? `${path.name} · ${path.host}${path.followWebMonitor ? ` · follows ${path.followWebMonitor.name}` : ''}` : 'not found' });
    if (entry.kind === 'custom' && web) rows.push({ app: entry.name, check: 'Web probe URL', ok: T.hostOf(web.url) === entry.host, detail: web.url });
  }
  return rows;
}

function registerZdxRoutes(app, requireAuth) {
  const getZdx = (req, res) => {
    const s = req.session;
    if (!s?.zdxClient) { res.status(400).json({ error: 'ZDX client not initialized. Reconnect with OneAPI credentials.' }); return null; }
    return s.zdxClient;
  };

  app.get('/api/zdx/catalog', requireAuth, async (req, res) => {
    const zdx = getZdx(req, res); if (!zdx) return;
    try {
      const [supported, apps] = await Promise.all([zdx.listSupported('PREDEFINED'), zdx.listApps()]);
      const predefined = supported.map(s => {
        const cfg = apps.find(a => a.type === 'PREDEFINED' && a.provider === s.provider);
        return {
          provider: s.provider,
          label: T.PREDEFINED_INFO[s.provider]?.label || s.name,
          description: T.PREDEFINED_INFO[s.provider]?.description || `${s.name} (${s.host})`,
          host: s.host, needsPrefix: String(s.host || '').includes('<prefix>'),
          configured: !!cfg, active: !!cfg?.active, prefix: cfg?.prefix || null,
          configuredHost: cfg?.host || null
        };
      });
      res.json({ templates: T.getTemplateCatalog(), predefined, frequencies: T.PROBE_FREQUENCIES, protocols: T.CLOUDPATH_PROTOCOLS });
    } catch (e) { res.status(502).json({ error: e.message }); }
  });

  app.post('/api/zdx/dryrun', requireAuth, async (req, res) => {
    const zdx = getZdx(req, res); if (!zdx) return;
    try {
      const plan = await planZdx(zdx, req.body);
      req.session.logger.log('ZDX_DRY_RUN', { ok: plan.ok, changes: plan.changes, apps: plan.apps.map(a => `${a.kind}:${a.name}`) });
      const { _ctx, ...rest } = plan;
      rest.apps = rest.apps.map(a => ({ ...a, steps: a.steps.map(({ body, ...s }) => s) }));
      res.json(rest);
    } catch (e) { res.status(502).json({ error: e.message }); }
  });

  app.post('/api/zdx/apply', requireAuth, async (req, res) => {
    const zdx = getZdx(req, res); if (!zdx) return;
    const { logger } = req.session;
    try {
      const plan = await planZdx(zdx, req.body);
      if (!plan.ok) return res.status(409).json({ error: 'Pre-flight checks failed: ' + plan.checks.filter(c => c.status === 'fail').map(c => `${c.name}: ${c.detail}`).join('; '), checks: plan.checks });
      const results = [];
      for (const entry of plan.apps) {
        // Apps need their collection: if tenant setup failed, don't try them (nothing half-built is left behind)
        const setupFailed = results.some(r => r.kind === 'setup' && !r.ok);
        if (setupFailed) { results.push({ name: entry.name, kind: entry.kind, ok: false, steps: [{ label: 'Not started — ZDX tenant setup failed', ok: false, error: 'Skipped' }], created: {} }); continue; }
        const r = await runApp(zdx, entry, plan._ctx);
        results.push(r);
        logger.log('PROGRESS', { product: 'ZDX', message: `${r.name}: ${r.ok ? 'done' : 'failed'}` }, r.ok ? 'success' : 'error');
      }
      let verification = [];
      try { verification = await verifyZdx(zdx, plan, results); }
      catch (e) { verification = [{ app: '—', check: 'Read back from ZDX', ok: false, detail: e.message }]; }
      const ok = results.every(r => r.ok);
      const verified = ok && verification.every(v => v.ok);
      logger.log('ZDX_APPLY', { ok, verified, results: results.map(r => ({ app: r.name, kind: r.kind, ok: r.ok, created: r.created, rolledBack: r.rolledBack || null })) }, ok ? 'info' : 'error');
      if (app.locals.recordZdxRun) app.locals.recordZdxRun(req.session, { apps: results.map(r => ({ name: r.name, kind: r.kind, ok: r.ok })) });
      res.json({ success: ok, verified, results, verification });
    } catch (e) {
      logger.log('ZDX_APPLY', { error: e.message }, 'error');
      res.status(502).json({ error: e.message });
    }
  });

  app.get('/api/zdx/overview', requireAuth, async (req, res) => {
    const zdx = getZdx(req, res); if (!zdx) return;
    try {
      const [apps, monitors] = await Promise.all([zdx.listApps(), zdx.listAllMonitors()]);
      const out = apps.map(a => ({
        id: a.id, key: a.type === 'PREDEFINED' ? a.provider : a.id, name: a.name, type: a.type, provider: a.provider || null,
        active: !!a.active, host: a.host || null,
        monitors: monitors.filter(m => m.application?.id === a.id).map(m => ({
          id: m.id, name: m.name, type: m.type, active: !!m.active, target: m.url || m.host || '',
          frequency: m.frequencyInSeconds, follows: m.followWebMonitor?.id || null
        }))
      })).sort((x, y) => (x.type === y.type ? x.name.localeCompare(y.name) : x.type === 'PREDEFINED' ? -1 : 1));
      res.json({ apps: out });
    } catch (e) { res.status(502).json({ error: e.message }); }
  });

  app.post('/api/zdx/apps/:key/:action(activate|deactivate)', requireAuth, async (req, res) => {
    const zdx = getZdx(req, res); if (!zdx) return;
    try {
      const r = req.params.action === 'activate' ? await zdx.activateApp(req.params.key) : await zdx.deactivateApp(req.params.key);
      req.session.logger.log('ZDX_APPLY', { action: `APP_${req.params.action.toUpperCase()}`, key: req.params.key });
      res.json({ success: true, app: r });
    } catch (e) { res.status(e.status && e.status < 500 ? 400 : 502).json({ error: e.zdxMessage || e.message }); }
  });

  app.post('/api/zdx/apps/:key/monitors/:mid/:action(activate|deactivate)', requireAuth, async (req, res) => {
    const zdx = getZdx(req, res); if (!zdx) return;
    try {
      const { key, mid, action } = req.params;
      const r = action === 'activate' ? await zdx.activateMonitor(key, mid) : await zdx.deactivateMonitor(key, mid);
      req.session.logger.log('ZDX_APPLY', { action: `PROBE_${action.toUpperCase()}`, key, mid });
      res.json({ success: true, result: r });
    } catch (e) { res.status(e.status && e.status < 500 ? 400 : 502).json({ error: e.zdxMessage || e.message }); }
  });

  app.delete('/api/zdx/apps/:key/monitors/:mid', requireAuth, async (req, res) => {
    const zdx = getZdx(req, res); if (!zdx) return;
    try {
      const { key, mid } = req.params;
      if (!/^\d+$/.test(key)) return res.status(400).json({ error: 'Zscaler predefined probes cannot be deleted; deactivate them instead.' });
      const mons = await zdx.listAppMonitors(key);
      const m = mons.find(x => String(x.id) === String(mid));
      if (!m) return res.status(404).json({ error: `Probe ${mid} not found in app ${key}.` });
      if (req.query.confirmName !== m.name) return res.status(400).json({ error: `Confirmation name does not match "${m.name}".` });
      if (isWeb(m) && mons.some(x => isPath(x) && x.followWebMonitor?.id === m.id)) {
        return res.status(409).json({ error: `A CloudPath probe follows "${m.name}". Delete the CloudPath probe first.` });
      }
      await zdx.deleteMonitor(key, mid);
      req.session.logger.log('ZDX_APPLY', { action: 'PROBE_DELETE', key, mid, name: m.name });
      res.json({ success: true });
    } catch (e) { res.status(e.status && e.status < 500 ? 400 : 502).json({ error: e.zdxMessage || e.message }); }
  });

  app.delete('/api/zdx/apps/:id', requireAuth, async (req, res) => {
    const zdx = getZdx(req, res); if (!zdx) return;
    try {
      const id = String(req.params.id);
      if (!/^\d+$/.test(id)) return res.status(400).json({ error: 'Zscaler predefined apps cannot be deleted; deactivate them instead.' });
      const apps = await zdx.listApps();
      const a = apps.find(x => String(x.id) === id);
      if (!a) return res.status(404).json({ error: `App ${id} not found.` });
      if (a.type === 'PREDEFINED') return res.status(400).json({ error: 'Zscaler predefined apps cannot be deleted; deactivate them instead.' });
      if (req.query.confirmName !== a.name) return res.status(400).json({ error: `Confirmation name does not match "${a.name}".` });
      const mons = await zdx.listAppMonitors(id);
      for (const m of mons.filter(isPath)) await zdx.deleteMonitor(id, m.id);   // CloudPath first
      for (const m of mons.filter(x => !isPath(x))) await zdx.deleteMonitor(id, m.id);
      await zdx.deleteApp(id);
      req.session.logger.log('ZDX_APPLY', { action: 'APP_DELETE', id, name: a.name, probes: mons.length });
      res.json({ success: true, deletedProbes: mons.length });
    } catch (e) { res.status(e.status && e.status < 500 ? 400 : 502).json({ error: e.zdxMessage || e.message }); }
  });
}

module.exports = { registerZdxRoutes, planZdx, runApp, verifyZdx, ZDXClient };
