/**
 * Idempotent ZIA executor (GLB-03/04/05, VAL-02).
 * The dry run and the apply run the SAME code: in a dry run every write is recorded instead of sent, so the preview
 * shows exactly what the apply will do. Objects are matched by name:
 *   - missing                 → CREATE
 *   - present, fields differ  → UPDATE (only the fields the wizard manages; the rule keeps its position)
 *   - present, fields match   → NO_CHANGE
 * One failure never stops the rest; objects that depend on a failed one are reported as SKIPPED.
 */
const { SANDBOX_PROTOCOLS } = require('./zia-areas');

const list = (r) => (Array.isArray(r) ? r : (r && (r.list || r.items)) || []);
const READ_ONLY = ['lastModifiedTime', 'lastModifiedBy', 'accessControl', 'predefined', 'defaultRule', 'creationTime', 'modifiedTime', 'modifiedBy'];
const IGNORE_IN_DIFF = new Set(['order', 'rank', 'id']);

// ---------- comparison ----------
const emptyish = (v) => v === undefined || v === null || v === false || v === '' || v === 0 || (Array.isArray(v) && v.length === 0);
function norm(v) {
  if (Array.isArray(v)) {
    const m = v.map(x => (x && typeof x === 'object') ? (x.id !== undefined ? String(x.id) : JSON.stringify(norm(x))) : String(x));
    return m.sort();
  }
  if (v && typeof v === 'object') {
    if (v.id !== undefined && Object.keys(v).every(k => ['id', 'name', 'url', 'profileSeq', 'extensions'].includes(k))) return String(v.id);
    return v;
  }
  return v === undefined || v === null ? '' : String(v);
}
/** Fields of `desired` that differ from `existing` (returns [] when everything the wizard manages already matches). */
function diff(desired, existing, path = '') {
  const out = [];
  for (const [k, dv] of Object.entries(desired || {})) {
    if (IGNORE_IN_DIFF.has(k)) continue;
    const ev = existing ? existing[k] : undefined;
    const p = path ? `${path}.${k}` : k;
    if (emptyish(dv) && emptyish(ev)) continue;
    if (dv && typeof dv === 'object' && !Array.isArray(dv) && dv.id === undefined) {
      out.push(...diff(dv, ev && typeof ev === 'object' ? ev : {}, p));
      continue;
    }
    if (JSON.stringify(norm(dv)) !== JSON.stringify(norm(ev))) out.push(p);
  }
  return out;
}

/** v2.2: before → after values for the changed fields (short, for the dry-run view). */
const short = (v) => { const t = typeof v === 'string' ? v : JSON.stringify(v === undefined ? null : v); return t.length > 140 ? t.slice(0, 137) + '…' : t; };
function details(changes, want, existing) {
  const get = (o, p) => p.split('.').reduce((x, k) => (x == null ? undefined : x[k]), o);
  return changes.filter(c => !/^order \(/.test(c)).map(f => ({ field: f, from: short(get(existing, f)), to: short(get(want, f)) }));
}
const strip = (o) => { const c = JSON.parse(JSON.stringify(o || {})); for (const k of ['lastModifiedTime', 'lastModifiedBy', 'accessControl', 'creationTime', 'modifiedTime', 'modifiedBy']) delete c[k]; return c; };

// ZIA rejects descriptions over 255 bytes on several object types (e.g. DLP dictionaries).
function clampDescription(b) {
  if (!b || typeof b.description !== 'string' || Buffer.byteLength(b.description) <= 255) return b;
  let d = b.description;
  while (Buffer.byteLength(d + '…') > 255) d = d.slice(0, -1);
  return { ...b, description: d.trimEnd() + '…' };
}

class ZiaEngine {
  constructor(client, { dryRun = true, logger = null } = {}) {
    this.client = client;
    this.dryRun = dryRun;
    this.logger = logger;
    this.ledger = [];      // per object: { product, category, name, action, changes, error, id, note }
    this.warnings = [];
    this.cache = {};
    this.wrote = false;
    this.seq = 0;
    this.undo = [];   // v2.2 snapshot: how to put every change back (create → delete, update → previous body)
  }

  record(entry) {
    const e = { product: 'ZIA', ...entry };
    this.ledger.push(e);
    if (this.logger && !this.dryRun) this.logger.logPolicyApply(e.category, e.name, e.action, e.error ? { error: e.error } : { success: true, id: e.id, changes: e.changes });
    return e;
  }

  async get(path) {
    if (!this.cache[path]) this.cache[path] = list(await this.client.apiCall('GET', path));
    return this.cache[path];
  }

  async nextOrder(path, { afterPredefined = false } = {}) {
    const key = `order:${path}`;
    if (this.cache[key] === undefined) {
      let start = 1;
      try {
        const rules = (await this.get(path)).filter(r => !r.defaultRule);
        start = Math.max(0, ...rules.filter(r => !afterPredefined || r.predefined).map(r => r.order || 0)) + 1;
        if (!afterPredefined) start = Math.max(0, ...rules.map(r => r.order || 0)) + 1;
      } catch (e) { /* start at 1 */ }
      this.cache[key] = start;
    }
    return this.cache[key]++;
  }

  /** The bottom of the list (below every rule, predefined ones included), read fresh. */
  async lastOrder(path) {
    this.cache[path] = null;
    const rules = (await this.get(path)).filter(r => !r.defaultRule);
    return Math.max(0, ...rules.map(r => r.order || 0)) + 1;
  }

  releaseOrder(path, order) {
    const key = `order:${path}`;
    if (this.cache[key] === order + 1) this.cache[key] = order;
  }

  /**
   * Create-or-update one object.
   * spec: { category, name, listPath, createPath, updatePath(id), body | build(order), orderPath?, orderOpts?, match?(obj), createFallback?(err, body) }
   * Rule order is only taken when a rule is actually created, so updates never leave gaps.
   */
  async upsert(spec) {
    const { category, name } = spec;
    const body = clampDescription(spec.build ? spec.build(0) : spec.body);
    let existing = null;
    try {
      const items = await this.get(spec.listPath);
      existing = items.find(spec.match || (o => o && (o.name === name || o.configuredName === name)));
    } catch (e) {
      return this.record({ category, name, action: 'FAILED', error: `Could not read existing ${category}: ${e.message}` });
    }
    if (existing) {
      const want = spec.adjust ? spec.adjust(body, existing) : body;
      const changes = diff(want, existing);
      // A catch-all rule that is no longer last (e.g. it sits above Zscaler's predefined rules) is moved to the bottom.
      let moveTo = null;
      if (spec.placeLast) {
        const others = (this.cache[spec.listPath] || []).filter(o => o && !o.defaultRule && o.id !== existing.id && o.order !== undefined);
        const max = Math.max(0, ...others.map(o => o.order));
        if (existing.order !== undefined && existing.order < max) { moveTo = max; changes.push(`order (${existing.order} → bottom, ${max})`); }
      }
      if (!changes.length) return this.record({ category, name, action: 'NO_CHANGE', id: existing.id });
      const det = details(changes, want, existing);
      if (this.dryRun) return this.record({ category, name, action: 'UPDATE', id: existing.id, changes, details: det });
      const merged = clampDescription({ ...existing, ...want, id: existing.id });
      if (existing.order !== undefined) merged.order = moveTo || existing.order;   // re-runs only move a catch-all back to the bottom
      for (const k of READ_ONLY) delete merged[k];
      try {
        await this.client.apiCall('PUT', spec.updatePath(existing.id), merged);
        this.wrote = true;
        this.undo.push({ op: 'PUT', path: spec.updatePath(existing.id), body: strip(existing), label: `${category}: ${name}` });
        this.cache[spec.listPath] = null;
        return this.record({ category, name, action: 'UPDATE', id: existing.id, changes, details: det });
      } catch (e) {
        return this.record({ category, name, action: 'FAILED', id: existing.id, error: e.message, changes });
      }
    }
    if (this.dryRun) {
      if (spec.build && !spec.placeLast) await this.nextOrder(spec.orderPath || spec.listPath, spec.orderOpts);
      return this.record({ category, name, action: 'CREATE', id: `new:${++this.seq}` });
    }
    let takenOrder;
    const orderPath = spec.orderPath || spec.listPath;
    try {
      let created;
      if (spec.build) takenOrder = spec.placeLast ? await this.lastOrder(orderPath) : await this.nextOrder(orderPath, spec.orderOpts);
      const createBody = spec.build ? clampDescription(spec.build(takenOrder)) : clampDescription(body);
      try { created = await this.client.apiCall('POST', spec.createPath, createBody); }
      catch (e) {
        if (!spec.createFallback) throw e;
        const retry = spec.createFallback(e, createBody);
        if (!retry) throw e;
        if (retry.warning) this.warnings.push(`${name}: ${retry.warning}`);
        created = await this.client.apiCall('POST', spec.createPath, retry.body);
      }
      this.wrote = true;
      if (created && created.id !== undefined) this.undo.push({ op: 'DELETE', path: spec.updatePath(created.id), label: `${category}: ${name}` });
      this.cache[spec.listPath] = null;
      return this.record({ category, name, action: 'CREATE', id: created && (created.id !== undefined ? created.id : created.configuredName) });
    } catch (e) {
      if (takenOrder !== undefined && !spec.placeLast) this.releaseOrder(orderPath, takenOrder);
      return this.record({ category, name, action: 'FAILED', error: e.message });
    }
  }

  /** Singleton settings object: GET, merge the managed fields, PUT only if something differs. */
  async upsertSettings({ category, name, path, values, putFilter }) {
    let current;
    try { current = await this.client.apiCall('GET', path); }
    catch (e) { return this.record({ category, name, action: 'FAILED', error: `Could not read current settings: ${e.message}` }); }
    const changes = Object.keys(values).filter(k => (current || {})[k] !== values[k] && !(emptyish(values[k]) && emptyish((current || {})[k])));
    if (!changes.length) return this.record({ category, name, action: 'NO_CHANGE' });
    const det = changes.map(k => ({ field: k, from: short((current || {})[k]), to: short(values[k]) }));
    if (this.dryRun) return this.record({ category, name, action: 'UPDATE', changes, details: det });
    try {
      const merged = { ...current, ...values };
      if (putFilter) { const r = await putFilter(merged); if (r && r.notes) this.warnings.push(...r.notes); }
      else await this.client.apiCall('PUT', path, merged);
      this.wrote = true;
      this.undo.push({ op: 'PUT', path, body: strip(current), label: `${category}: ${name}` });
      return this.record({ category, name, action: 'UPDATE', changes, details: det });
    } catch (e) {
      if (e.skipped) return this.record({ category, name, action: 'SKIPPED', error: e.message, changes });
      return this.record({ category, name, action: 'FAILED', error: e.message, changes });
    }
  }

  async activate() {
    if (this.dryRun || !this.wrote) return null;
    try { await this.client.apiCall('POST', '/api/v1/status/activate'); return true; }
    catch (e) { this.warnings.push(`Activation failed: ${e.message}. Activate pending changes in the ZIA admin portal.`); return false; }
  }
}

// ---------- body builders (ported from the 1.9 apply route) ----------
const ALL_METHODS = ['OPTIONS', 'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'TRACE', 'CONNECT', 'OTHER', 'PROPFIND', 'PROPPATCH', 'MOVE', 'MKCOL', 'LOCK', 'COPY', 'UNLOCK', 'PATCH'];

function urlRuleBody(rule, order, catIds) {
  const b = {
    name: rule.name, description: rule.description || '', order, state: rule.state || 'ENABLED', rank: 7, action: rule.action,
    urlCategories: (rule.urlCategories || []).map(c => catIds[c] || c),
    protocols: rule.action === 'ISOLATE' ? ['HTTPS_RULE', 'HTTP_RULE'] : (rule.protocols && rule.protocols.length ? rule.protocols : ['ANY_RULE']),
    requestMethods: rule.action === 'CAUTION' ? ['CONNECT', 'GET', 'HEAD'] : rule.action === 'ISOLATE' ? ['CONNECT', 'GET'] : ALL_METHODS,
    blockOverride: false, enforceTimeValidity: false
  };
  if (rule.action === 'ISOLATE' && rule.cbiProfile) {
    b.userAgentTypes = rule.userAgentTypes && rule.userAgentTypes.length ? rule.userAgentTypes : ['OPERA', 'FIREFOX', 'MSIE', 'MSEDGE', 'CHROME', 'SAFARI', 'MSCHREDGE'];
    b.cbiProfile = { id: rule.cbiProfile.id, name: rule.cbiProfile.name, url: rule.cbiProfile.url, ...(rule.cbiProfile.profileSeq !== undefined ? { profileSeq: rule.cbiProfile.profileSeq } : {}) };
  }
  return b;
}
function firewallBody(rule, order) {
  const b = { name: rule.name, description: rule.description || '', order, state: rule.state || 'ENABLED', rank: 7,
    action: rule.action === 'BLOCK_ICMP_UNREACHABLE' ? 'BLOCK_DROP' : rule.action, enableFullLogging: false };
  for (const k of ['nwApplications', 'destPorts', 'protocols', 'destIpCategories', 'destCountries', 'sourceCountries']) if (rule[k] && (!Array.isArray(rule[k]) || rule[k].length)) b[k] = rule[k];
  return b;
}
/** A rule with no category or app scope (urlCategories empty or ['ANY']) catches all remaining traffic. */
function isSslCatchAll(rule) {
  const cats = rule.urlCategories || [];
  return (!cats.length || (cats.length === 1 && cats[0] === 'ANY')) && !(rule.cloudApplications || []).length && rule.placeLast !== false;
}
function sslBody(rule, order) {
  const decrypt = rule.action === 'INSPECT' || rule.action === 'DECRYPT';
  const b = { name: rule.name, description: rule.description || '', order, state: rule.state || 'ENABLED', rank: 7, roadWarriorForKerberos: false };
  b.action = decrypt
    ? { type: 'DECRYPT', decryptSubActions: { serverCertificates: 'ALLOW', ocspCheck: true, blockSslTrafficWithNoSniEnabled: true,
        minClientTLSVersion: rule.minClientTLS || 'CLIENT_TLS_1_0', minServerTLSVersion: rule.minServerTLS || 'SERVER_TLS_1_0', blockUndecrypt: true, http2Enabled: false },
        showEUN: false, showEUNATP: false, overrideDefaultCertificate: false }
    : { type: 'DO_NOT_DECRYPT', doNotDecryptSubActions: { serverCertificates: 'ALLOW', bypassOtherPolicies: false, ocspCheck: false, blockSslTrafficWithNoSniEnabled: false },
        showEUN: false, showEUNATP: false, overrideDefaultCertificate: false };
  if (rule.urlCategories && rule.urlCategories.length && !(rule.urlCategories.length === 1 && rule.urlCategories[0] === 'ANY')) b.urlCategories = rule.urlCategories;
  if (decrypt && rule.sslInterceptionCert && rule.sslInterceptionCert.id !== undefined) {
    b.action.overrideDefaultCertificate = true;
    b.action.sslInterceptionCert = { id: rule.sslInterceptionCert.id, name: rule.sslInterceptionCert.name };
  }
  return b;
}
function sandboxBody(rule, order) {
  const b = { name: rule.name, description: rule.description || '', order, state: rule.state || 'ENABLED', rank: 7,
    protocols: (rule.protocols || []).filter(x => !/^ANY/.test(x)).length ? rule.protocols.filter(x => !/^ANY/.test(x)) : SANDBOX_PROTOCOLS,
    fileTypes: rule.fileTypes, baPolicyCategories: rule.baPolicyCategories || [], baRuleAction: rule.baRuleAction || 'BLOCK',
    firstTimeEnable: rule.firstTimeEnable !== false, firstTimeOperation: rule.firstTimeOperation || 'ALLOW_SCAN', mlActionEnabled: !!rule.mlActionEnabled };
  if (b.firstTimeOperation === 'QUARANTINE_ISOLATE') {
    if (rule.cbiProfile && rule.cbiProfile.id) b.cbiProfile = { id: rule.cbiProfile.id, name: rule.cbiProfile.name, url: rule.cbiProfile.url };
    else b.firstTimeOperation = 'QUARANTINE';
  }
  return b;
}
const dnsBody = (rule, order, gateway) => {
  const b = { name: rule.name, description: rule.description || '', order, state: rule.state || 'ENABLED', rank: rule.rank || 7,
    action: rule.action || 'BLOCK', protocols: rule.protocols || ['ANY_RULE'] };
  for (const k of ['applications', 'destIpCategories', 'resCategories', 'destCountries']) if (rule[k] && rule[k].length) b[k] = rule[k].slice();
  if (gateway) b.dnsGateway = { id: gateway.id, name: gateway.name };
  return b;
};
const fileTypeBody = (rule, order) => ({ name: rule.name, description: rule.description || '', order, state: rule.state || 'ENABLED', rank: 7,
  protocols: rule.protocols || ['ANY_RULE'], fileTypes: rule.fileTypes || [], filteringAction: rule.filteringAction || 'BLOCK',
  operation: rule.operation || 'UPLOAD_DOWNLOAD', ...(rule.passwordProtected !== undefined ? { passwordProtected: rule.passwordProtected } : {}) });
// ZIA: "Caution Action can be applied only for specific user agents" (live, ZTH) — a Caution rule must name the browsers.
const CAC_BROWSERS = ['OPERA', 'FIREFOX', 'MSIE', 'MSEDGE', 'CHROME', 'SAFARI', 'MSCHREDGE'];
const cacBody = (rule, order) => {
  const b = { name: rule.name, description: rule.description || '', order, state: rule.state || 'ENABLED', rank: 7,
    type: rule.ruleType || rule.type || 'AI_ML', actions: rule.actions || [] };
  if (rule.applications && rule.applications.length) b.applications = rule.applications.slice();
  if (b.actions.some(a => /^CAUTION_/.test(a))) b.userAgentTypes = rule.userAgentTypes && rule.userAgentTypes.length ? rule.userAgentTypes : CAC_BROWSERS.slice();
  return b;
};

// ---------- the run ----------
/**
 * Execute (or preview) a 2.0 template against ZIA.
 * Returns { ledger, warnings, activated }.
 */
async function runZia(client, template, { dryRun, logger }) {
  const eng = new ZiaEngine(client, { dryRun, logger });
  const P = template.policies || {};

  // Custom URL categories the rules reference (created if missing; an existing one is reused as-is)
  const catIds = {};
  const customNames = new Set();
  for (const r of P.urlFiltering || []) if (r.requiresCustomCategory && r.customCategoryName) customNames.add(r.customCategoryName);
  if (customNames.size) {
    let cats = [];
    try { cats = list(await client.apiCall('GET', '/api/v1/urlCategories?customOnly=true')); } catch (e) { eng.warnings.push(`Could not read custom URL categories: ${e.message}`); }
    for (const nm of customNames) {
      const hit = cats.find(c => c.configuredName === nm);
      if (hit) { catIds[nm] = hit.id; eng.record({ category: 'URL Category', name: nm, action: 'NO_CHANGE', id: hit.id }); continue; }
      if (dryRun) { eng.record({ category: 'URL Category', name: nm, action: 'CREATE' }); continue; }
      try {
        const c = await client.apiCall('POST', '/api/v1/urlCategories', { configuredName: nm, superCategory: 'USER_DEFINED', urls: ['placeholder.example.com'], customCategory: true, description: 'Custom category created by the Zscaler Policy Wizard' });
        catIds[nm] = c.id; eng.wrote = true; eng.undo.push({ op: 'DELETE', path: `/api/v1/urlCategories/${c.id}`, label: `URL Category: ${nm}` }); eng.record({ category: 'URL Category', name: nm, action: 'CREATE', id: c.id });
      } catch (e) { eng.record({ category: 'URL Category', name: nm, action: 'FAILED', error: e.message }); }
    }
  }

  for (const r of P.urlFiltering || []) {
    if (r.requiresCustomCategory && r.customCategoryName && !catIds[r.customCategoryName] && !dryRun) {
      eng.record({ category: 'URL Filtering', name: r.name, action: 'SKIPPED', error: `Depends on custom category ${r.customCategoryName}, which failed` }); continue;
    }
    if (r.action === 'ISOLATE' && !(r.cbiProfile && r.cbiProfile.id)) {
      eng.record({ category: 'URL Filtering', name: r.name, action: 'SKIPPED', error: 'Isolate needs a Cloud Browser Isolation profile and this tenant has none.' }); continue;
    }
    await eng.upsert({ category: 'URL Filtering', name: r.name, listPath: '/api/v1/urlFilteringRules', createPath: '/api/v1/urlFilteringRules',
      updatePath: id => `/api/v1/urlFilteringRules/${id}`, orderPath: '/api/v1/urlFilteringRules', build: order => urlRuleBody(r, order, catIds) });
  }
  for (const r of P.firewallFiltering || []) {
    await eng.upsert({ category: 'Cloud Firewall', name: r.name, listPath: '/api/v1/firewallFilteringRules', createPath: '/api/v1/firewallFilteringRules',
      updatePath: id => `/api/v1/firewallFilteringRules/${id}`, orderPath: '/api/v1/firewallFilteringRules', build: order => firewallBody(r, order) });
  }
  if (P.sslInspection) {
    let sslLast = null;
    for (const r of P.sslInspection) {
      if (r.action !== 'INSPECT' && r.action !== 'DECRYPT' && Array.isArray(r.urlCategories) && r.urlCategories.length === 0) {
        eng.record({ category: 'SSL Inspection', name: r.name, action: 'SKIPPED', error: 'Do Not Inspect with no categories left would exempt all traffic.' }); continue;
      }
      await eng.upsert({ category: 'SSL Inspection', name: r.name, listPath: '/api/v1/sslInspectionRules', createPath: '/api/v1/sslInspectionRules',
        updatePath: id => `/api/v1/sslInspectionRules/${id}`, orderPath: '/api/v1/sslInspectionRules', orderOpts: { afterPredefined: true }, build: order => sslBody(r, order),
        // The catch-all (inspect everything remaining) goes last, below "Zscaler Recommended Exemptions" and the other predefined rules.
        placeLast: isSslCatchAll(r),
        createFallback: (e, body) => {
          if (!/not allowed at order/i.test(String(e.message))) return null;
          const all = eng.cache['/api/v1/sslInspectionRules'] || [];
          sslLast = sslLast || Math.max(0, ...all.filter(x => !x.defaultRule).map(x => x.order || 0)) + 1;
          return { body: { ...body, order: sslLast++ }, warning: 'placed after the existing SSL rules (the tenant did not allow it higher).' };
        } });
    }
  }
  for (const r of P.sandbox || []) {
    await eng.upsert({ category: 'Cloud Sandbox', name: r.name, listPath: '/api/v1/sandboxRules', createPath: '/api/v1/sandboxRules',
      updatePath: id => `/api/v1/sandboxRules/${id}`, orderPath: '/api/v1/sandboxRules', build: order => sandboxBody(r, order),
        // A rule created without a type the tenant can't sandbox (e.g. DMG without Sandbox macOS) stays as created.
        adjust: (body, existing) => (body.fileTypes || []).includes('FTCATEGORY_DMG') && !(existing.fileTypes || []).includes('FTCATEGORY_DMG')
          ? { ...body, fileTypes: body.fileTypes.filter(t => t !== 'FTCATEGORY_DMG') } : body,
        createFallback: (e, body) => {
          const m = String(e.message).match(/(\w+) file type is only available when subscribed to ([^."]+)/i);
          if (!m) return null;
          const ft = `FTCATEGORY_${m[1].toUpperCase()}`;
          const types = (body.fileTypes || []).filter(t => t !== ft);
          if (!types.length || types.length === (body.fileTypes || []).length) return null;
          return { body: { ...body, fileTypes: types }, warning: `${m[1].toUpperCase()} left out (needs ${m[2].trim()}).` };
        } });
  }
  let ztr;   // Zscaler Trusted Resolver gateway (auto-created by Zscaler, natZtrGateway)
  for (const r of P.dnsSecurity || []) {
    let gw = null;
    if (r.useTrustedResolver) {
      if (ztr === undefined) {
        try { ztr = list(await client.apiCall('GET', '/api/v1/dnsGateways')).find(g => g.natZtrGateway) || null; }
        catch (e) { ztr = null; eng.warnings.push(`Could not read DNS gateways: ${e.message}`); }
      }
      if (!ztr) { eng.record({ category: 'DNS Security', name: r.name, action: 'SKIPPED', error: 'This tenant has no Zscaler Trusted Resolver DNS gateway.' }); continue; }
      gw = ztr;
    }
    await eng.upsert({ category: 'DNS Security', name: r.name, listPath: '/api/v1/firewallDnsRules', createPath: '/api/v1/firewallDnsRules',
      updatePath: id => `/api/v1/firewallDnsRules/${id}`, orderPath: '/api/v1/firewallDnsRules', build: order => dnsBody(r, order, gw) });
  }
  for (const r of P.fileTypeControl || []) {
    await eng.upsert({ category: 'File Type Control', name: r.name, listPath: '/api/v1/fileTypeRules', createPath: '/api/v1/fileTypeRules',
      updatePath: id => `/api/v1/fileTypeRules/${id}`, orderPath: '/api/v1/fileTypeRules', build: order => fileTypeBody(r, order) });
  }
  for (const r of P.cloudAppControl || []) {
    const type = r.ruleType || r.type || 'AI_ML';
    const path = `/api/v1/webApplicationRules/${type}`;
    const sameSet = (a, b) => JSON.stringify([...(a || [])].sort()) === JSON.stringify([...(b || [])].sort());
    await eng.upsert({ category: 'Cloud App Control', name: r.name, listPath: path, createPath: path, updatePath: id => `${path}/${id}`, orderPath: path, build: order => cacBody(r, order),
      // A rule created with its fallback actions (the tenant refused the first set) stays as created on re-runs.
      adjust: (body, existing) => (r.fallbackActions && sameSet(existing.actions, r.fallbackActions)) ? { ...body, actions: existing.actions } : body,
      createFallback: (e, body) => {
        if (!r.fallbackActions || !/Invalid action|not supported|INVALID_INPUT/i.test(String(e.message))) return null;
        return { body: { ...body, actions: r.fallbackActions.slice() }, warning: `the tenant refused ${body.actions.join(', ')}; created with ${r.fallbackActions.join(', ')}.` };
      } });
  }

  // DLP: dictionaries → engines → rules (FWK-20/22: reuse predefined, update ours by name)
  if (P.dlp || P.endpointDlp) await runDlp(eng, template);

  // ATP defaults (GET → merge → PUT). Some tenants refuse fields behind feature flags: those fields are dropped and reported.
  if (P.advancedThreatProtection) {
    const values = {};
    for (const s of P.advancedThreatProtection.settings) if (!s.skip) values[s.key] = !!s.value;
    await eng.upsertSettings({ category: 'Advanced Threat Protection', name: P.advancedThreatProtection.name, path: '/api/v1/cyberThreatProtection/advancedThreatSettings', values,
      putFilter: (body) => putAtpWithFlagRetry(client, body) });
  }
  // AI Prompt Capture (fixed app list)
  if (P.aiPromptCapture) {
    const values = {};
    for (const s of P.aiPromptCapture.settings) values[s.key] = !!s.value;
    await eng.upsertSettings({ category: 'AI Prompt Capture', name: P.aiPromptCapture.name, path: '/api/v1/advancedUrlFilterAndCloudAppSettings', values });
  }
  if (P.ucaas) {
    const values = {};
    for (const s of P.ucaas.settings) values[s.key] = !!s.value;
    await eng.upsertSettings({ category: 'UCaaS', name: P.ucaas.name, path: '/api/v1/advancedUrlFilterAndCloudAppSettings', values });
  }

  const activated = await eng.activate();
  return { ledger: eng.ledger, warnings: eng.warnings, activated, undo: eng.undo };
}

/** PUT ATP; if a feature flag blocks some fields, drop them and retry once; still refused → skipped (not failed). */
async function putAtpWithFlagRetry(client, body) {
  try { await client.apiCall('PUT', '/api/v1/cyberThreatProtection/advancedThreatSettings', body); return {}; }
  catch (e) {
    if (!/feature flag/i.test(String(e.message))) throw e;
    const drop = Object.keys(body).filter(k => /mcp|agentic|genai|aiApp/i.test(k));
    const slim = { ...body }; for (const k of drop) delete slim[k];
    try { await client.apiCall('PUT', '/api/v1/cyberThreatProtection/advancedThreatSettings', slim); }
    catch (e2) {
      const err = new Error(`Skipped — a Zscaler feature flag on this tenant blocks ATP updates through the API (${(String(e2.message).match(/Feature Flag[^"]*/i) || [''])[0]}). Set these options in the portal.`);
      err.skipped = true; throw err;
    }
    return { notes: [`Advanced Threat Protection: left out ${drop.join(', ') || 'feature-flagged settings'} (not enabled on this tenant).`] };
  }
}

async function runDlp(eng, template) {
  const P = template.policies;
  const client = eng.client;
  let engines = [], dicts = [];
  try { engines = await eng.get('/api/v1/dlpEngines'); } catch (e) { eng.warnings.push(`Could not read DLP engines: ${e.message}`); }
  try { dicts = await eng.get('/api/v1/dlpDictionaries'); } catch (e) { eng.warnings.push(`Could not read DLP dictionaries: ${e.message}`); }
  const predefinedEngine = (key) => engines.find(e => e.predefinedEngineName === key || (!e.customDlpEngine && e.name === key));
  const predefinedDict = (key) => dicts.find(d => !d.custom && d.name === key);
  const dictIds = {}, engineIds = {}, failed = new Set();

  // Custom dictionaries (FWK-21)
  for (const d of template.dlpDictionaries || []) {
    const body = { name: d.name, description: `${d.description} Source: ${d.source ? d.source.title + ' ' + d.source.url : 'n/a'}`,
      dictionaryType: 'PATTERNS_AND_PHRASES', customPhraseMatchType: d.customPhraseMatchType || 'MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY',
      patterns: (d.patterns || []).map(p => ({ action: 'PATTERN_COUNT_TYPE_UNIQUE', pattern: p })),
      phrases: (d.phrases || []).map(p => ({ action: 'PHRASE_COUNT_TYPE_UNIQUE', phrase: p })) };
    const e = await eng.upsert({ category: 'DLP Dictionary', name: d.name, listPath: '/api/v1/dlpDictionaries', createPath: '/api/v1/dlpDictionaries',
      updatePath: id => `/api/v1/dlpDictionaries/${id}`, body, match: o => o.custom && o.name === d.name });
    if (e.action === 'FAILED') failed.add(d.name); else dictIds[d.name] = e.id;
  }
  // Custom engines (Block mode)
  for (const en of template.dlpEngines || []) {
    const ids = [], missing = [];
    for (const ref of en.dictRefs) {
      if (ref.custom) { if (failed.has(ref.custom)) missing.push(ref.custom); else ids.push(dictIds[ref.custom]); }
      else { const pd = predefinedDict(ref.predefined); if (pd) ids.push(pd.id); else missing.push(ref.predefined); }
    }
    if (missing.length) eng.warnings.push(`${en.name}: dictionaries not available, left out: ${missing.join(', ')}`);
    if (!ids.length) { failed.add(en.name); eng.record({ category: 'DLP Engine', name: en.name, action: 'SKIPPED', error: 'No usable dictionaries' }); continue; }
    const expr = '(' + ids.map(id => `(D${String(id).startsWith('new:') ? 'NEW' : id}.S> 1)`).join(' OR ') + ')';
    const e = await eng.upsert({ category: 'DLP Engine', name: en.name, listPath: '/api/v1/dlpEngines', createPath: '/api/v1/dlpEngines',
      updatePath: id => `/api/v1/dlpEngines/${id}`, body: { name: en.name, description: en.description, customDlpEngine: true, engineExpression: expr },
      match: o => o.customDlpEngine && o.name === en.name });
    if (e.action === 'FAILED') failed.add(en.name); else engineIds[en.name] = e.id;
  }
  // Inline (web) DLP rules
  for (const r of P.dlp || []) {
    let engineId = null;
    if (r.engineRef.predefined) {
      const pe = predefinedEngine(r.engineRef.predefined);
      if (!pe) { eng.record({ category: 'Inline DLP', name: r.name, action: 'SKIPPED', error: `Predefined DLP engine ${r.engineRef.predefined} is not available on this tenant` }); continue; }
      engineId = pe.id;
    } else {
      if (failed.has(r.engineRef.custom)) { eng.record({ category: 'Inline DLP', name: r.name, action: 'SKIPPED', error: `Depends on ${r.engineRef.custom}, which failed` }); continue; }
      engineId = engineIds[r.engineRef.custom];
    }
    const body = (order) => ({ name: r.name, description: r.description || '', order, rank: 7, state: 'ENABLED', protocols: ['ANY_RULE'],
      action: r.action === 'BLOCK' ? 'BLOCK' : 'ALLOW', severity: r.severity || 'RULE_SEVERITY_MEDIUM',
      dlpEngines: [{ id: engineId }], withoutContentInspection: false });
    await eng.upsert({ category: 'Inline DLP', name: r.name, listPath: '/api/v1/webDlpRules', createPath: '/api/v1/webDlpRules', updatePath: id => `/api/v1/webDlpRules/${id}`, build: body });
  }
  // Endpoint DLP (Monitor) — resources per channel come from the tenant
  for (const r of P.endpointDlp || []) {
    let resources = [];
    try { resources = list(await client.apiCall('GET', `/api/v1/dlpEndpointResource/${r.channel}`)); }
    catch (e) { eng.record({ category: 'Endpoint DLP', name: r.name, action: 'FAILED', error: /NOT_SUBSCRIBED|subscription/i.test(String(e.message)) ? 'Endpoint DLP is not licensed on this tenant' : e.message }); continue; }
    const engIds = r.engineRefs.map(x => predefinedEngine(x.predefined)).filter(Boolean).map(e => ({ id: e.id }));
    const body = (order) => ({ name: r.name, description: r.description, order, rank: 7, state: 'ENABLED', action: 'ALLOW', severity: r.severity,
      resources: resources.map(x => ({ id: x.id })), dlpEngines: engIds });
    await eng.upsert({ category: 'Endpoint DLP', name: r.name, listPath: '/api/v1/endPointDlpRules', createPath: '/api/v1/endPointDlpRules', updatePath: id => `/api/v1/endPointDlpRules/${id}`, build: body });
  }
}

module.exports = { runZia, ZiaEngine, diff, isSslCatchAll };
