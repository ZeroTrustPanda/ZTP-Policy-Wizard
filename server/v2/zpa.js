/**
 * Zscaler Private Access wizard (§5) and bulk manager (BRM-01..05) over OneAPI (GLB-01: same client credentials).
 * Paths: /zpa/mgmtconfig/v1/admin/customers/{customerId}/... (enrollment certificates under v2).
 * The customer ID comes from Mobile Admin getCompanyInfo.masterCustomerId (seen live).
 * Provisioning keys are secrets (GLB-09): never logged; only returned to the browser for the run summary.
 */
const COPY = require('./copy');

const list = (r) => (Array.isArray(r) ? r : (r && (r.list || r.items)) || []);

class ZPAClient {
  constructor(ziaClient, zccClient) { this.zia = ziaClient; this.zcc = zccClient; this.customerId = null; }

  async cid() {
    if (this.customerId) return this.customerId;
    const info = await this.zcc.apiCall('GET', '/zcc/papi/public/v1/getCompanyInfo');
    if (!info || !info.masterCustomerId) throw new Error('Could not find the ZPA customer ID for this tenant (Mobile Admin getCompanyInfo has no masterCustomerId). Is ZPA provisioned and in the API client\'s scope?');
    this.customerId = String(info.masterCustomerId);
    return this.customerId;
  }

  /** Raw call. Response bodies are never logged (they can contain provisioning keys). */
  async apiCall(method, path, body = null) {
    const z = this.zia;
    if (!z || !z.isAuthenticated() || z.authMode !== 'oneapi') throw new Error('ZPA needs a OneAPI sign-in.');
    const now = Date.now();
    if (z._lastRequestTime && now - z._lastRequestTime < 400) await z._sleep(400 - (now - z._lastRequestTime));
    z._lastRequestTime = Date.now();
    const headers = { 'Content-Type': 'application/json', Accept: 'application/json', Authorization: `Bearer ${z.accessToken}` };
    console.log(`[ZPA-API] ${method} ${path.replace(/customers\/\d+/, 'customers/<cid>')}`);
    const res = await z._rawRequest(method, z.baseUrl, path, body ? JSON.stringify(body) : null, headers);
    if (res.statusCode === 429) { await z._sleep(2000); return this.apiCall(method, path, body); }
    if (res.statusCode >= 200 && res.statusCode < 300) return res.body === '' ? null : res.body;
    const msg = typeof res.body === 'string' ? res.body.slice(0, 400) : JSON.stringify(res.body).replace(/"provisioningKey"\s*:\s*"[^"]*"/g, '"provisioningKey":"<redacted>"').slice(0, 400);
    throw new Error(`ZPA API Error ${res.statusCode}: ${msg}`);
  }

  async base(v = 'v1') { return `/zpa/mgmtconfig/${v}/admin/customers/${await this.cid()}`; }
  async listAll(rel, v = 'v1') {
    const out = [];
    for (let page = 1; page < 50; page++) {
      const r = await this.apiCall('GET', `${await this.base(v)}${rel}${rel.includes('?') ? '&' : '?'}page=${page}&pagesize=500`);
      const items = list(r);
      out.push(...items);
      const total = r && r.totalPages ? Number(r.totalPages) : 1;
      if (page >= total || !items.length) break;
    }
    return out;
  }
}

const PATHS = {
  connectorGroup: '/appConnectorGroup',
  provisioningKey: '/associationType/CONNECTOR_GRP/provisioningKey',
  segmentGroup: '/segmentGroup',
  serverGroup: '/serverGroup',
  appSegment: '/application'
};

// §5.2 defaults (editable in the UI, ZPA-21)
const APP_SEGMENT_DEFAULTS = {
  bypassType: 'NEVER',               // Use Client Forwarding Policy
  healthReporting: 'ON_ACCESS',      // On Access | CONTINUOUS | NONE
  selectConnectorCloseToApp: false,  // Closer to User (UDP is not supported with Closer to Application)
  icmpAccessType: 'PING',            // Pingable on
  clientlessAccess: false,
  adpEnabled: false,                 // Active Directory Inspection
  autoAppProtectEnabled: false,
  useInDrMode: false,                // Disaster Recovery
  ipAnchored: false,                 // Source IP Anchor
  tcpKeepAlive: '0',
  isCnameEnabled: true,
  doubleEncrypt: false,
  bypassOnReauth: false
};
const SAN_JOSE = { location: 'San Jose, CA, USA', cityCountry: 'San Jose, US', countryCode: 'US', latitude: '37.3382082', longitude: '-121.8863286' };

// ---------- validation (ZPA-10..13, VAL-01) ----------
const FQDN = /^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$/;
const WILDCARD = /^\*\.(?=.{1,251}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$/;
function ipv4(s) { const p = s.split('.'); return p.length === 4 && p.every(x => /^\d{1,3}$/.test(x) && +x <= 255); }
function cidr4(s) { const [ip, m] = s.split('/'); return m !== undefined && ipv4(ip) && /^\d{1,2}$/.test(m) && +m <= 32; }
function classifyEntry(raw) {
  const s = String(raw).trim();
  if (!s) return { ok: false, why: 'empty entry' };
  if (/^\*\./.test(s)) return WILDCARD.test(s) ? { ok: true, type: 'wildcard' } : { ok: false, why: 'not a valid wildcard domain (use *.example.com)' };
  if (s.includes('*')) return { ok: false, why: 'wildcards are only allowed as a leading *.' };
  if (s.includes('/')) return cidr4(s) ? { ok: true, type: 'cidr' } : { ok: false, why: 'not a valid IPv4 CIDR (e.g. 10.0.0.0/24)' };
  if (/^[\d.]+$/.test(s)) return ipv4(s) ? { ok: true, type: 'ip' } : { ok: false, why: 'not a valid IPv4 address' };
  return FQDN.test(s) ? { ok: true, type: 'fqdn' } : { ok: false, why: 'not a valid domain name' };
}
function splitEntries(v) { return (Array.isArray(v) ? v : String(v || '').split(/[,\n]/)).map(x => String(x).trim()).filter(Boolean); }
function parsePortRanges(v) {
  const out = [], errors = [];
  for (const part of splitEntries(v)) {
    const m = part.match(/^(\d{1,5})(?:\s*-\s*(\d{1,5}))?$/);
    if (!m) { errors.push(`"${part}" is not a port or range (e.g. 1-52)`); continue; }
    const a = +m[1], b = m[2] ? +m[2] : a;
    if (a < 1 || b > 65535 || a > b) { errors.push(`"${part}" must be within 1-65535 with the start before the end`); continue; }
    out.push([a, b]);
  }
  return { ranges: out, errors };
}

function validateZpaInput(input) {
  const errors = [];
  const entries = splitEntries(input.domains);
  if (!entries.length) errors.push('Enter at least one domain or IP for the application segment.');
  for (const e of entries) { const c = classifyEntry(e); if (!c.ok) errors.push(`"${e}": ${c.why}.`); }
  const tcp = parsePortRanges(input.tcpPorts), udp = parsePortRanges(input.udpPorts);
  errors.push(...tcp.errors.map(e => `TCP ports: ${e}`), ...udp.errors.map(e => `UDP ports: ${e}`));
  if (!tcp.ranges.length && !udp.ranges.length) errors.push('Enter at least one TCP or UDP port range.');
  if (!['ON_ACCESS', 'CONTINUOUS', 'NONE'].includes(input.settings?.healthReporting || 'ON_ACCESS')) errors.push('Health check must be On Access, Continuous or None.');
  return { errors, entries, tcp: tcp.ranges, udp: udp.ranges };
}

// ---------- plan / apply (GLB-03/05, VAL-02) ----------
const flat = (ranges) => ranges.flatMap(([a, b]) => [String(a), String(b)]);
const emptyish = (v) => v === undefined || v === null || v === false || v === '' || (Array.isArray(v) && !v.length);
function diffZpa(desired, existing) {
  const out = [];
  for (const [k, v] of Object.entries(desired)) {
    const e = existing[k];
    if (emptyish(v) && emptyish(e)) continue;
    if (Array.isArray(v)) {
      const n = (a) => (a || []).map(x => (x && typeof x === 'object') ? String(x.id) : String(x));
      const sorted = ['domainNames'].includes(k) ? (a) => n(a).sort() : n;
      if (JSON.stringify(sorted(v)) !== JSON.stringify(sorted(e))) out.push(k);
    } else if (String(v) !== String(e === undefined ? '' : e)) out.push(k);
  }
  return out;
}

/**
 * Run (or preview) the ZPA chain. Each step feeds the next; when one fails, the ones that depend on it are skipped.
 * input: { prefix, domains, tcpPorts, udpPorts, settings:{...APP_SEGMENT_DEFAULTS overrides}, connectorGroupId? (from the dropdown),
 *          descriptions:{connectorGroup, appSegment} }
 */
async function runZpa(zpa, input, { dryRun, logger }) {
  const v = validateZpaInput(input);
  if (v.errors.length) return { ledger: [], warnings: [], errors: v.errors, secrets: {} };
  const p = input.prefix;
  const names = {
    connectorGroup: `${p}-appconnector-group`, provisioningKey: `${p}-provisioning-key`,
    segmentGroup: `${p}-segment-group`, serverGroup: `${p}-server-group`, appSegment: `${p}-app-segment`
  };
  const ledger = [], warnings = [], secrets = {};
  const rec = (e) => { const x = { product: 'ZPA', ...e }; ledger.push(x); if (logger && !dryRun) logger.logPolicyApply(`ZPA ${e.category}`, e.name, e.action, e.error ? { error: e.error } : { success: true, id: e.id }); return x; };
  const base = await zpa.base();

  async function upsert(kind, category, name, body, { createPath, updatePath, listRel, fetchFull } = {}) {
    const rel = listRel || PATHS[kind];
    let existing;
    try { existing = (await zpa.listAll(rel)).find(o => o.name === name); }
    catch (e) { return rec({ category, name, action: 'FAILED', error: `Could not read existing objects: ${e.message}` }); }
    if (existing) {
      const full = fetchFull ? await zpa.apiCall('GET', `${base}${rel}/${existing.id}`).catch(() => existing) : existing;
      const changes = diffZpa(body, full);
      if (!changes.length) return rec({ category, name, action: 'NO_CHANGE', id: existing.id, existing: full });
      if (dryRun) return rec({ category, name, action: 'UPDATE', id: existing.id, changes, existing: full });
      try {
        await zpa.apiCall('PUT', `${base}${updatePath || rel}/${existing.id}`, { ...full, ...body, id: existing.id });
        return rec({ category, name, action: 'UPDATE', id: existing.id, changes, existing: full });
      } catch (e) { return rec({ category, name, action: 'FAILED', id: existing.id, error: e.message, changes }); }
    }
    if (dryRun) return rec({ category, name, action: 'CREATE', id: `new:${kind}` });
    try {
      const created = await zpa.apiCall('POST', `${base}${createPath || rel}`, body);
      return rec({ category, name, action: 'CREATE', id: created && created.id, created });
    } catch (e) { return rec({ category, name, action: 'FAILED', error: e.message }); }
  }
  const dead = (e) => !e || e.action === 'FAILED' || e.action === 'SKIPPED';
  const skip = (category, name, dep) => rec({ category, name, action: 'SKIPPED', error: `Depends on ${dep}, which failed` });

  // Connector certificate (ZPA-01/03)
  let certId = null;
  try {
    const certs = await zpa.listAll('/enrollmentCert', 'v2');
    const c = certs.find(x => x.name === 'Connector');
    if (c) certId = String(c.id); else warnings.push('No "Connector" enrollment certificate found; ZPA will use its default.');
  } catch (e) { warnings.push(`Could not read enrollment certificates: ${e.message}`); }

  // 1. App Connector Group (ZPA-01) — location San Jose, CA; upgrade schedule and version profile left at defaults
  const cg = await upsert('connectorGroup', 'App Connector Group', names.connectorGroup, {
    name: names.connectorGroup, description: input.descriptions?.connectorGroup || COPY.zpa.connectorGroupDescription, enabled: true,
    ...SAN_JOSE, ...(certId ? { enrollmentCertId: certId } : {})
  });
  // Location is only set on create, so a re-run never undoes the "change the location in the portal" follow-up
  if (cg.action === 'UPDATE' && cg.changes && cg.changes.every(c => ['location', 'cityCountry', 'countryCode', 'latitude', 'longitude'].includes(c))) {
    cg.action = 'NO_CHANGE'; cg.note = 'Location differs from San Jose, CA (changed in the portal) — left as is.'; delete cg.changes;
  }
  let cgId = dead(cg) ? null : cg.id;
  if (input.connectorGroupId) cgId = input.connectorGroupId;   // ZPA-03 dropdown

  // 2. Provisioning key (ZPA-03/04)
  let pk;
  if (!cgId) pk = skip('Provisioning Key', names.provisioningKey, names.connectorGroup);
  else {
    pk = await upsert('provisioningKey', 'Provisioning Key', names.provisioningKey, {
      name: names.provisioningKey, associationType: 'CONNECTOR_GRP', maxUsage: '5', enabled: true,
      zcomponentId: String(cgId).startsWith('new:') ? undefined : String(cgId), ...(certId ? { enrollmentCertId: certId } : {})
    }, { fetchFull: true });
    if (!dryRun && !dead(pk)) {
      const key = (pk.created && pk.created.provisioningKey) || (pk.existing && pk.existing.provisioningKey);
      if (key) secrets.provisioningKey = key;
      else {
        try { const full = await zpa.apiCall('GET', `${base}${PATHS.provisioningKey}/${pk.id}`); if (full && full.provisioningKey) secrets.provisioningKey = full.provisioningKey; } catch (e) { /* shown as unavailable */ }
      }
    }
    delete pk.created; delete pk.existing;
  }
  delete cg.created; delete cg.existing;

  // 3. Segment group (ZPA-05)
  const sg = await upsert('segmentGroup', 'Segment Group', names.segmentGroup, { name: names.segmentGroup, enabled: true });
  // 4. Server group (ZPA-06): Dynamic Server Discovery on, the connector group from step 1
  let svg;
  if (!cgId) svg = skip('Server Group', names.serverGroup, names.connectorGroup);
  else svg = await upsert('serverGroup', 'Server Group', names.serverGroup, {
    name: names.serverGroup, enabled: true, dynamicDiscovery: true, appConnectorGroups: [{ id: String(cgId) }]
  });
  // 5. App segment (ZPA-07, §5.2)
  const s = { ...APP_SEGMENT_DEFAULTS, ...(input.settings || {}) };
  let as;
  if (dead(sg) || dead(svg)) as = skip('Application Segment', names.appSegment, dead(sg) ? names.segmentGroup : names.serverGroup);
  else {
    const body = {
      name: names.appSegment, description: input.descriptions?.appSegment || COPY.zpa.appSegmentDescription, enabled: true,
      domainNames: v.entries, segmentGroupId: String(sg.id), serverGroups: [{ id: String(svg.id) }],
      tcpPortRanges: flat(v.tcp), udpPortRanges: flat(v.udp),
      bypassType: s.bypassType, healthReporting: s.healthReporting, healthCheckType: s.healthReporting === 'NONE' ? 'NONE' : 'DEFAULT',
      selectConnectorCloseToApp: !!s.selectConnectorCloseToApp, icmpAccessType: s.icmpAccessType === 'PING' || s.icmpAccessType === true ? 'PING' : 'NONE',
      isCnameEnabled: !!s.isCnameEnabled, ipAnchored: !!s.ipAnchored, doubleEncrypt: !!s.doubleEncrypt, bypassOnReauth: !!s.bypassOnReauth,
      tcpKeepAlive: s.tcpKeepAlive === true || s.tcpKeepAlive === '1' ? '1' : '0', adpEnabled: !!s.adpEnabled, autoAppProtectEnabled: !!s.autoAppProtectEnabled,
      useInDrMode: !!s.useInDrMode, passiveHealthEnabled: true
    };
    if (String(body.segmentGroupId).startsWith('new:')) body.segmentGroupId = '(new)';
    as = await upsert('appSegment', 'Application Segment', names.appSegment, body, { fetchFull: true });
    if (s.clientlessAccess) warnings.push('Clientless (browser) access needs a web server certificate and per-application settings; enable it in the ZPA portal.');
  }
  return { ledger, warnings, errors: [], secrets, names, followUps: [COPY.report.followUps.zpaLocation, COPY.report.followUps.zpaDeploy] };
}

// ---------- bulk manager (BRM-01..05) ----------
const DELETE_ORDER = ['appSegment', 'serverGroup', 'segmentGroup', 'provisioningKey', 'connectorGroup'];
const KIND_LABEL = { appSegment: 'Application Segment', serverGroup: 'Server Group', segmentGroup: 'Segment Group', provisioningKey: 'Provisioning Key', connectorGroup: 'App Connector Group' };

async function listZpaObjects(zpa, prefix) {
  const out = [];
  for (const kind of DELETE_ORDER) {
    try {
      for (const o of await zpa.listAll(PATHS[kind])) {
        if (prefix && !String(o.name || '').startsWith(prefix)) continue;
        out.push({ kind, label: KIND_LABEL[kind], id: String(o.id), name: o.name, enabled: o.enabled, detail: kind === 'provisioningKey' ? `used ${o.usageCount || 0} of ${o.maxUsage}` : (o.description || '') });
      }
    } catch (e) { out.push({ kind, label: KIND_LABEL[kind], error: e.message }); }
  }
  return out;
}

/** Delete selected objects in dependency order (BRM-04). dryRun returns the planned order only. */
async function deleteZpaObjects(zpa, items, { dryRun, logger }) {
  const base = await zpa.base();
  const sorted = [...items].sort((a, b) => DELETE_ORDER.indexOf(a.kind) - DELETE_ORDER.indexOf(b.kind));
  const results = [];
  for (const it of sorted) {
    if (!PATHS[it.kind]) { results.push({ ...it, action: 'FAILED', error: 'Unknown object type' }); continue; }
    if (dryRun) { results.push({ ...it, action: 'DELETE' }); continue; }
    try {
      const q = it.kind === 'appSegment' ? '?forceDelete=true' : '';
      await zpa.apiCall('DELETE', `${base}${PATHS[it.kind]}/${it.id}${q}`);
      results.push({ ...it, action: 'DELETED' });
      if (logger) logger.logPolicyApply(`ZPA ${KIND_LABEL[it.kind]}`, it.name, 'DELETE', { success: true, id: it.id });
    } catch (e) {
      results.push({ ...it, action: 'FAILED', error: e.message });
      if (logger) logger.logPolicyApply(`ZPA ${KIND_LABEL[it.kind]}`, it.name, 'DELETE', { error: e.message });
    }
  }
  return results;
}

module.exports = { ZPAClient, runZpa, validateZpaInput, classifyEntry, splitEntries, parsePortRanges, APP_SEGMENT_DEFAULTS, SAN_JOSE,
  listZpaObjects, deleteZpaObjects, DELETE_ORDER, KIND_LABEL };
