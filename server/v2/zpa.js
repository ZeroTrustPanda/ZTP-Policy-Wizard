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
  async apiCall(method, path, body = null, attempt = 0) {
    const z = this.zia;
    if (!z || !z.isAuthenticated() || z.authMode !== 'oneapi') throw new Error('ZPA needs a OneAPI sign-in.');
    const now = Date.now();
    if (z._lastRequestTime && now - z._lastRequestTime < 400) await z._sleep(400 - (now - z._lastRequestTime));
    z._lastRequestTime = Date.now();
    const headers = { 'Content-Type': 'application/json', Accept: 'application/json', Authorization: `Bearer ${z.accessToken}` };
    console.log(`[ZPA-API] ${method} ${path.replace(/customers\/\d+/, 'customers/<cid>')}`);
    const res = await z._rawRequest(method, z.baseUrl, path, body ? JSON.stringify(body) : null, headers);
    if (res.statusCode === 429) {
      const wait = parseInt((res.headers || {})['retry-after']) || 2;
      if (wait > 30 || attempt >= 3) throw new Error(`ZPA API rate limit reached (HTTP 429). Wait about ${Math.max(1, Math.ceil(wait / 60))} minute(s) and run the dry run again.`);
      await z._sleep(wait * 1000); return this.apiCall(method, path, body, attempt + 1);
    }
    if (res.statusCode >= 200 && res.statusCode < 300) return res.body === '' ? null : res.body;
    const raw = typeof res.body === 'string' ? res.body : JSON.stringify(res.body);
    const msg = raw.replace(/"provisioningKey"\s*:\s*"[^"]*"/g, '"provisioningKey":"<redacted>"').replace(/\d+\|[A-Za-z0-9+/=]{20,}[^"\s]*/g, '<redacted>').slice(0, 400);
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
  appSegment: '/application',
  praConsole: '/praConsole',
  inspectionProfile: '/inspectionProfile'
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
  tcpKeepAlive: false,               // sent to ZPA as "0" / "1"
  isCnameEnabled: true,
  doubleEncrypt: false,
  bypassOnReauth: false
};
// Default ZPA policies built for the application segment(s) (on by default; each can be turned off in the UI)
// v2.2 isolation profile security controls (CBI): none = blocked; upstream = local → isolated only
const ISOLATION_DEFAULTS = { enabled: true, copyPaste: 'none', uploadDownload: 'none', allowPrinting: false, watermark: true, watermarkMessage: 'Zscaler POV' };
const POLICY_DEFAULTS = { access: true, timeout: true, inspection: true, isolation: true };
const TIMEOUTS = { reauthTimeout: '28800', reauthIdleTimeout: '3600' };   // seconds: re-authenticate every 8 hours, or after 1 hour idle
const OWASP_FALLBACK = 'OWASP_CRS/4.8.0';   // live: tenants refuse new profiles on 3.3.0; the current version comes from /inspectionControls/predefined/versions
const PRA_PROTOCOLS = { rdp: { protocol: 'RDP', port: '3389' }, ssh: { protocol: 'SSH', port: '22' } };
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

function praErrors(pra) {
  const out = [];
  for (const k of ['rdp', 'ssh']) {
    const h = String((pra || {})[`${k}Host`] || '').trim();
    if (!h) continue;
    const c = classifyEntry(h);
    if (!c.ok || (c.type !== 'fqdn' && c.type !== 'ip')) out.push(`PRA ${k.toUpperCase()} host "${h}": enter one server name or IP address (no wildcard or subnet).`);
  }
  return out;
}
function browserAccessErrors(ba) {
  const d = String((ba || {}).domain || '').trim();
  if (!d) return [];
  const out = [];
  const c = classifyEntry(d);
  if (!c.ok || c.type !== 'fqdn') out.push(`Browser Access domain "${d}": enter one web server name (for example ehr.hospital.org).`);
  if (!/^\d{1,5}$/.test(String(ba.port || '443')) || +ba.port > 65535) out.push('Browser Access port must be a number from 1 to 65535.');
  return out;
}
function validateZpaInput(input) {
  const pe = [...praErrors(input.pra), ...browserAccessErrors(input.browserAccess)];
  const r = validateZpaInputCore(input);
  r.errors.push(...pe);
  return r;
}
function validateZpaInputCore(input) {
  if (Array.isArray(input.apps) && input.apps.length) {
    const b = validateBulkApps(input.apps);
    if (!['ON_ACCESS', 'CONTINUOUS', 'NONE'].includes(input.settings?.healthReporting || 'ON_ACCESS')) b.errors.push('Health check must be On Access, Continuous or None.');
    for (const a of input.apps) if (a.settings && a.settings.healthReporting && !['ON_ACCESS', 'CONTINUOUS', 'NONE'].includes(a.settings.healthReporting)) b.errors.push(`${a.name}: health check must be On Access, Continuous or None.`);
    for (const a of b.apps) {
      const health = (a.settings && a.settings.healthReporting) || input.settings?.healthReporting || 'ON_ACCESS';
      const subnets = a.entries.filter(e => classifyEntry(e).type === 'cidr');
      if (health === 'CONTINUOUS' && subnets.length) b.errors.push(`${a.name}: ZPA does not allow Continuous health checks on subnet destinations (${subnets.join(', ')}). Use On Access or None for this application.`);
    }
    return { errors: b.errors, bulk: b.apps, entries: [], tcp: [], udp: [] };
  }
  const errors = [];
  const entries = splitEntries(input.domains);
  if (!entries.length) errors.push('Enter at least one domain or IP for the application segment.');
  for (const e of entries) { const c = classifyEntry(e); if (!c.ok) errors.push(`"${e}": ${c.why}.`); }
  const tcp = parsePortRanges(input.tcpPorts), udp = parsePortRanges(input.udpPorts);
  errors.push(...tcp.errors.map(e => `TCP ports: ${e}`), ...udp.errors.map(e => `UDP ports: ${e}`));
  if (!tcp.ranges.length && !udp.ranges.length) errors.push('Enter at least one TCP or UDP port range.');
  if (!['ON_ACCESS', 'CONTINUOUS', 'NONE'].includes(input.settings?.healthReporting || 'ON_ACCESS')) errors.push('Health check must be On Access, Continuous or None.');
  const subnets = entries.filter(e => classifyEntry(e).type === 'cidr');
  if (input.settings?.healthReporting === 'CONTINUOUS' && subnets.length) errors.push(`ZPA does not allow Continuous health checks on subnet destinations (${subnets.join(', ')}). Use On Access or None.`);
  return { errors, entries, tcp: tcp.ranges, udp: udp.ranges };
}

// ---------- bulk application segments from a CSV (ZPA bulk upload) ----------
// Columns: Application Name, Destinations, Ports. Inside a cell, separate multiple values with ";" (or new lines,
// "|" or spaces; commas also work when the cell is in quotes). Ports: 443, 8000-8100, udp:53, tcp:22 (TCP when no prefix).
function parseCsvRows(text) {
  const rows = []; let row = [], cell = '', q = false;
  const src = String(text || '').replace(/^﻿/, '');
  for (let i = 0; i < src.length; i++) {
    const ch = src[i];
    if (q) {
      if (ch === '"') { if (src[i + 1] === '"') { cell += '"'; i++; } else q = false; }
      else cell += ch;
    } else if (ch === '"') q = true;
    else if (ch === ',') { row.push(cell); cell = ''; }
    else if (ch === '\n' || ch === '\r') { if (ch === '\r' && src[i + 1] === '\n') i++; row.push(cell); rows.push(row); row = []; cell = ''; }
    else cell += ch;
  }
  if (cell !== '' || row.length) { row.push(cell); rows.push(row); }
  return rows.filter(r => r.some(c => String(c).trim()));
}
const splitCell = (v) => String(v || '').split(/[;|\n,\s]+/).map(x => x.trim()).filter(Boolean);
function splitPorts(cell) {
  const tcp = [], udp = [], bad = [];
  for (const t of splitCell(cell)) {
    const m = t.match(/^(tcp|udp|t|u)?\s*[:=]?\s*(\d{1,5}(?:-\d{1,5})?)$/i);
    if (!m) { bad.push(t); continue; }
    (m[1] && /^u/i.test(m[1]) ? udp : tcp).push(m[2]);
  }
  return { tcp: tcp.join(', '), udp: udp.join(', '), bad };
}
const COL = { name: /^(app(lication)?\s*name|name|application|app)$/i, dest: /^(destinations?|fqdn|fqdn\s*\/\s*ip|domains?|hosts?|ips?|addresses|fqdns?\s*\/\s*ips?)$/i, ports: /^ports?$/i, tcp: /^tcp(\s*ports?)?$/i, udp: /^udp(\s*ports?)?$/i };
/** CSV text → { apps:[{name, destinations[], tcpPorts, udpPorts, row}], errors[] } */
function parseBulkCsv(text) {
  const rows = parseCsvRows(text);
  const errors = [];
  if (!rows.length) return { apps: [], errors: ['The file is empty.'] };
  const head = rows[0].map(c => String(c).trim());
  let idx = { name: head.findIndex(h => COL.name.test(h)), dest: head.findIndex(h => COL.dest.test(h)), ports: head.findIndex(h => COL.ports.test(h)), tcp: head.findIndex(h => COL.tcp.test(h)), udp: head.findIndex(h => COL.udp.test(h)) };
  let body = rows.slice(1);
  if (idx.name < 0 || idx.dest < 0) { idx = { name: 0, dest: 1, ports: 2, tcp: -1, udp: -1 }; body = rows; }   // no header row
  const apps = [];
  body.forEach((r, i) => {
    const rowNo = i + (body === rows ? 1 : 2);
    const name = String(r[idx.name] || '').trim();
    const destinations = splitCell(r[idx.dest]);
    let tcp = [], udp = [], bad = [];
    if (idx.ports >= 0) { const p = splitPorts(r[idx.ports]); tcp.push(p.tcp); udp.push(p.udp); bad.push(...p.bad); }
    if (idx.tcp >= 0) tcp.push(splitCell(r[idx.tcp]).join(', '));
    if (idx.udp >= 0) udp.push(splitCell(r[idx.udp]).join(', '));
    if (bad.length) errors.push(`Row ${rowNo} (${name || 'no name'}): ports ${bad.map(b => `"${b}"`).join(', ')} not understood (use 443, 8000-8100 or udp:53).`);
    apps.push({ name, destinations, tcpPorts: tcp.filter(Boolean).join(', '), udpPorts: udp.filter(Boolean).join(', '), row: rowNo });
  });
  return { apps, errors };
}
const APP_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9 _.()&-]{0,99}$/;
const segmentName = (prefix, appName) => `${prefix}-${String(appName).trim().replace(/\s+/g, '-')}`;
const overlaps = (a, b) => a.some(([a1, a2]) => b.some(([b1, b2]) => a1 <= b2 && b1 <= a2));
/** Validate the uploaded apps (names, destinations, ports, and clashes ZPA would reject). */
function validateBulkApps(apps) {
  const errors = [], out = [];
  const seen = new Map();
  for (const a of apps || []) {
    const label = `${a.row ? `Row ${a.row}: ` : ''}${a.name || '(no name)'}`;
    if (!a.name || !APP_NAME_RE.test(String(a.name).trim())) errors.push(`${label}: the application name must start with a letter or digit and use letters, digits, spaces and _ . ( ) & - (up to 100 characters).`);
    const key = String(a.name || '').trim().toLowerCase();
    if (key && seen.has(key)) errors.push(`${label}: the name is used twice (also row ${seen.get(key)}).`); else seen.set(key, a.row || '?');
    const dests = Array.isArray(a.destinations) ? a.destinations : splitCell(a.destinations);
    if (!dests.length) errors.push(`${label}: no destinations (FQDN, *.domain, IP or CIDR).`);
    for (const d of dests) { const c = classifyEntry(d); if (!c.ok) errors.push(`${label}: "${d}" ${c.why}.`); }
    const tcp = parsePortRanges(a.tcpPorts), udp = parsePortRanges(a.udpPorts);
    errors.push(...tcp.errors.map(e => `${label}: TCP ${e}`), ...udp.errors.map(e => `${label}: UDP ${e}`));
    if (!tcp.ranges.length && !udp.ranges.length) errors.push(`${label}: no ports.`);
    out.push({ ...a, name: String(a.name || '').trim(), entries: dests, tcp: tcp.ranges, udp: udp.ranges });
  }
  // ZPA refuses the same destination in two application segments when their ports overlap
  for (let i = 0; i < out.length; i++) for (let j = i + 1; j < out.length; j++) {
    const shared = out[i].entries.filter(d => out[j].entries.some(e => e.toLowerCase() === d.toLowerCase()));
    if (shared.length && (overlaps(out[i].tcp, out[j].tcp) || overlaps(out[i].udp, out[j].udp)))
      errors.push(`${out[i].name} and ${out[j].name} both include ${shared.join(', ')} on overlapping ports; ZPA does not allow that. Merge them into one row or split the ports.`);
  }
  if (!out.length) errors.push('Upload at least one application.');
  return { errors, apps: out };
}

// ---------- plan / apply (GLB-03/05, VAL-02) ----------
const flat = (ranges) => ranges.flatMap(([a, b]) => [String(a), String(b)]);
const emptyish = (v) => v === undefined || v === null || v === false || v === '' || (Array.isArray(v) && !v.length);
function diffZpa(desired, existing) {
  const out = [];
  for (const [k, v] of Object.entries(desired)) {
    if (k === 'associationType') continue;   // write-only: GET never returns it
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
  const ledger = [], warnings = [], secrets = {}, undo = [];
  const rec = (e) => { const x = { product: 'ZPA', ...e }; ledger.push(x); if (logger && !dryRun) logger.logPolicyApply(`ZPA ${e.category}`, e.name, e.action, e.error ? { error: e.error } : { success: true, id: e.id }); return x; };
  const base = await zpa.base();

  async function upsert(kind, category, name, body, { createPath, updatePath, listRel, fetchFull, createOnly = [] } = {}) {
    const rel = listRel || PATHS[kind];
    let existing;
    try { existing = (await zpa.listAll(rel)).find(o => o.name === name); }
    catch (e) { return rec({ category, name, action: 'FAILED', error: `Could not read existing objects: ${e.message}` }); }
    if (existing) {
      const full = fetchFull ? await zpa.apiCall('GET', `${base}${rel}/${existing.id}`).catch(() => existing) : existing;
      // Fields set only on create (e.g. the connector group location the SE changes in the portal) are never compared or sent on update
      if (createOnly.length) { body = { ...body }; for (const k of createOnly) delete body[k]; }
      const changes = diffZpa(body, full);
      if (!changes.length) return rec({ category, name, action: 'NO_CHANGE', id: existing.id, existing: full });
      const det = changes.map(k => ({ field: k, from: shortVal(full[k]), to: shortVal(body[k]) }));
      if (dryRun) return rec({ category, name, action: 'UPDATE', id: existing.id, changes, details: det, existing: full });
      try {
        await zpa.apiCall('PUT', `${base}${updatePath || rel}/${existing.id}`, { ...full, ...body, id: existing.id });
        const before = { ...full }; delete before.provisioningKey;   // never kept: the key is a secret
        undo.push({ op: 'PUT', path: `${base}${updatePath || rel}/${existing.id}`, body: before, label: `${category}: ${name}` });
        return rec({ category, name, action: 'UPDATE', id: existing.id, changes, details: det, existing: full });
      } catch (e) { return rec({ category, name, action: 'FAILED', id: existing.id, error: e.message, changes }); }
    }
    if (dryRun) return rec({ category, name, action: 'CREATE', id: `new:${kind}` });
    try {
      const created = await zpa.apiCall('POST', `${base}${createPath || rel}`, body);
      if (created && created.id) undo.push({ op: 'DELETE', path: `${base}${createPath || rel}/${created.id}${kind === 'appSegment' ? '?forceDelete=true' : ''}`, label: `${category}: ${name}` });
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
  }, { createOnly: ['location', 'cityCountry', 'countryCode', 'latitude', 'longitude'] });
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
  // 5. App segment(s) (ZPA-07, §5.2): one wildcard segment, or one segment per uploaded application
  const segments = v.bulk
    ? v.bulk.map(a => ({ name: segmentName(p, a.name), entries: a.entries, tcp: a.tcp, udp: a.udp, settings: a.settings || {}, description: a.description || `${a.name}: application segment created by the Zscaler Policy Wizard (bulk upload).` }))
    : [{ name: names.appSegment, entries: v.entries, tcp: v.tcp, udp: v.udp, settings: {}, description: input.descriptions?.appSegment || COPY.zpa.appSegmentDescription }];
  if (v.bulk) names.appSegments = segments.map(x => x.name);
  const segIds = [];
  for (const seg of segments) {
  const s = { ...APP_SEGMENT_DEFAULTS, ...(input.settings || {}), ...seg.settings };
  let as;
  if (dead(sg) || dead(svg)) as = skip('Application Segment', seg.name, dead(sg) ? names.segmentGroup : names.serverGroup);
  else {
    const body = {
      name: seg.name, description: seg.description, enabled: true,
      domainNames: seg.entries, segmentGroupId: String(sg.id), serverGroups: [{ id: String(svg.id) }],
      tcpPortRanges: flat(seg.tcp), udpPortRanges: flat(seg.udp),
      bypassType: s.bypassType, healthReporting: s.healthReporting, healthCheckType: s.healthReporting === 'NONE' ? 'NONE' : 'DEFAULT',
      selectConnectorCloseToApp: !!s.selectConnectorCloseToApp, icmpAccessType: s.icmpAccessType === 'PING' || s.icmpAccessType === true ? 'PING' : 'NONE',
      isCnameEnabled: !!s.isCnameEnabled, ipAnchored: !!s.ipAnchored, doubleEncrypt: !!s.doubleEncrypt, bypassOnReauth: !!s.bypassOnReauth,
      tcpKeepAlive: s.tcpKeepAlive === true || s.tcpKeepAlive === '1' ? '1' : '0', adpEnabled: !!s.adpEnabled, autoAppProtectEnabled: !!s.autoAppProtectEnabled,
      useInDrMode: !!s.useInDrMode, passiveHealthEnabled: true
    };
    if (String(body.segmentGroupId).startsWith('new:')) body.segmentGroupId = '(new)';
    if (s.selectConnectorCloseToApp && seg.udp.length) warnings.push(`${seg.name}: UDP ports are not supported with Closer to Application; ZPA may reject this segment.`);
    as = await upsert('appSegment', 'Application Segment', seg.name, body, { fetchFull: true });
    delete as.existing; delete as.created;
    if (s.clientlessAccess) warnings.push(`${seg.name}: Clientless (browser) access needs a web server certificate and per-application settings; enable it in the ZPA portal.`);
    segIds.push(as);
  }
  }

  // 5b. Browser Access (clientless): one web application published through ZPA with an uploaded/existing web certificate
  const ba = input.browserAccess || {};
  if (String(ba.domain || '').trim()) {
    const host = String(ba.domain).trim(), port = String(ba.port || '443');
    names.browserAccess = `${p}-browser-access`;
    if (dead(sg) || dead(svg)) skip('Browser Access Application', names.browserAccess, dead(sg) ? names.segmentGroup : names.serverGroup);
    else if (!ba.certificateId) rec({ category: 'Browser Access Application', name: names.browserAccess, action: 'SKIPPED', error: 'Pick a web server certificate for the Browser Access domain.' });
    else {
      const body = { name: names.browserAccess, description: `Browser Access (no client) to https://${host}. Created by the Zscaler Policy Wizard.`, enabled: true,
        domainNames: [host], segmentGroupId: String(sg.id), serverGroups: [{ id: String(svg.id) }], tcpPortRanges: [port, port],
        bypassType: 'NEVER', healthReporting: 'ON_ACCESS', healthCheckType: 'DEFAULT', isCnameEnabled: true, icmpAccessType: 'NONE',
        clientlessApps: [{ name: host, domain: host, applicationPort: port, applicationProtocol: ba.protocol === 'HTTP' ? 'HTTP' : 'HTTPS', certificateId: String(ba.certificateId),
          enabled: true, trustUntrustedCert: true, allowOptions: false, path: '/' }] };
      if (String(body.segmentGroupId).startsWith('new:')) body.segmentGroupId = '(new)';
      const b = await upsert('appSegment', 'Browser Access Application', names.browserAccess, body, { fetchFull: true, createOnly: ['clientlessApps'] });
      if (b.existing) { const url = ((b.existing.clientlessApps || [])[0] || {}).extDomainName; if (url) names.browserAccessUrl = `https://${url}`; }
      delete b.existing; delete b.created;
      segIds.push(b);
    }
  }

  // Cloud Browser Isolation profile (ZPA CBI service). Created profiles appear as ZPA isolation profiles with the same name.
  async function upsertCbiProfile(name, iso) {
    const C = `/zpa/cbiconfig/cbi/api/customers/${await zpa.cid()}`;
    const sc = { copyPaste: iso.copyPaste, uploadDownload: iso.uploadDownload, allowPrinting: !!iso.allowPrinting, documentViewer: true, localRender: true,
      restrictKeystrokes: false, cameraAndMic: false, flattenedPdf: false, deepLink: { enabled: false, applications: [] },
      watermark: { enabled: !!iso.watermark, showUserId: !!iso.watermark, showTimestamp: !!iso.watermark, showMessage: !!iso.watermark, message: String(iso.watermarkMessage || 'Zscaler POV').slice(0, 64) } };
    const profiles = list(await zpa.apiCall('GET', `${C}/profiles`));
    const existing = profiles.find(x => x.name === name);
    const cat = 'Isolation Profile';
    if (existing) {
      const full = await zpa.apiCall('GET', `${C}/profiles/${existing.id}`);
      const cur = full.securityControls || {};
      const changes = ['copyPaste', 'uploadDownload', 'allowPrinting'].filter(k => String(cur[k]) !== String(sc[k]));
      if (!!(cur.watermark || {}).enabled !== sc.watermark.enabled || ((cur.watermark || {}).message || '') !== (sc.watermark.enabled ? sc.watermark.message : ((cur.watermark || {}).message || ''))) changes.push('watermark');
      if (!changes.length) rec({ category: cat, name, action: 'NO_CHANGE', id: existing.id });
      else if (dryRun) rec({ category: cat, name, action: 'UPDATE', id: existing.id, changes, details: changes.map(k => ({ field: k, from: shortVal(k === 'watermark' ? cur.watermark : cur[k]), to: shortVal(k === 'watermark' ? sc.watermark : sc[k]) })) });
      else {
        const body = { ...full, securityControls: { ...cur, ...sc } };
        for (const k of ['regions', 'certificates']) if (Array.isArray(full[k])) { body[k === 'regions' ? 'regionIds' : 'certificateIds'] = full[k].map(x => x.id); delete body[k]; }
        if (full.banner && full.banner.id) { body.bannerId = full.banner.id; delete body.banner; }
        await zpa.apiCall('PUT', `${C}/profiles/${existing.id}`, body);
        undo.push({ op: 'PUT', path: `${C}/profiles/${existing.id}`, body: { ...body, securityControls: cur }, label: `${cat}: ${name}` });
        rec({ category: cat, name, action: 'UPDATE', id: existing.id, changes });
      }
    } else if (dryRun) {
      rec({ category: cat, name, action: 'CREATE', id: 'new:isolationProfile' });
      return { id: '(new)', name };
    } else {
      const regions = list(await zpa.apiCall('GET', `${C}/regions`)), certs = list(await zpa.apiCall('GET', `${C}/certificates`)), banners = list(await zpa.apiCall('GET', `${C}/banners`));
      const near = regions.filter(r => /Ohio|Portland|Washington/i.test(r.name));
      const c = await zpa.apiCall('POST', `${C}/profiles`, { name, description: 'Isolation settings for the POV (copy / paste, upload / download, printing, watermark). Created by the Zscaler Policy Wizard.',
        regionIds: (near.length >= 2 ? near : regions.slice(0, 3)).map(r => r.id), certificateIds: certs.filter(x => x.isDefault).map(x => x.id),
        ...(banners.length ? { bannerId: (banners.find(b => /default/i.test(b.name)) || banners[0]).id } : {}),
        securityControls: sc, userExperience: { browserInBrowser: true, sessionPersistence: true, persistIsolationBar: false, translate: false, zgpu: false, forwardToZia: { enabled: false } } });
      if (c && c.id) undo.push({ op: 'DELETE', path: `${C}/profiles/${c.id}`, label: `${cat}: ${name}` });
      rec({ category: cat, name, action: 'CREATE', id: c && c.id });
    }
    // the matching ZPA isolation profile (created by ZPA from the CBI profile)
    const zp = (await zpa.listAll('/isolation/profiles')).find(x => x.name === name);
    return zp ? { id: String(zp.id), name } : null;
  }

  // 6. Policies for the segment(s): timeout (re-authentication), AppProtection inspection, browser isolation
  const pol = { ...POLICY_DEFAULTS, ...(input.policies || {}) };
  const appIds = segIds.filter(x => !dead(x)).map(x => String(x.id));
  const anyApps = appIds.length > 0;
  const policyRule = async (policyType, name, body, ids = appIds) => {
    if (!ids.length) return skip('Policy Rule', name, 'the application segment');
    const want = { ...body, name, conditions: [...(body.conditions || []), { operator: 'OR', operands: [{ objectType: 'APP', values: ids }] }] };
    let set;
    try { set = await zpa.apiCall('GET', `${base}/policySet/policyType/${policyType}`); }
    catch (e) { return rec({ category: 'Policy Rule', name, action: 'FAILED', error: `Could not read the ${policyType} policy set: ${e.message}` }); }
    if (!set || !set.id) return rec({ category: 'Policy Rule', name, action: 'FAILED', error: `This tenant has no ${policyType} policy set` });
    // the policy set read does not embed its rules (seen live): list them separately
    let rules;
    try { rules = await policyRules(zpa, policyType); }
    catch (e) { return rec({ category: 'Policy Rule', name, action: 'FAILED', error: `Could not read the ${policyType} rules: ${e.message}` }); }
    const existing = rules.find(r => r.name === name);
    const v2 = `${await zpa.base('v2')}/policySet/${set.id}/rule`;
    if (existing) {
      const changes = policyRuleDiff(want, existing);
      if (!changes.length) return rec({ category: 'Policy Rule', name, action: 'NO_CHANGE', id: existing.id });
      if (dryRun) return rec({ category: 'Policy Rule', name, action: 'UPDATE', id: existing.id, changes });
      try {
        await zpa.apiCall('PUT', `${v2}/${existing.id}`, { ...want, id: existing.id });
        undo.push({ op: 'PUT', path: `${v2}/${existing.id}`, body: v1RuleToV2(existing), label: `Policy Rule: ${name}` });
        return rec({ category: 'Policy Rule', name, action: 'UPDATE', id: existing.id, changes });
      }
      catch (e) { return rec({ category: 'Policy Rule', name, action: 'FAILED', id: existing.id, error: e.message, changes }); }
    }
    if (dryRun) return rec({ category: 'Policy Rule', name, action: 'CREATE', id: 'new:policyRule' });
    try {
      const c = await zpa.apiCall('POST', v2, want);
      if (c && c.id) undo.push({ op: 'DELETE', path: `${base}/policySet/${set.id}/rule/${c.id}`, label: `Policy Rule: ${name}` });
      return rec({ category: 'Policy Rule', name, action: 'CREATE', id: c && c.id });
    }
    catch (e) { return rec({ category: 'Policy Rule', name, action: 'FAILED', error: e.message }); }
  };
  if (pol.timeout) {
    names.timeoutPolicy = `${p}-timeout-policy`;
    await policyRule('TIMEOUT_POLICY', names.timeoutPolicy, { action: 'RE_AUTH', ...TIMEOUTS,
      description: 'Users re-authenticate to these applications every 8 hours, or after 1 hour idle. Created by the Zscaler Policy Wizard.' });
  }
  if (pol.inspection) {
    names.inspectionProfile = `${p}-inspection-profile`;
    names.inspectionPolicy = `${p}-inspection-policy`;
    let ip = null;
    try {
      const existing = (await zpa.listAll('/inspectionProfile')).find(o => o.name === names.inspectionProfile);
      if (existing) ip = rec({ category: 'Inspection Profile', name: names.inspectionProfile, action: 'NO_CHANGE', id: existing.id });
      else if (dryRun) ip = rec({ category: 'Inspection Profile', name: names.inspectionProfile, action: 'CREATE', id: 'new:inspectionProfile' });
      else {
        // Current predefined rule-set version (older versions exist on old profiles but are refused for new ones)
        let ver = OWASP_FALLBACK;
        try { const vs = await zpa.apiCall('GET', `${base}/inspectionControls/predefined/versions`); const arr = Array.isArray(vs) ? vs : list(vs); if (arr.length) ver = String(arr[arr.length - 1]); }
        catch (e) { /* fallback */ }
        const groups = list(await zpa.apiCall('GET', `${base}/inspectionControls/predefined?version=${ver}`));
        const controls = groups.flatMap(g => g.predefinedInspectionControls || []).filter(x => Number(x.paranoiaLevel || 1) <= 1 && x.defaultAction);
        const c = await zpa.apiCall('POST', `${base}/inspectionProfile`, {
          name: names.inspectionProfile, description: `OWASP Core Rule Set ${ver.split('/')[1] || ''} (paranoia level 1) with all predefined controls. Created by the Zscaler Policy Wizard.`,
          paranoiaLevel: '1', predefinedControlsVersion: ver,
          globalControlActions: ['PREDEFINED:NONE', 'CUSTOM:NONE', 'WEBSOCKET:NONE', 'THREATLABZ:NONE', 'OVERRIDE_ACTION:SPECIFIC'],
          predefinedControls: controls.map(x => ({ id: String(x.id), action: x.defaultAction }))
        });
        try { await zpa.apiCall('PUT', `${base}/inspectionProfile/${c.id}/associateAllPredefinedControls?version=${ver}`); }
        catch (e) { warnings.push(`${names.inspectionProfile}: created, but adding all predefined controls failed (${e.message}). Add them in the ZPA portal.`); }
        if (c && c.id) undo.push({ op: 'DELETE', path: `${base}/inspectionProfile/${c.id}`, label: `Inspection Profile: ${names.inspectionProfile}` });
        ip = rec({ category: 'Inspection Profile', name: names.inspectionProfile, action: 'CREATE', id: c && c.id });
      }
    } catch (e) { ip = rec({ category: 'Inspection Profile', name: names.inspectionProfile, action: 'FAILED', error: e.message }); }
    if (dead(ip)) skip('Policy Rule', names.inspectionPolicy, names.inspectionProfile);
    else await policyRule('INSPECTION_POLICY', names.inspectionPolicy, { action: 'INSPECT', zpnInspectionProfileId: String(ip.id).startsWith('new:') ? undefined : String(ip.id),
      description: 'Inspect traffic to these applications with AppProtection (OWASP rules). Created by the Zscaler Policy Wizard.' });
  }
  if (pol.isolation) {
    names.isolationPolicy = `${p}-isolation-policy`;
    let prof = null;
    // v2.2: the wizard's own isolation profile with the POV security controls (copy / paste, upload / download, printing, watermark)
    const iso = { ...ISOLATION_DEFAULTS, ...(input.isolationProfile || {}) };
    if (iso.enabled !== false) {
      const cbiName = `${p}-isolation-profile`;
      names.isolationProfile = cbiName;
      try { prof = await upsertCbiProfile(cbiName, iso); }
      catch (e) { rec({ category: 'Isolation Profile', name: cbiName, action: 'FAILED', error: e.message }); }
    }
    if (!prof) {
      try { const ps = await zpa.listAll('/isolation/profiles'); prof = ps.find(x => x.enabled !== false && /default/i.test(x.name)) || ps.find(x => x.enabled !== false) || null; }
      catch (e) { warnings.push(`Could not read ZPA isolation profiles: ${e.message}`); }
    }
    if (!prof) rec({ category: 'Policy Rule', name: names.isolationPolicy, action: 'SKIPPED', error: 'This tenant has no ZPA isolation profile (Cloud Browser Isolation for ZPA).' });
    else await policyRule('ISOLATION_POLICY', names.isolationPolicy, { action: 'ISOLATE', zpnIsolationProfileId: String(prof.id),
      conditions: [{ operator: 'OR', operands: [{ objectType: 'CLIENT_TYPE', values: ['zpn_client_type_exporter'] }] }],
      description: `Users who reach these applications from a browser (Browser Access) get an isolated session (${prof.name}). Created by the Zscaler Policy Wizard.` });
  }

  // 7. Privileged Remote Access: one RDP and/or SSH application (by host), and a console when the tenant has a PRA portal
  const followUps = [COPY.report.followUps.zpaLocation, COPY.report.followUps.zpaDeploy];
  const pra = input.pra || {};
  const praSegIds = [];
  const praWanted = Object.entries(PRA_PROTOCOLS).filter(([k]) => String(pra[`${k}Host`] || '').trim());
  if (praWanted.length) {
    let portal = null;
    try { const portals = await zpa.listAll('/praPortal'); portal = portals.find(x => String(x.id) === String(pra.portalId)) || portals.find(x => x.enabled !== false) || null; }
    catch (e) { warnings.push(`Could not read PRA portals: ${e.message}`); }
    for (const [k, proto] of praWanted) {
      const host = String(pra[`${k}Host`]).trim();
      const segName = `${p}-pra-${k}`;
      names[`pra_${k}`] = segName;
      if (dead(sg) || dead(svg)) { skip('PRA Application', segName, dead(sg) ? names.segmentGroup : names.serverGroup); continue; }
      const body = { name: segName, description: `Privileged Remote Access (${proto.protocol}) to ${host}. Created by the Zscaler Policy Wizard.`, enabled: true,
        domainNames: [host], segmentGroupId: String(sg.id), serverGroups: [{ id: String(svg.id) }], tcpPortRanges: [proto.port, proto.port],
        bypassType: 'NEVER', healthReporting: 'ON_ACCESS', healthCheckType: 'DEFAULT', isCnameEnabled: true, icmpAccessType: 'NONE',
        commonAppsDto: { appsConfig: [{ name: host, domain: host, enabled: true, appTypes: ['SECURE_REMOTE_ACCESS'], applicationPort: proto.port, applicationProtocol: proto.protocol,
          ...(proto.protocol === 'RDP' ? { connectionSecurity: 'ANY' } : {}) }] } };
      if (String(body.segmentGroupId).startsWith('new:')) body.segmentGroupId = '(new)';
      const seg = await upsert('appSegment', 'PRA Application', segName, body, { fetchFull: true, createOnly: ['commonAppsDto'] });
      praSegIds.push(seg);
      const praApp = seg && seg.existing && (seg.existing.praApps || [])[0];
      delete seg.existing; delete seg.created;
      const consoleName = `${p}-pra-${k}-console`;
      names[`praConsole_${k}`] = consoleName;
      if (!portal) { rec({ category: 'PRA Console', name: consoleName, action: 'SKIPPED', error: 'This tenant has no PRA portal yet. Create one (domain and certificate) in the ZPA portal, then run again.' }); continue; }
      if (dead(seg)) { skip('PRA Console', consoleName, segName); continue; }
      let appRef = praApp;
      if (!appRef && !dryRun && !String(seg.id).startsWith('new:')) {
        try { appRef = ((await zpa.apiCall('GET', `${base}/application/${seg.id}`)).praApps || [])[0]; } catch (e) { /* reported below */ }
      }
      if (!appRef && !dryRun) { rec({ category: 'PRA Console', name: consoleName, action: 'FAILED', error: 'ZPA did not return the PRA application for the segment.' }); continue; }
      await upsert('praConsole', 'PRA Console', consoleName, { name: consoleName, description: `${proto.protocol} console for ${host} in the ${portal.name} portal.`, enabled: true,
        praApplication: { id: appRef ? String(appRef.id) : '(new)' }, praPortals: [{ id: String(portal.id) }] });
    }
    if (!portal) followUps.push('Create a Privileged Remote Access portal (domain and certificate) in the ZPA portal, then run the wizard again to add the PRA consoles.');
  }
  // 8. Access policy: anyone signed in to ZPA can reach the wizard's applications (segments, Browser Access and PRA)
  if (pol.access) {
    names.accessPolicy = `${p}-access-policy`;
    const accessIds = [...appIds, ...praSegIds.filter(x => !dead(x)).map(x => String(x.id))];
    await policyRule('ACCESS_POLICY', names.accessPolicy, { action: 'ALLOW',
      description: 'Any user signed in to ZPA can reach these applications. Narrow it to groups in the ZPA portal when the POV moves to production. Created by the Zscaler Policy Wizard.' }, accessIds);
  }
  followUps.push('ZPA browser isolation applies to Browser Access (clientless) users; ZPA inspection needs AppProtection on the tenant.');
  for (const e of ledger) { delete e.existing; delete e.created; }   // full objects stay on the server (they can hold a provisioning key)
  return { ledger, warnings, errors: [], secrets, names, followUps, undo };
}

const shortVal = (v) => { const t = typeof v === 'string' ? v : JSON.stringify(v === undefined ? null : v); return t.length > 140 ? t.slice(0, 137) + '…' : t; };
/** A rule read back (v1 operands lhs/rhs) as a v2 body, for putting it back on restore. */
function v1RuleToV2(r) {
  const out = { name: r.name, description: r.description || '', action: r.action };
  for (const k of ['reauthTimeout', 'reauthIdleTimeout', 'zpnInspectionProfileId', 'zpnIsolationProfileId', 'customMsg', 'operator']) if (r[k] !== undefined) out[k] = r[k];
  out.conditions = (r.conditions || []).map(c => {
    const byType = {};
    for (const o of c.operands || []) (byType[o.objectType] = byType[o.objectType] || []).push(o.rhs);
    return { operator: c.operator || 'OR', operands: Object.entries(byType).map(([objectType, values]) => ({ objectType, values })) };
  });
  return out;
}

/** Rules of one policy type (GET policySet/rules/policyType/{type}, paged). */
async function policyRules(zpa, policyType) {
  return zpa.listAll(`/policySet/rules/policyType/${policyType}`);
}

/** Fields of a wanted v2 policy rule that differ from the rule read back (v1 shape: operands with lhs/rhs). */
function policyRuleDiff(want, existing) {
  const out = [];
  for (const k of ['action', 'reauthTimeout', 'reauthIdleTimeout', 'zpnInspectionProfileId', 'zpnIsolationProfileId', 'description']) {
    if (want[k] !== undefined && String(want[k]) !== String(existing[k] === undefined ? '' : existing[k])) out.push(k);
  }
  const values = (conds, type) => (conds || []).flatMap(c => (c.operands || []).filter(o => o.objectType === type).flatMap(o => o.values || [o.rhs])).map(String).sort();
  for (const type of ['APP', 'CLIENT_TYPE']) if (JSON.stringify(values(want.conditions, type)) !== JSON.stringify(values(existing.conditions, type))) out.push(type === 'APP' ? 'applications' : 'client types');
  return out;
}

// ---------- bulk manager (BRM-01..05) ----------
// v2.6: ZPA refuses to delete an object something else still uses, so deletes run strictly in this order (field-tested):
//   take the app segment out of its segment group → access → app protection (inspection) → isolation policy rules →
//   isolation profile → inspection profile → timeout policy rules → PRA console → app segment → segment group →
//   server group → App Connector group → provisioning key.
const DELETE_ORDER = ['detach', 'accessRule', 'inspectionRule', 'isolationRule', 'cbiProfile', 'inspectionProfile', 'timeoutRule',
  'praConsole', 'appSegment', 'segmentGroup', 'serverGroup', 'connectorGroup', 'provisioningKey'];
const KIND_LABEL = { detach: 'Remove from segment group', accessRule: 'Access Policy', inspectionRule: 'App Protection Policy', isolationRule: 'Isolation Policy',
  timeoutRule: 'Timeout Policy', policyRule: 'Policy Rule', praConsole: 'PRA Console', appSegment: 'Application Segment', inspectionProfile: 'App Protection Profile',
  cbiProfile: 'Isolation Profile', serverGroup: 'Server Group', segmentGroup: 'Segment Group', provisioningKey: 'Provisioning Key', connectorGroup: 'App Connector Group' };
const RULE_KIND = { ACCESS_POLICY: 'accessRule', INSPECTION_POLICY: 'inspectionRule', ISOLATION_POLICY: 'isolationRule', TIMEOUT_POLICY: 'timeoutRule' };
const POLICY_TYPES = Object.keys(RULE_KIND);
const RULE_KINDS = Object.values(RULE_KIND);
const ids = (l) => (l || []).map(x => String(x && typeof x === 'object' ? x.id : x)).filter(x => x && x !== 'undefined');

/**
 * Every ZPA object that matters for deletes, wizard-made or not, with what it points at.
 * Returns { all, byKey } where each object = { kind, id, name, mine, refs: {...} }.
 */
async function zpaGraph(zpa, prefix) {
  const all = [], errors = [];
  const mine = (o) => !prefix || String(o.name || '').startsWith(prefix + '-');
  const add = (kind, o, refs, extra = {}) => all.push({ kind, label: KIND_LABEL[kind], id: String(o.id), name: o.name, enabled: o.enabled !== false, mine: mine(o), refs, ...extra });
  const base = await zpa.base();
  for (const t of POLICY_TYPES) {
    try {
      const set = await zpa.apiCall('GET', `${base}/policySet/policyType/${t}`).catch(() => null);
      if (!set) continue;
      for (const r of await policyRules(zpa, t)) {
        const apps = (r.conditions || []).flatMap(c => (c.operands || []).filter(o => o.objectType === 'APP').flatMap(o => o.values || [o.rhs])).map(String);
        add(RULE_KIND[t], { ...r, id: `${set.id}:${r.id}` }, { apps, isolationProfile: r.zpnIsolationProfileId ? String(r.zpnIsolationProfileId) : null, inspectionProfile: r.zpnInspectionProfileId ? String(r.zpnInspectionProfileId) : null },
          { detail: `${t.replace('_POLICY', '').toLowerCase()} policy` });
      }
    } catch (e) { errors.push({ kind: RULE_KIND[t], label: KIND_LABEL[RULE_KIND[t]], error: e.message }); }
  }
  // CBI profiles appear in ZPA as isolation profiles of the same name; rules point at the ZPA isolation profile id
  let isoByName = {};
  try { for (const o of await zpa.listAll('/isolation/profiles')) isoByName[o.name] = String(o.id); } catch (e) { /* older tenants: matched by name only */ }
  try {
    for (const o of list(await zpa.apiCall('GET', `/zpa/cbiconfig/cbi/api/customers/${await zpa.cid()}/profiles`))) add('cbiProfile', o, { zpnId: isoByName[o.name] || null }, { detail: o.description || '' });
  } catch (e) { errors.push({ kind: 'cbiProfile', label: KIND_LABEL.cbiProfile, error: e.message }); }
  const lists = { inspectionProfile: [], praConsole: [], appSegment: [], segmentGroup: [], serverGroup: [], connectorGroup: [], provisioningKey: [] };
  for (const kind of Object.keys(lists)) {
    try { lists[kind] = await zpa.listAll(PATHS[kind]); } catch (e) { errors.push({ kind, label: KIND_LABEL[kind], error: e.message }); }
  }
  for (const o of lists.inspectionProfile) add('inspectionProfile', o, {}, { detail: o.description || '' });
  for (const o of lists.praConsole) add('praConsole', o, { praApp: o.praApplication ? String(o.praApplication.id) : null }, { detail: o.description || '' });
  for (const o of lists.appSegment) add('appSegment', o, { segmentGroup: o.segmentGroupId ? String(o.segmentGroupId) : null, serverGroups: ids(o.serverGroups), praApps: ids(o.praApps) }, { detail: o.description || '', segmentGroupName: o.segmentGroupName || '' });
  for (const o of lists.segmentGroup) add('segmentGroup', o, { apps: ids(o.applications) }, { detail: o.description || '' });
  for (const o of lists.serverGroup) add('serverGroup', o, { connectorGroups: ids(o.appConnectorGroups) }, { detail: o.description || '' });
  for (const o of lists.connectorGroup) add('connectorGroup', o, {}, { detail: o.description || '' });
  for (const o of lists.provisioningKey) add('provisioningKey', o, { connectorGroup: o.zcomponentId ? String(o.zcomponentId) : null }, { detail: `used ${o.usageCount || 0} of ${o.maxUsage}` });
  return { all, errors };
}

/** Objects that must be deleted before x (ZPA refuses otherwise). */
function blockersOf(x, all) {
  const k = x.kind, id = x.id;
  if (k === 'appSegment') return all.filter(o => (RULE_KINDS.includes(o.kind) && o.refs.apps.includes(id)) || (o.kind === 'praConsole' && o.refs.praApp && x.refs.praApps.includes(o.refs.praApp)));
  if (k === 'segmentGroup') return all.filter(o => o.kind === 'appSegment' && o.refs.segmentGroup === id);
  if (k === 'serverGroup') return all.filter(o => o.kind === 'appSegment' && o.refs.serverGroups.includes(id));
  if (k === 'connectorGroup') return all.filter(o => o.kind === 'serverGroup' && o.refs.connectorGroups.includes(id));
  if (k === 'cbiProfile') return all.filter(o => o.kind === 'isolationRule' && ((x.refs.zpnId && o.refs.isolationProfile === x.refs.zpnId)));
  if (k === 'inspectionProfile') return all.filter(o => o.kind === 'inspectionRule' && o.refs.inspectionProfile === id);
  return [];
}

async function listZpaObjects(zpa, prefix) {
  const { all, errors } = await zpaGraph(zpa, prefix);
  const out = [];
  for (const kind of DELETE_ORDER) for (const o of all.filter(x => x.kind === kind && x.mine)) {
    const usedBy = blockersOf(o, all).map(b => ({ kind: b.kind, label: b.label, id: b.id, name: b.name, mine: b.mine }));
    out.push({ kind: o.kind, label: o.label, id: o.id, name: o.name, enabled: o.enabled, detail: o.detail || '', usedBy });
  }
  return [...out, ...errors];
}

/**
 * Plan / run a delete of the selected objects, strictly in DELETE_ORDER.
 * Anything still used by an object that is not selected is BLOCKED (with an issue saying what to select or remove first) and is not deleted.
 * When a delete fails, everything that depended on it is SKIPPED instead of failing in turn.
 * Returns { results, issues }.
 */
async function deleteZpaObjects(zpa, items, { dryRun, logger, prefix } = {}) {
  const base = await zpa.base();
  const { all } = await zpaGraph(zpa, prefix);
  const key = (o) => `${o.kind}:${o.id}`;
  const chosen = new Set(items.map(key));
  const sel = all.filter(o => chosen.has(key(o)));
  const results = [], issues = [];
  // what is held back: still used by something that is not being deleted
  const blocked = new Map();
  for (const o of sel) {
    const open = blockersOf(o, all).filter(b => !chosen.has(key(b)));
    if (open.length) {
      blocked.set(key(o), open);
      for (const b of open) issues.push({ object: `${o.label}: ${o.name}`, blockedBy: `${b.label}: ${b.name}`, kind: b.kind, id: b.id, selectable: b.mine,
        fix: b.mine ? `Select ${b.label} "${b.name}" too; it is deleted first.` : `"${b.name}" was not created by the wizard. Remove it (or take ${o.name} out of it) in the ZPA portal first.` });
    }
  }
  // a blocked object also holds back what it in turn needs gone (e.g. a blocked app segment keeps its segment group and server group in use)
  let grew = true;
  while (grew) {
    grew = false;
    for (const o of sel) {
      if (blocked.has(key(o))) continue;
      const via = blockersOf(o, all).filter(b => blocked.has(key(b)));
      if (via.length) { blocked.set(key(o), via); grew = true; }
    }
  }
  // steps: detach each app segment from its segment group first, then every object in order
  const steps = [];
  for (const o of sel.filter(x => x.kind === 'appSegment' && x.refs.segmentGroup && !blocked.has(key(x)))) {
    const sg = all.find(g => g.kind === 'segmentGroup' && g.id === o.refs.segmentGroup);
    steps.push({ kind: 'detach', label: KIND_LABEL.detach, id: `${o.refs.segmentGroup}:${o.id}`, name: `${o.name} from ${sg ? sg.name : 'its segment group'}`, app: o, groupId: o.refs.segmentGroup });
  }
  for (const kind of DELETE_ORDER.slice(1)) for (const o of sel.filter(x => x.kind === kind)) steps.push({ kind: o.kind, label: o.label, id: o.id, name: o.name, obj: o });
  const failed = new Set();
  for (const st of steps) {
    const row = { kind: st.kind, label: st.label, id: st.id, name: st.name };
    if (st.kind !== 'detach' && blocked.has(key(st.obj))) {
      const b = blocked.get(key(st.obj));
      results.push({ ...row, action: 'BLOCKED', error: `Still used by ${b.map(x => `${x.label} "${x.name}"`).join(', ')}.` });
      continue;
    }
    const needs = st.kind === 'detach' ? [] : blockersOf(st.obj, all).filter(b => failed.has(key(b)));
    if (needs.length) { results.push({ ...row, action: 'SKIPPED', error: `Not deleted because ${needs.map(x => `${x.label} "${x.name}"`).join(', ')} could not be deleted first.` }); failed.add(key(st.obj)); continue; }
    if (dryRun) { results.push({ ...row, action: st.kind === 'detach' ? 'DETACH' : 'DELETE' }); continue; }
    try {
      if (st.kind === 'detach') {
        const g = await zpa.apiCall('GET', `${base}${PATHS.segmentGroup}/${st.groupId}`);
        const apps = (g.applications || []).filter(a => String(a.id) !== String(st.app.id));
        if (apps.length !== (g.applications || []).length) await zpa.apiCall('PUT', `${base}${PATHS.segmentGroup}/${st.groupId}`, { ...g, applications: apps.map(a => ({ id: String(a.id) })) });
        results.push({ ...row, action: 'DETACHED' });
      } else {
        if (st.kind === 'cbiProfile') await zpa.apiCall('DELETE', `/zpa/cbiconfig/cbi/api/customers/${await zpa.cid()}/profiles/${st.id}`);
        else if (RULE_KINDS.includes(st.kind)) { const [setId, ruleId] = String(st.id).split(':'); await zpa.apiCall('DELETE', `${base}/policySet/${setId}/rule/${ruleId}`); }
        else await zpa.apiCall('DELETE', `${base}${PATHS[st.kind]}/${st.id}${st.kind === 'appSegment' ? '?forceDelete=true' : ''}`);
        results.push({ ...row, action: 'DELETED' });
      }
      if (logger) logger.logPolicyApply(`ZPA ${st.label}`, st.name, st.kind === 'detach' ? 'DETACH' : 'DELETE', { success: true, id: st.id });
    } catch (e) {
      // Already gone: ZPA deletes a provisioning key together with its App Connector group (seen live on ZTH).
      if (st.kind !== 'detach' && /resource\.not\.found|404/.test(String(e.message))) {
        results.push({ ...row, action: 'DELETED', note: st.kind === 'provisioningKey' ? 'Already removed by ZPA with its App Connector group.' : 'Already gone.' });
        if (logger) logger.logPolicyApply(`ZPA ${st.label}`, st.name, 'DELETE', { success: true, id: st.id, note: 'already gone' });
        continue;
      }
      if (st.kind !== 'detach') failed.add(key(st.obj));
      results.push({ ...row, action: 'FAILED', error: e.message });
      if (logger) logger.logPolicyApply(`ZPA ${st.label}`, st.name, 'DELETE', { error: e.message });
    }
  }
  return { results, issues };
}

module.exports = {
  parseBulkCsv, validateBulkApps, segmentName, ZPAClient, runZpa, validateZpaInput, classifyEntry, splitEntries, parsePortRanges, APP_SEGMENT_DEFAULTS, SAN_JOSE, POLICY_DEFAULTS, ISOLATION_DEFAULTS, policyRuleDiff,
  listZpaObjects, deleteZpaObjects, DELETE_ORDER, KIND_LABEL, zpaGraph, blockersOf };
