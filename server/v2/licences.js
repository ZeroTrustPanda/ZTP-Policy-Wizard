/**
 * v2.3: tenant-wide licence check for the readiness panel.
 * "Good looks like" = the subscriptions on a fully licensed POV tenant (taken from the reference tenant, Oct 2026).
 * Each capability lists the SKU ids that unlock it (any one is enough).
 *   tier 'core'        → missing is a caution (warn): a standard POV test case cannot be shown.
 *   tier 'recommended' → missing is info: nice to show, not needed for the core POV.
 * Trial or paid subscriptions that end within 21 days are also a caution.
 */
'use strict';

const CAPABILITIES = [
  // ---- ZIA core ----
  { key: 'urlFiltering', name: 'URL Filtering', product: 'ZIA', tier: 'core', skus: ['URL_FILTER'], why: 'URL filtering rules (block / caution / isolate by category).' },
  { key: 'cloudAppControl', name: 'Cloud App Control', product: 'ZIA', tier: 'core', skus: ['ZMAN_WEB_2_0'], why: 'Cloud app rules (AI/ML, file sharing, webmail, DoH tenancy).' },
  { key: 'sslInspection', name: 'SSL Inspection', product: 'ZIA', tier: 'core', skus: ['ZIA_SSL', 'ZSSL_PVT_CERT'], why: 'Inspecting encrypted traffic; most other test cases depend on it.' },
  { key: 'atp', name: 'Advanced Threat Protection', product: 'ZIA', tier: 'core', skus: ['ZIA_ATP'], why: 'Malicious sites, phishing, botnet callbacks.' },
  { key: 'antivirus', name: 'Antivirus / Anti-spam', product: 'ZIA', tier: 'core', skus: ['AV_AS'], why: 'Malware scanning test cases (EICAR).' },
  { key: 'sandbox', name: 'Cloud Sandbox', product: 'ZIA', tier: 'core', skus: ['ZSEC_WEB_ABA', 'ZIA_SANDBOX', 'ZIA_ADV_SANDBOX'], why: 'Sandbox rules and unknown-file analysis.' },
  { key: 'dlp', name: 'Data Loss Prevention (web)', product: 'ZIA', tier: 'core', skus: ['ZDLP_WEB'], why: 'DLP rules and the DLP test kit.' },
  { key: 'firewall', name: 'Cloud Firewall', product: 'ZIA', tier: 'core', skus: ['Z_FIREWALL_BASIC', 'ZFW_NG_WITH_LOG'], why: 'Firewall and geo-blocking rules.' },
  { key: 'dnsSecurity', name: 'DNS Security', product: 'ZIA', tier: 'core', skus: ['Z_DNS_ESS', 'Z_DNS_ADVANCED', 'ZFW_NG_WITH_LOG'], why: 'DNS rules, DoH inspection and the Trusted Resolver.' },
  { key: 'clientConnector', name: 'Client Connector', product: 'ZCC', tier: 'core', skus: ['ZSCALER_CLIENT_CONNECTOR'], why: 'Forwarding traffic from POV devices.' },
  { key: 'isolation', name: 'Cloud Browser Isolation', product: 'ZIA', tier: 'core', skusPrefix: 'ZIA_ISO_', skus: ['ZS_DP_ISO_SAAS_ADV_PLUS'], why: 'Isolate rules for risky and uncategorized sites.' },
  // ---- ZIA recommended ----
  { key: 'advancedFirewall', name: 'Advanced Cloud Firewall', product: 'ZIA', tier: 'recommended', skus: ['ZFW_NG_WITH_LOG'], why: 'Application-aware firewall rules and full firewall logging.' },
  { key: 'ips', name: 'Cloud IPS', product: 'ZIA', tier: 'recommended', skus: ['Z_FIREWALL_IPS'], why: 'IPS signatures on non-web traffic.' },
  { key: 'casb', name: 'CASB (SaaS security)', product: 'ZIA', tier: 'recommended', skus: ['Z_CASB'], why: 'Out-of-band SaaS scanning and tenant restrictions.' },
  { key: 'genAi', name: 'Gen AI security', product: 'ZIA', tier: 'recommended', skus: ['ZS_DP_GEN_AI'], why: 'AI prompt capture and AI app controls.' },
  { key: 'edm', name: 'Exact / Indexed Data Match', product: 'ZIA', tier: 'recommended', skus: ['Z_DLP_EDM', 'Z_DLP_IDM'], why: 'Advanced DLP fingerprinting.' },
  { key: 'bandwidth', name: 'Bandwidth Control', product: 'ZIA', tier: 'recommended', skus: ['ZIA_BW_CTRL'], why: 'Bandwidth classes for video and updates.' },
  { key: 'deception', name: 'Deception', product: 'ZIA', tier: 'recommended', skus: ['ZS_DECEPTION_STANDARD'], why: 'Decoys for lateral-movement detection.' },
  { key: 'logStreaming', name: 'Log streaming (NSS / cloud NSS)', product: 'ZIA', tier: 'recommended', skus: ['Z_LOGFEED', 'Z_CLOUD_NSS_WEB'], why: 'Sending logs to the customer SIEM.' },
  { key: 'api', name: 'Z-API', product: 'ZIA', tier: 'recommended', skus: ['Z_API'], why: 'API access (the wizard itself uses the OneAPI).' }
];

function hasCap(cap, subs) {
  return cap.skus.some(s => subs.includes(s)) || (cap.skusPrefix ? subs.some(s => s.startsWith(cap.skusPrefix)) : false);
}

/**
 * raw: the GET /api/v1/subscriptions array. Returns { checks: [...readiness checks], summary }.
 * zpaCustomer: GET {zpa base} (feature flags), optional.
 */
function licenceChecks(raw, { zpaCustomer, now = Date.now() } = {}) {
  const checks = [];
  if (!Array.isArray(raw)) {
    checks.push({ area: 'Licensing', name: 'Subscriptions', status: 'warn', detail: 'Could not read the tenant subscriptions, so licensing was not checked.', fix: 'Give the API client read access to subscriptions (ZIA admin role).' });
    return { checks, summary: null };
  }
  const active = raw.filter(s => s && s.subscribed !== false && !/EXPIRED|CANCEL/i.test(String(s.status || '')));
  const subs = active.map(s => String(s.id));
  const missingCore = [], missingRec = [], present = [];
  for (const cap of CAPABILITIES) {
    if (hasCap(cap, subs)) { present.push(cap.name); continue; }
    if (cap.tier === 'core') missingCore.push(cap); else missingRec.push(cap);
  }
  for (const cap of missingCore) {
    checks.push({ area: 'Licensing', name: `Missing: ${cap.name}`, status: 'warn', detail: `Not licensed on this tenant. Affects: ${cap.why}`, fix: `Ask for a trial of ${cap.name} (SKU ${cap.skus[0]}${cap.skusPrefix ? ' or a Cloud Browser Isolation SKU' : ''}) before the POV.` });
  }
  if (missingRec.length) checks.push({ area: 'Licensing', name: 'Not licensed (optional)', status: 'info', detail: missingRec.map(c => c.name).join(', ') + '.' });
  if (!missingCore.length) checks.push({ area: 'Licensing', name: 'Core licences', status: 'pass', detail: `All ${CAPABILITIES.filter(c => c.tier === 'core').length} core POV capabilities are licensed.` });

  // Subscriptions ending soon
  const soon = active.filter(s => s.endDate && (s.endDate * 1000) > now && (s.endDate * 1000) - now < 21 * 86400000);
  if (soon.length) {
    const d = new Date(Math.min(...soon.map(s => s.endDate * 1000))).toISOString().slice(0, 10);
    checks.push({ area: 'Licensing', name: 'Subscriptions ending soon', status: 'warn', detail: `${soon.length} subscription(s) end by ${d}: ${soon.slice(0, 6).map(s => s.sku || s.id).join(', ')}${soon.length > 6 ? '…' : ''}.`, fix: 'Extend the trial so it covers the whole POV.' });
  }

  // ZPA feature flags
  if (zpaCustomer && typeof zpaCustomer === 'object') {
    if (zpaCustomer.featureInspectionEnabled === false) checks.push({ area: 'Licensing', name: 'Missing: ZPA AppProtection (inspection)', status: 'warn', detail: 'Inspection is not enabled for this ZPA tenant, so the inspection policy cannot be shown.', fix: 'Ask for ZPA AppProtection on the trial.' });
    if (zpaCustomer.featurePraEnabled === false) checks.push({ area: 'Licensing', name: 'ZPA Privileged Remote Access', status: 'info', detail: 'PRA is not enabled for this ZPA tenant; PRA consoles are skipped.' });
  }
  return { checks, summary: { core: CAPABILITIES.filter(c => c.tier === 'core').length, missingCore: missingCore.map(c => c.key), missingRecommended: missingRec.map(c => c.key), present: present.length } };
}

// ---------- v2.6: SKU printout (every SKU on the tenant, mapped to its product area and what it unlocks in the wizard) ----------
// Draft mapping from the ZTH reference tenant (51 SKUs, Oct 2026); entries marked confirm:false still need SE confirmation.
const SKU_MAP = {
  URL_FILTER: { area: 'ZIA', what: 'URL Filtering', unlocks: 'URL Filtering rules' },
  ZMAN_WEB_2_0: { area: 'ZIA', what: 'Cloud App Control', unlocks: 'Cloud App Control rules' },
  ZIA_SSL: { area: 'ZIA', what: 'SSL Inspection', unlocks: 'SSL Inspection rules' },
  ZSSL_PVT_CERT: { area: 'ZIA', what: 'Custom root certificate for SSL inspection', unlocks: 'Customer intermediate CA' },
  ZIA_ATP: { area: 'ZIA', what: 'Advanced Threat Protection', unlocks: 'ATP settings, threat tests' },
  AV_AS: { area: 'ZIA', what: 'Antivirus and anti-spam (malware protection)', unlocks: 'EICAR malware tests' },
  ZSEC_WEB_ABA: { area: 'ZIA', what: 'Cloud Sandbox', unlocks: 'Sandbox rules, sandbox test file', confirm: false },
  ZDLP_WEB: { area: 'ZIA', what: 'Web DLP', unlocks: 'DLP dictionaries, engines and rules; DLP test data', confirm: false },
  Z_DLP_EDM: { area: 'ZIA', what: 'DLP Exact Data Match', unlocks: 'EDM (not configured by the wizard)' },
  Z_DLP_IDM: { area: 'ZIA', what: 'DLP Indexed Document Match', unlocks: 'IDM (not configured by the wizard)' },
  Z_CASB: { area: 'ZIA', what: 'CASB (out-of-band SaaS security)', unlocks: 'Cloud app controls' },
  Z_FIREWALL_BASIC: { area: 'ZIA', what: 'Cloud Firewall (basic)', unlocks: 'Firewall rules' },
  ZFW_NG_WITH_LOG: { area: 'ZIA', what: 'Advanced Cloud Firewall with full logging', unlocks: 'Firewall, geo-block and DNS rules' },
  ZFW_STD_LOG: { area: 'ZIA', what: 'Standard firewall full logging', unlocks: 'Firewall logs' },
  Z_FIREWALL_IPS: { area: 'ZIA', what: 'Cloud IPS', unlocks: 'IPS signatures' },
  Z_DNS_ESS: { area: 'ZIA', what: 'DNS Security Essentials', unlocks: 'DNS Control rules' },
  Z_DNS_ADVANCED: { area: 'ZIA', what: 'DNS Security Advanced', unlocks: 'DNS Control, DoH and tunnel rules' },
  ZIA_BW_CTRL: { area: 'ZIA', what: 'Bandwidth Control', unlocks: '—' },
  ZS_DP_GEN_AI: { area: 'ZIA', what: 'Gen AI Security', unlocks: 'AI prompt capture, AI Guard prompt capture' },
  ZS_DECEPTION_STANDARD: { area: 'ZIA', what: 'Deception (standard)', unlocks: '—' },
  Z_REPORTING: { area: 'ZIA', what: 'Basic reporting', unlocks: '—' },
  Z_LOGFEED: { area: 'ZIA', what: 'NSS log feed (web)', unlocks: '—' },
  Z_LOGFEED_FW: { area: 'ZIA', what: 'NSS log feed (firewall)', unlocks: '—' },
  Z_CLOUD_NSS_WEB: { area: 'ZIA', what: 'Cloud NSS streaming (web)', unlocks: '—' },
  Z_CLOUD_NSS_FW: { area: 'ZIA', what: 'Cloud NSS streaming (firewall)', unlocks: '—' },
  Z_ICAP: { area: 'ZIA', what: 'ICAP (DLP to third-party DLP)', unlocks: '—' },
  Z_CLOUD_ID_BROKER: { area: 'ZIA', what: 'Cloud identity broker', unlocks: '—' },
  Z_MOBILE_SEC: { area: 'ZIA', what: 'Mobile security', unlocks: '—' },
  Z_VPN_S2S: { area: 'ZIA', what: 'Site-to-site VPN', unlocks: '—' },
  ZIA_ENC_VPN: { area: 'ZIA', what: 'Encrypted VPN', unlocks: '—' },
  Z_API: { area: 'ZIA', what: 'Z-API', unlocks: 'API access' },
  ZSCALER_CLIENT_CONNECTOR: { area: 'Client Connector', what: 'Zscaler Client Connector', unlocks: 'App and forwarding profiles, installs' },
  ZS_SIPA: { area: 'ZPA', what: 'Source IP anchoring', unlocks: '—' },
  ZIA_ISO_UNCAT: { area: 'Isolation', what: 'Isolation of Miscellaneous / Unknown', unlocks: 'Isolate Miscellaneous / Unknown rule' },
  ZS_DP_ISO_SAAS_ADV_PLUS: { area: 'Isolation', what: 'Isolation for SaaS (Data Protection Advanced Plus)', unlocks: 'Isolate rules' },
  ZIA_ISO_ADV_PLUS: { area: 'Isolation', what: 'Isolation Advanced Plus', unlocks: 'Isolate rules' },
  ZIA_ISO_STD: { area: 'Isolation', what: 'Cloud Browser Isolation (standard)', unlocks: 'Isolate rules' },
  ZIA_ISO_PROXY: { area: 'Isolation', what: 'Cloud Browser Isolation (proxy)', unlocks: 'Isolate rules', confirm: false },
  ZEXT_BW_PREM: { area: 'Extranet', what: 'Extranet bandwidth (premium)', unlocks: '—', confirm: false },
  ZS_EXT_LOCATIONS: { area: 'Extranet', what: 'Extranet locations', unlocks: '—' },
  ZS_EXT_PARTNERS: { area: 'Extranet', what: 'Extranet partners', unlocks: '—' }
};
const skuInfo = (id) => SKU_MAP[id] || (/^ZIA_ISO_\d+$/.test(id) ? { area: 'Isolation', what: `Cloud Browser Isolation (${id.replace('ZIA_ISO_', '')} users)`, unlocks: 'Isolate rules' }
  : /^BC_DEVICE_/.test(id) ? { area: 'Branch Connector', what: `Branch Connector: ${id.replace('BC_DEVICE_', '').toLowerCase().replace(/_/g, ' ')}`, unlocks: '—' } : { area: 'Other', what: '', unlocks: '—', confirm: false });

/**
 * Standard vs advanced editions: when the advanced edition is licensed, the standard choice is hidden in the scope screen.
 * SKU ids to be confirmed with the SE team (see the 2.6 notes); an empty list means "not detectable from SKUs yet".
 */
// Until the SKU ids are confirmed nothing is hidden or blocked: ZSEC_WEB_ABA ("Cloud Sandbox" on ZTH) is not yet known to be either edition.
const EDITIONS = {
  sandbox: { advanced: [], standard: [] },
  dlp: { advanced: [], standard: [] }
};
function editions(subs) {
  const out = {};
  for (const [k, e] of Object.entries(EDITIONS)) out[k] = e.advanced.some(s => subs.includes(s)) ? 'advanced' : e.standard.some(s => subs.includes(s)) ? 'standard' : null;
  return out;
}

/** Every SKU on the tenant, grouped by area, plus products the API token can reach (ZPA / ZDX / AI Guard are not in /subscriptions). */
function skuTable(raw, { products = [] } = {}) {
  if (!Array.isArray(raw)) return null;
  const now = Date.now();
  const rows = raw.map(s => {
    const id = String(s.id), info = skuInfo(id);
    const end = s.endDate ? new Date(s.endDate * 1000) : null;
    return { id, name: s.sku || id, status: s.status || '', active: s.subscribed !== false && !/EXPIRED|CANCEL/i.test(String(s.status || '')), endsOn: end ? end.toISOString().slice(0, 10) : null,
      endingSoon: !!(end && end.getTime() > now && end.getTime() - now < 21 * 86400000), area: info.area, what: info.what || s.sku || '', unlocks: info.unlocks, confirmed: info.confirm !== false };
  }).sort((a, b) => a.area.localeCompare(b.area) || a.id.localeCompare(b.id));
  const viaToken = (products || []).filter(p => ['ZPA', 'ZDX', 'ZGUARD'].includes(p.product)).map(p => ({ product: p.product, label: p.label, access: p.access, role: p.role }));
  return { rows, total: rows.length, active: rows.filter(r => r.active).length, editions: editions(rows.filter(r => r.active).map(r => r.id)), viaToken };
}

module.exports = { CAPABILITIES, licenceChecks, hasCap, SKU_MAP, EDITIONS, editions, skuTable };
