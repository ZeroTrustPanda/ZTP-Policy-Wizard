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

module.exports = { CAPABILITIES, licenceChecks, hasCap };
