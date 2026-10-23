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
  { key: 'cloudAppControl', name: 'Cloud App Control', product: 'ZIA', tier: 'core', skus: ['ZMAN_WEB_2_0', 'Z_CASB', 'Z_CASB_BASIC'], why: 'Cloud app rules (AI/ML, file sharing, webmail, DoH tenancy).' },
  { key: 'sslInspection', name: 'SSL Inspection', product: 'ZIA', tier: 'core', skus: ['ZIA_SSL'], why: 'Inspecting encrypted traffic; most other test cases depend on it.' },
  { key: 'atp', name: 'Advanced Threat Protection', product: 'ZIA', tier: 'core', skus: ['ZIA_ATP'], why: 'Malicious sites, phishing, botnet callbacks.' },
  { key: 'antivirus', name: 'Antivirus / Anti-spam', product: 'ZIA', tier: 'core', skus: ['AV_AS'], why: 'Malware scanning test cases (EICAR).' },
  { key: 'sandbox', name: 'Cloud Sandbox', product: 'ZIA', tier: 'core', skus: ['ZIA_ATP', 'ZSEC_WEB_ABA', 'ZSEC_WEB_ABA_ADV'], why: 'Sandbox rules and unknown-file analysis.' },
  { key: 'dlp', name: 'Data Loss Prevention (web)', product: 'ZIA', tier: 'core', skus: ['ZDLP_WEB', 'ZDLP_WEB_BASIC'], why: 'DLP rules and the DLP test kit.' },
  { key: 'firewall', name: 'Cloud Firewall', product: 'ZIA', tier: 'core', skus: ['Z_FIREWALL_BASIC', 'ZFW_NG_WITH_LOG', 'ZIA_ATP'], why: 'Firewall and geo-blocking rules.' },
  { key: 'dnsSecurity', name: 'DNS Security', product: 'ZIA', tier: 'core', skus: ['Z_DNS_ESS', 'Z_DNS_ADVANCED', 'ZFW_NG_WITH_LOG', 'ZIA_ATP'], why: 'DNS rules, DoH inspection and the Trusted Resolver.' },
  { key: 'clientConnector', name: 'Client Connector', product: 'ZCC', tier: 'core', skus: ['ZSCALER_CLIENT_CONNECTOR'], why: 'Forwarding traffic from POV devices.' },
  { key: 'isolation', name: 'Cloud Browser Isolation', product: 'ZIA', tier: 'core', skusPrefix: 'ZIA_ISO_', skus: [], why: 'Isolate rule for Miscellaneous / Unknown sites.' },
  // ---- ZIA recommended ----
  { key: 'advancedFirewall', name: 'Advanced Cloud Firewall', product: 'ZIA', tier: 'recommended', skus: ['ZFW_NG_WITH_LOG'], why: 'Application-based firewall rules (P2P, tunnels, allow lists) and DNS tunnel detection.' },
  { key: 'sandboxAdvanced', name: 'Sandbox Advanced', product: 'ZIA', tier: 'recommended', skus: ['ZSEC_WEB_ABA_ADV'], why: 'The Sandbox Advanced scope option.' },
  { key: 'ips', name: 'Cloud IPS', product: 'ZIA', tier: 'recommended', skus: ['Z_FIREWALL_IPS', 'ZFW_NG_WITH_LOG'], why: 'IPS signatures on non-web traffic.' },
  { key: 'casb', name: 'CASB (SaaS security)', product: 'ZIA', tier: 'recommended', skus: ['Z_CASB', 'Z_CASB_BASIC'], why: 'Out-of-band SaaS scanning and tenant restrictions.' },
  { key: 'genAi', name: 'Gen AI security', product: 'ZIA', tier: 'recommended', skus: ['ZS_DP_GEN_AI'], why: 'AI prompt capture and AI app controls.' },
  { key: 'edm', name: 'Exact / Indexed Data Match', product: 'ZIA', tier: 'recommended', skus: ['Z_DLP_EDM', 'Z_DLP_IDM'], why: 'Advanced DLP fingerprinting.' },
  { key: 'bandwidth', name: 'Bandwidth Control', product: 'ZIA', tier: 'recommended', skus: ['ZIA_BW_CTRL'], why: 'Bandwidth classes for video and updates.' },
  { key: 'deception', name: 'Deception', product: 'ZIA', tier: 'recommended', skus: ['ZS_DECEPTION_STANDARD', 'ZS_DECEPTION_ADV'], why: 'Decoys for lateral-movement detection.' },
  { key: 'logStreaming', name: 'Log streaming (NSS / cloud NSS)', product: 'ZIA', tier: 'recommended', skus: ['Z_LOGFEED', 'Z_CLOUD_NSS_WEB', 'Z_LOGFEED_LIVE'], why: 'Sending logs to the customer SIEM.' },
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
  // The core ZIA features are reported as prerequisites (entitlements.prereqChecks); not repeated here.
  const PREREQ_CAPS = ['urlFiltering', 'cloudAppControl', 'sslInspection', 'atp', 'antivirus', 'firewall', 'dnsSecurity'];
  for (const cap of missingCore.filter(c => !PREREQ_CAPS.includes(c.key))) {
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

// ---------- v2.6: SKU printout (every SKU on the tenant, its product area, what it is and what it unlocks in the wizard) ----------
const W = (area, what, unlocks = '—') => ({ area, what, unlocks });
const SKU_MAP = {
  ZIA_TENANT: W('ZIA', 'ZIA tenant'),
  URL_FILTER: W('ZIA', 'URL Filtering', 'URL Filtering rules (core prerequisite)'),
  ZMAN_WEB_2_0: W('ZIA', 'Cloud App Control', 'Cloud App Control rules (core prerequisite)'),
  ZIA_SSL: W('ZIA', 'SSL Inspection', 'SSL Inspection rules (core prerequisite)'),
  ZSSL_PVT_CERT: W('ZIA', 'Custom root certificate for SSL inspection', 'Customer intermediate CA'),
  Z_CUSTOMROOTCERT_HSM: W('ZIA', 'Custom root certificate (HSM)'),
  ZIA_ATP: W('ZIA', 'Advanced Threat Protection (includes standard sandbox, firewall and DNS control)', 'ATP settings, threat tests, Sandbox Standard'),
  AV_AS: W('ZIA', 'Antivirus and anti-spam (malware protection)', 'Malware settings, EICAR tests (core prerequisite)'),
  ZSEC_WEB_ABA: W('ZIA', 'Cloud Sandbox', 'Sandbox Standard rules, sandbox test file'),
  ZSEC_WEB_ABA_ADV: W('ZIA', 'Cloud Sandbox Advanced', 'Sandbox Advanced option'),
  ZSEC_WEB_ABA_MAC_OS: W('ZIA', 'Sandbox for macOS files'),
  ZSEC_WEB_ABA_LARGE_FILES: W('ZIA', 'Sandbox for large files'),
  ZDLP_WEB_BASIC: W('Data Protection', 'Web DLP (standard)', 'DLP rules and DLP test data'),
  ZDLP_WEB: W('Data Protection', 'Web DLP (full)', 'DLP dictionaries, engines and rules; DLP test data'),
  Z_DLP_ENDPOINT: W('Data Protection', 'Endpoint DLP', 'Endpoint DLP option'),
  Z_DLP_EDM: W('Data Protection', 'DLP Exact Data Match', 'EDM (not configured by the wizard)'),
  Z_DLP_IDM: W('Data Protection', 'DLP Indexed Document Match', 'IDM (not configured by the wizard)'),
  CUST_DICTIONARIES_ENGINES: W('Data Protection', 'Custom DLP dictionaries and engines'),
  ZS_DP_GEN_AI: W('Data Protection', 'Gen AI data protection', 'AI prompt capture option'),
  ZS_DP_GEN_AI_REPORTING: W('Data Protection', 'Gen AI reporting'),
  ZS_DP_GEN_A_REPORTING: W('Data Protection', 'Gen AI reporting'),
  ZS_DP_EMAIL: W('Data Protection', 'Email DLP'),
  ZS_DP_SAAS_3PA: W('Data Protection', 'SaaS third-party app security'),
  ZS_DP_DATA_TFORM: W('Data Protection', 'Data transformation'),
  Z_DP_INSTANCE_DISCOVERY: W('Data Protection', 'SaaS instance discovery'),
  Z_CASB_BASIC: W('Data Protection', 'CASB (basic)', 'Cloud App Control rules'),
  Z_CASB: W('Data Protection', 'CASB', 'Cloud App Control rules'),
  Z_FIREWALL_BASIC: W('ZIA', 'Cloud Firewall (standard)', 'Standard firewall rules (geo-block, QUIC)'),
  Z_FIREWALL_BASIC_EXTRA_RULES: W('ZIA', 'Cloud Firewall (standard) extra rules'),
  ZFW_NG_WITH_LOG: W('ZIA', 'Cloud Firewall Advanced', 'Application-based firewall rules, DNS tunnel rules'),
  ZFW_STD_LOG: W('ZIA', 'Standard firewall logging'),
  Z_FIREWALL_IPS: W('ZIA', 'Cloud IPS'),
  Z_DNS_ESS: W('ZIA', 'DNS Security (essential)', 'DNS Control rules'),
  Z_DNS_ADVANCED: W('ZIA', 'DNS Security (advanced)', 'DNS Control rules'),
  ZIA_BW_CTRL: W('ZIA', 'Bandwidth Control'),
  ZS_DECEPTION_STANDARD: W('ZIA', 'Deception (standard)'),
  ZS_DECEPTION_ADV: W('ZIA', 'Deception (advanced)'),
  Z_REPORTING: W('ZIA', 'Reporting'),
  Z_LOGFEED: W('Logging', 'NSS log feed (web)'), Z_LOGFEED_FW: W('Logging', 'NSS log feed (firewall)'),
  Z_LOGFEED_LIVE: W('Logging', 'Live NSS log feed (web)'), Z_LOGFEED_FW_LIVE: W('Logging', 'Live NSS log feed (firewall)'),
  Z_CLOUD_NSS_WEB: W('Logging', 'Cloud NSS (web)'), Z_CLOUD_NSS_FW: W('Logging', 'Cloud NSS (firewall)'),
  Z_ICAP: W('ZIA', 'ICAP integration'),
  Z_WORKFLOW_AUTOMATION: W('ZIA', 'Workflow automation'),
  Z_CLOUD_ID_BROKER: W('ZIA', 'Cloud identity broker'),
  Z_MOBILE_SEC: W('ZIA', 'Mobile security'),
  Z_VPN_S2S: W('Connectivity', 'Site-to-site VPN'),
  ZIA_ENC_VPN: W('Connectivity', 'Encrypted VPN tunnels'),
  ZEXT_BW_PREM: W('Connectivity', 'Premium data center access'),
  ZEXT_BW_PREM_ME: W('Connectivity', 'Middle East data center access'),
  ZS_DDCTD_IP: W('Connectivity', 'Dedicated egress IP'),
  ZS_GEO_IP: W('Connectivity', 'Geolocalization'),
  Z_PROXYPORT: W('Connectivity', 'Dedicated proxy port'),
  V_SVC_EDGE: W('Connectivity', 'Virtual Service Edge'),
  IPV6_BASIC: W('Connectivity', 'IPv6 (basic)'), IPV6_ADVANCED: W('Connectivity', 'IPv6 (advanced)'),
  ZIA_SERVER_GB: W('ZIA', 'Server, IoT and guest Wi-Fi traffic'),
  ZT_IOT_VIS: W('ZIA', 'IoT device visibility'),
  ZIA_ADD50K_URLS: W('ZIA', 'Additional custom URLs'),
  ZSC_PRI_CAT: W('ZIA', 'Priority URL categorization'),
  ZIA_TRAFFIC_CAP_ESS: W('ZIA', 'Traffic capture (essentials)'), ZIA_TRAFFIC_CAPTURE_ADV: W('ZIA', 'Traffic capture (advanced)'), ZIA_TRAFFIC_CAP_EXTRAGB: W('ZIA', 'Traffic capture storage'),
  Z_API: W('ZIA', 'API access', 'API access'),
  ZSCALER_CLIENT_CONNECTOR: W('Client Connector', 'Zscaler Client Connector', 'App and forwarding profiles, installs'),
  ZS_SIPA: W('ZPA', 'Source IP anchoring'),
  ZS_EXT_LOCATIONS: W('ZPA', 'Extranet locations'), ZS_EXT_PARTNERS: W('ZPA', 'Extranet partners'),
  ZIA_ISO_STD: W('Isolation', 'Cloud Browser Isolation (standard)', 'Isolate Miscellaneous / Unknown rule'),
  ZIA_ISO_UNCAT: W('Isolation', 'Isolation of Miscellaneous / Unknown sites', 'Isolate Miscellaneous / Unknown rule'),
  ZIA_ISO_ADV: W('Isolation', 'Cloud Browser Isolation (advanced)', 'Isolate rules'),
  ZIA_ISO_ADV_PLUS: W('Isolation', 'Cloud Browser Isolation (advanced plus)', 'Isolate rules'),
  ZIA_ISO_PROXY: W('Isolation', 'Cloud Browser Isolation (proxy mode)', 'Isolate rules'),
  ZS_DP_ISO_SAAS_STD: W('Isolation', 'SaaS isolation (standard)'), ZS_DP_ISO_SAAS_ADV: W('Isolation', 'SaaS isolation (advanced)'), ZS_DP_ISO_SAAS_ADV_PLUS: W('Isolation', 'SaaS isolation (advanced plus)'),
  ZS_DP_ISO_GEN_AI: W('Isolation', 'Gen AI isolation', 'Isolate AI apps'),
  ZDX_LITE: W('ZDX', 'ZDX Lite', 'No configurable probes'), Z_ZDX_STD: W('ZDX', 'ZDX Standard', 'ZDX Standard template'),
  ZDX_ADVANCED: W('ZDX', 'ZDX Advanced', 'All ZDX templates, call-quality apps'), ZDX_ADV_PLUS: W('ZDX', 'ZDX Advanced Plus', 'All ZDX templates, call-quality apps'),
  Z_ZDX_M365: W('ZDX', 'ZDX M365', 'Microsoft 365 apps only'), ZDX_ADV_PROBES: W('ZDX', 'Additional ZDX probes'), ZDX_HOSTED_PROBES: W('ZDX', 'Hosted ZDX probes'),
  WORKLOAD_ZIA: W('Workloads', 'ZIA for workloads'), WORKLOAD_ZPA: W('Workloads', 'ZPA for workloads'), WORKLOAD_CONNECTOR_VM: W('Workloads', 'Workload connector VM'),
  WORKLOAD_ADVANCED_LOG: W('Workloads', 'Workload logging'), WORKLOAD_TUNNEL_ENCRYPT: W('Workloads', 'Workload tunnel encryption'), WORKLOAD_VDI: W('Workloads', 'VDI'),
  ZS_AI_ASSETS_PLATFORM: W('AI security', 'AI asset platform'), ZS_AI_ASSETS: W('AI security', 'AI asset discovery'), ZS_AI_SCANNING_PLATFORM: W('AI security', 'AI scanning'), AI_RED_TEAMING_PROBE: W('AI security', 'AI red teaming'),
  ZS_ENDPOINT_LOGGING_POLICY: W('Endpoint context', 'Endpoint logging'), ZS_ENDPOINT_CONTEXT_APPLICATION: W('Endpoint context', 'Endpoint application context'),
  ZS_APP_FINGERPRINTING: W('Endpoint context', 'Application fingerprinting'), ZS_ENDPOINT_SME_POLICY_CONTROL: W('Endpoint context', 'Endpoint policy control'),
  ZS_ZSS: W('Analytics', 'Threat Insights'), Z_RA_STD: W('Analytics', 'Risk360 (standard)'), Z_RA: W('Analytics', 'Risk360 (advanced)'), Z_BI: W('Analytics', 'Business insights'),
  ZS_INSP_PRV: W('Other', 'Provisioning code')
};
const skuInfo = (id) => SKU_MAP[id]
  || (/^ZIA_ISO_\d+$/.test(id) ? W('Isolation', `Cloud Browser Isolation (${id.replace('ZIA_ISO_', '')}% of users)`, 'Isolate rules')
  : /^BC_DEVICE_/.test(id) ? W('Branch Connector', `Branch Connector: ${id.replace('BC_DEVICE_', '').toLowerCase().replace(/_/g, ' ')}`)
  : /^(ZIA_SVC_|ZIA_CHINA_|ZS_CHINA_)/.test(id) ? W('Connectivity', 'China access or private service edge') : { area: 'Other', what: '', unlocks: '—', confirm: false });

const ENT = require('./entitlements');
const editions = (subs) => ENT.editions(subs);

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

module.exports = { CAPABILITIES, licenceChecks, hasCap, SKU_MAP, editions, skuTable };
