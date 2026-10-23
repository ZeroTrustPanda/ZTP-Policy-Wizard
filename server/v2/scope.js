/**
 * Scope screen model (§1) and licensing detection (GLB-08, SCP-32/33).
 */
const COPY = require('./copy');

// Order = display order on the scope screen
const SCOPE_ITEMS = [
  { key: 'dlpMonitor', id: 'SCP-10', default: false, group: 'dlp' },
  { key: 'dlpBlock', id: 'SCP-11', default: false, group: 'dlp' },
  { key: 'endpointDlp', id: 'SCP-12', default: false },
  { key: 'sandboxStandard', id: 'SCP-13', default: false, group: 'sandbox' },
  { key: 'sandboxAdvanced', id: 'SCP-14', default: false, group: 'sandbox' },
  { key: 'aiPromptCapture', id: 'SCP-15', default: false },
  { key: 'urlFiltering', id: 'SCP-16', default: true },
  { key: 'cloudAppControl', id: 'SCP-17', default: true },
  { key: 'fileTypeControl', id: 'SCP-18', default: true },
  { key: 'advancedThreatProtection', id: 'SCP-19', default: true },
  { key: 'firewallFiltering', id: 'SCP-20', default: true },
  { key: 'dnsSecurity', id: 'SCP-21', default: true },
  { key: 'sslInspection', id: 'SCP-16a', default: true }
].map(i => ({ ...i, ...COPY.scope.items[i.key] }));

const EXCLUSIVE_GROUPS = { dlp: ['dlpMonitor', 'dlpBlock'], sandbox: ['sandboxStandard', 'sandboxAdvanced'] };

function defaultScope() {
  return Object.fromEntries(SCOPE_ITEMS.map(i => [i.key, i.default]));
}

/** Enforce SCP-30/31: at most one item per exclusive pair (the last one listed wins if both are on). */
function normalizeScope(scope = {}) {
  const out = { ...defaultScope(), ...Object.fromEntries(Object.entries(scope).filter(([k]) => SCOPE_ITEMS.some(i => i.key === k)).map(([k, v]) => [k, !!v])) };
  for (const keys of Object.values(EXCLUSIVE_GROUPS)) {
    const on = keys.filter(k => out[k]);
    if (on.length > 1) for (const k of on.slice(0, -1)) out[k] = false;
  }
  return out;
}

/**
 * SKU ids from GET /zia/api/v1/subscriptions that unlock each scope item.
 * certain: absence of every SKU means "not licensed" (greyed out). Otherwise absence only gives a warning.
 */
const LICENCE_MAP = {
  dlpMonitor: { skus: ['ZDLP_WEB'], certain: true },
  dlpBlock: { skus: ['ZDLP_WEB'], certain: true },
  sandboxStandard: { skus: ['ZSEC_WEB_ABA', 'ZIA_SANDBOX', 'ZIA_ADV_SANDBOX'], certain: false },
  sandboxAdvanced: { skus: ['ZSEC_WEB_ABA', 'ZIA_ADV_SANDBOX'], certain: false },
  aiPromptCapture: { skus: ['ZS_DP_GEN_AI', 'ZS_DP_ISO_SAAS_ADV_PLUS', 'ZIA_GENAI'], certain: false },
  urlFiltering: { skus: ['URL_FILTER'], certain: false },
  cloudAppControl: { skus: ['ZMAN_WEB_2_0', 'Z_CASB'], certain: false },
  advancedThreatProtection: { skus: ['ZIA_ATP'], certain: false },
  firewallFiltering: { skus: ['Z_FIREWALL_BASIC', 'ZFW_NG_WITH_LOG', 'ZFW_STD_LOG'], certain: false },
  dnsSecurity: { skus: ['Z_DNS_ESS', 'Z_DNS_ADVANCED', 'Z_FIREWALL_BASIC', 'ZFW_NG_WITH_LOG'], certain: false },
  sslInspection: { skus: ['ZIA_SSL', 'ZSSL_PVT_CERT'], certain: false }
};

/**
 * Returns { items: { key: { licensed: true|false|null, reason } }, endpointDlpEnabledInZcc: true|false|null, subscriptions: [...ids] }.
 * licensed=false → grey out with "Not licensed on this tenant"; null → enabled with a non-blocking warning.
 */
async function detectLicensing({ client, zccClient }) {
  const items = {};
  let subs = null;
  try {
    const r = await client.apiCall('GET', '/api/v1/subscriptions');
    if (Array.isArray(r)) subs = r.filter(s => s && s.subscribed !== false && !/EXPIRED|CANCEL/i.test(String(s.status || ''))).map(s => s.id);
  } catch (e) { /* unknown */ }

  for (const item of SCOPE_ITEMS) {
    const map = LICENCE_MAP[item.key];
    if (!map) continue;
    if (!subs) { items[item.key] = { licensed: null, reason: COPY.scope.licenceUnknown }; continue; }
    const hit = map.skus.find(s => subs.includes(s));
    if (hit) items[item.key] = { licensed: true, reason: `Subscription ${hit}` };
    else items[item.key] = map.certain ? { licensed: false, reason: COPY.scope.notLicensed } : { licensed: null, reason: COPY.scope.licenceUnknown };
  }

  // Endpoint DLP: the endpoint resource API answers 403 NOT_SUBSCRIBED when the SKU is missing (seen live)
  try {
    await client.apiCall('GET', '/api/v1/dlpEndpointResource/REMOVABLE_DRIVE_TRANSFER');
    items.endpointDlp = { licensed: true, reason: 'Endpoint DLP API available' };
  } catch (e) {
    items.endpointDlp = /NOT_SUBSCRIBED|subscription/i.test(String(e.message))
      ? { licensed: false, reason: COPY.scope.notLicensed }
      : { licensed: null, reason: COPY.scope.licenceUnknown };
  }

  // SCP-32: Endpoint DLP must be enabled in Mobile Admin first
  let endpointDlpEnabledInZcc = null;
  if (zccClient) {
    try {
      const info = await zccClient.apiCall('GET', '/zcc/papi/public/v1/getCompanyInfo');
      if (info && info.dlpEnabled !== undefined) endpointDlpEnabledInZcc = String(info.dlpEnabled) === '1' || info.dlpEnabled === true;
    } catch (e) { /* unknown */ }
  }
  // v2.6: standard vs advanced editions. With the advanced edition licensed, the standard choice is hidden (and the reverse is shown as is).
  const editions = subs ? require('./licences').editions(subs.map(String)) : {};
  if (editions.sandbox === 'advanced') items.sandboxStandard = { licensed: true, hidden: true, reason: 'Sandbox Advanced is licensed, so Advanced is used.' };
  if (editions.sandbox === 'advanced') items.sandboxAdvanced = { licensed: true, reason: 'Sandbox Advanced is licensed.' };
  if (editions.sandbox === 'standard') items.sandboxAdvanced = { licensed: false, reason: 'Only Sandbox Standard is licensed on this tenant.' };
  return { items, endpointDlpEnabledInZcc, subscriptions: subs, editions };
}

/** Warnings shown on the dry run and in the report (VAL-03). */
function scopeWarnings(scope, licensing) {
  const w = [];
  if (!licensing) return w;
  for (const item of SCOPE_ITEMS) {
    if (!scope[item.key]) continue;
    const l = licensing.items && licensing.items[item.key];
    if (l && l.licensed === null) w.push({ scope: item.key, kind: 'licence', text: `${item.label}: ${COPY.scope.licenceUnknown}` });
    if (l && l.licensed === false) w.push({ scope: item.key, kind: 'licence', text: `${item.label}: ${COPY.scope.notLicensed}. Its rules will fail to apply.` });
  }
  if (scope.endpointDlp && licensing.endpointDlpEnabledInZcc !== true) {
    w.push({ scope: 'endpointDlp', kind: 'prerequisite', text: licensing.endpointDlpEnabledInZcc === false ? COPY.scope.endpointPrereqDisabled : COPY.scope.endpointPrereq });
  }
  return w;
}

module.exports = { SCOPE_ITEMS, EXCLUSIVE_GROUPS, LICENCE_MAP, defaultScope, normalizeScope, detectLicensing, scopeWarnings };
