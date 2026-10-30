/**
 * Scope screen model (§1) and licensing detection (GLB-08, SCP-32/33).
 */
const COPY = require('./copy');

// Order = display order on the scope screen
const SCOPE_ITEMS = [
  { key: 'dlpMonitor', id: 'SCP-10', default: false, group: 'dlp' },
  { key: 'dlpBlock', id: 'SCP-11', default: false, group: 'dlp' },
  { key: 'endpointDlp', id: 'SCP-12', default: false },
  { key: 'saasDlp', id: 'SCP-12a', default: false },
  { key: 'emailDlp', id: 'SCP-12b', default: false },
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

const ENT = require('./entitlements');
// Kept for callers that list the unlocking subscriptions per scope item.
const LICENCE_MAP = Object.fromEntries(Object.entries(ENT.SCOPE_SKUS).map(([k, skus]) => [k, { skus, certain: true }]));

/**
 * Returns { items: { key: { licensed: true|false|null, hidden?, reason } }, endpointDlpEnabledInZcc, subscriptions, editions, notes }.
 * licensed=false → greyed out with "Not licensed on this tenant"; null → subscriptions could not be read (enabled, with a warning).
 */
async function detectLicensing({ client, zccClient }) {
  let subs = null;
  try {
    const r = await client.apiCall('GET', '/api/v1/subscriptions');
    if (Array.isArray(r)) subs = r.filter(s => s && s.subscribed !== false && !/EXPIRED|CANCEL/i.test(String(s.status || ''))).map(s => String(s.id));
  } catch (e) { /* unknown */ }
  const items = ENT.scopeLicensing(subs) || Object.fromEntries(SCOPE_ITEMS.filter(i => ENT.SCOPE_SKUS[i.key]).map(i => [i.key, { licensed: null, reason: COPY.scope.licenceUnknown }]));

  // Endpoint DLP: the subscription, or the endpoint resource API (403 NOT_SUBSCRIBED when the SKU is missing, seen live)
  if (!(items.endpointDlp && items.endpointDlp.licensed)) {
    try {
      await client.apiCall('GET', '/api/v1/dlpEndpointResource/REMOVABLE_DRIVE_TRANSFER');
      items.endpointDlp = { licensed: true, reason: 'Endpoint DLP API available' };
    } catch (e) {
      items.endpointDlp = /NOT_SUBSCRIBED|subscription/i.test(String(e.message)) ? { licensed: false, reason: COPY.scope.notLicensed }
        : subs ? items.endpointDlp || { licensed: false, reason: COPY.scope.notLicensed } : { licensed: null, reason: COPY.scope.licenceUnknown };
    }
  }

  // v2.8 Email DLP: the smarthost subscription has no read check; ZIA answers NOT_SUBSCRIBED when the rule is created
  if (!items.emailDlp) items.emailDlp = { licensed: null, reason: 'Checked when the rule is created (needs the Email DLP smarthost subscription and mail routed through Zscaler).' };
  // SCP-32: Endpoint DLP must be enabled in Mobile Admin first
  let endpointDlpEnabledInZcc = null;
  if (zccClient) {
    try {
      const info = await zccClient.apiCall('GET', '/zcc/papi/public/v1/getCompanyInfo');
      if (info && info.dlpEnabled !== undefined) endpointDlpEnabledInZcc = String(info.dlpEnabled) === '1' || info.dlpEnabled === true;
    } catch (e) { /* unknown */ }
  }
  // Editions: with Sandbox Advanced licensed, the standard choice is hidden.
  const editions = subs ? ENT.editions(subs) : {};
  if (editions.sandbox === 'advanced') items.sandboxStandard = { licensed: true, hidden: true, reason: 'Sandbox Advanced is licensed, so Advanced is used.' };
  return { items, endpointDlpEnabledInZcc, subscriptions: subs, editions, notes: subs ? ENT.editionNotes(editions) : {} };
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
