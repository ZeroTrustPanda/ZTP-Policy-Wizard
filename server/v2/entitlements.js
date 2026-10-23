/**
 * v2.6.1: what a tenant's subscriptions let the POV show.
 * One place that turns subscription ids into yes / no decisions (and editions) for the scope screen, the readiness
 * prerequisites, the firewall / DNS rule sets and the ZDX templates. Decisions only: no quantities.
 */
'use strict';

const any = (subs, ids) => ids.some(id => subs.has(id));

/** Scope item → subscriptions that unlock it (any one is enough). */
const SCOPE_SKUS = {
  urlFiltering: ['URL_FILTER'],
  cloudAppControl: ['ZMAN_WEB_2_0', 'Z_CASB', 'Z_CASB_BASIC'],
  fileTypeControl: ['URL_FILTER', 'ZIA_TENANT'],
  advancedThreatProtection: ['ZIA_ATP'],
  firewallFiltering: ['Z_FIREWALL_BASIC', 'ZFW_NG_WITH_LOG', 'ZIA_ATP'],
  dnsSecurity: ['Z_DNS_ESS', 'Z_DNS_ADVANCED', 'ZFW_NG_WITH_LOG', 'ZIA_ATP'],
  sslInspection: ['ZIA_SSL'],
  dlpMonitor: ['ZDLP_WEB', 'ZDLP_WEB_BASIC'],
  dlpBlock: ['ZDLP_WEB', 'ZDLP_WEB_BASIC'],
  endpointDlp: ['Z_DLP_ENDPOINT'],
  sandboxStandard: ['ZIA_ATP', 'ZSEC_WEB_ABA', 'ZSEC_WEB_ABA_ADV'],   // standard sandbox comes with the threat bundle
  sandboxAdvanced: ['ZSEC_WEB_ABA_ADV'],
  aiPromptCapture: ['ZS_DP_GEN_AI']
};

/** Scope items that are on by default: the core of every ZIA POV. Missing any of them is a prerequisite failure. */
const CORE_PREREQS = [
  { key: 'urlFiltering', name: 'URL Filtering' },
  { key: 'cloudAppControl', name: 'Cloud App Control' },
  { key: 'fileTypeControl', name: 'File Type Control' },
  { key: 'advancedThreatProtection', name: 'Advanced Threat Protection' },
  { key: 'firewallFiltering', name: 'Cloud Firewall' },
  { key: 'dnsSecurity', name: 'DNS Security' },
  { key: 'sslInspection', name: 'SSL Inspection' },
  { key: 'antivirus', name: 'Malware protection (antivirus)', skus: ['AV_AS'] }
];

/** Standard / advanced editions and feature switches the wizard acts on. */
function editions(subsList) {
  const s = new Set((subsList || []).map(String));
  const iso = [...s].some(x => /^ZIA_ISO_(\d+|ADV|ADV_PLUS|PROXY)$/.test(x)) ? 'full'
    : any(s, ['ZIA_ISO_STD', 'ZIA_ISO_UNCAT']) ? 'misc' : null;
  return {
    firewall: s.has('ZFW_NG_WITH_LOG') ? 'advanced' : any(s, ['Z_FIREWALL_BASIC', 'ZIA_ATP']) ? 'standard' : null,
    ips: s.has('Z_FIREWALL_IPS') || s.has('ZFW_NG_WITH_LOG'),
    dns: any(s, SCOPE_SKUS.dnsSecurity) ? (s.has('ZFW_NG_WITH_LOG') ? 'advanced' : 'standard') : null,
    dnsTunnels: s.has('ZFW_NG_WITH_LOG'),
    sandbox: s.has('ZSEC_WEB_ABA_ADV') ? 'advanced' : any(s, ['ZIA_ATP', 'ZSEC_WEB_ABA']) ? 'standard' : null,
    dlp: s.has('ZDLP_WEB') ? 'advanced' : s.has('ZDLP_WEB_BASIC') ? 'standard' : null,
    isolation: iso,
    genAiIsolation: iso === 'full' || s.has('ZS_DP_ISO_GEN_AI'),
    zdx: zdxTierFromSubs(s)
  };
}

// ---------- ZDX tiers ----------
// The tier is not exposed by the ZDX API (checked on ZTH); it comes from a subscription when the tenant lists one, else the SE picks it.
const ZDX_TIERS = {
  ADV_PLUS: { label: 'Advanced Plus', configurable: true, ucaas: true, templates: ['POV_BEST_PRACTICE', 'POV_STANDARD', 'BLANK'] },
  ADVANCED: { label: 'Advanced', configurable: true, ucaas: true, templates: ['POV_BEST_PRACTICE', 'POV_STANDARD', 'BLANK'] },
  STANDARD: { label: 'Standard', configurable: true, ucaas: false, limited: true, templates: ['POV_STANDARD', 'BLANK'] },
  M365: { label: 'M365', configurable: true, ucaas: true, microsoftOnly: true, templates: ['BLANK'] },
  LITE: { label: 'Lite', configurable: false, ucaas: false, templates: [] }
};
function zdxTierFromSubs(s) {
  if (s.has('ZDX_ADV_PLUS')) return 'ADV_PLUS';
  if (s.has('ZDX_ADVANCED')) return 'ADVANCED';
  if (s.has('Z_ZDX_STD')) return 'STANDARD';
  if (s.has('Z_ZDX_M365')) return 'M365';
  if (s.has('ZDX_LITE')) return 'LITE';
  return null;
}
const UCAAS_PROVIDERS = ['MICROSOFT_TEAMS', 'ZOOM', 'WEBEX', 'RINGCENTRAL', 'GOOGLE_MEET'];
/** Is a ZDX choice allowed on this tier? Returns null when fine, else the reason. Unknown tier → everything allowed. */
function zdxBlocked(tier, { provider, templateId, label } = {}) {
  const t = tier && ZDX_TIERS[tier];
  if (!t) return null;
  if (!t.configurable) return `ZDX ${t.label} has no configurable probes.`;
  if (templateId && !t.templates.includes(templateId)) return `Not licensed on ZDX ${t.label}.`;
  if (provider && UCAAS_PROVIDERS.includes(provider) && !t.ucaas) return `Call-quality (UCaaS) monitoring needs ZDX Advanced.`;
  if (provider && t.microsoftOnly && !/^MICROSOFT|^SHAREPOINT|^ONEDRIVE|^OUTLOOK|^EXCHANGE|^OFFICE/.test(provider)) return `ZDX M365 monitors Microsoft 365 apps only.`;
  return null;
}

/** Scope licensing from the subscription list (null = could not be read). */
function scopeLicensing(subsList) {
  if (!subsList) return null;
  const s = new Set(subsList.map(String));
  const items = {};
  for (const [key, ids] of Object.entries(SCOPE_SKUS)) {
    const hit = ids.find(id => s.has(id));
    items[key] = hit ? { licensed: true, reason: `Subscription ${hit}` } : { licensed: false, reason: 'Not licensed on this tenant' };
  }
  return items;
}

/** Readiness: the default (core) ZIA items as prerequisites. */
function prereqChecks(subsList) {
  const s = new Set((subsList || []).map(String));
  const missing = CORE_PREREQS.filter(p => !any(s, p.skus || SCOPE_SKUS[p.key]));
  const checks = missing.map(p => ({ area: 'Prerequisites', name: `Not licensed: ${p.name}`, status: 'fail',
    detail: `${p.name} is part of every ZIA POV (on by default in the scope) and is not licensed on this tenant, so its rules cannot be applied or shown.`,
    fix: `Add ${p.name} to the POV trial (${(p.skus || SCOPE_SKUS[p.key])[0]}) before the kickoff.` }));
  if (!missing.length) checks.push({ area: 'Prerequisites', name: 'Core ZIA features', status: 'pass', detail: `All ${CORE_PREREQS.length} core ZIA features are licensed: ${CORE_PREREQS.map(p => p.name).join(', ')}.` });
  return { checks, missing: missing.map(p => p.key) };
}

/** Plain-language lines for the scope screen and readiness ("what this tenant's editions mean for the POV"). */
function editionNotes(ed) {
  const n = {};
  if (ed.firewall === 'standard') n.firewallFiltering = { status: 'warn', text: 'Advanced Cloud Firewall: Not licensed. Only standard rules are created (geo-blocking and QUIC by port); the application-based rules (P2P, tunnels, allow lists, default block) are left out.' };
  else if (ed.firewall === 'advanced') n.firewallFiltering = { status: 'pass', text: 'Advanced Cloud Firewall licensed: application-based rules included.' };
  if (ed.dns && !ed.dnsTunnels) n.dnsSecurity = { status: 'warn', text: 'DNS tunnel detection: Not licensed (needs Advanced Cloud Firewall). The tunnel rules are left out; DoH and Trusted Resolver rules are kept.' };
  if (ed.sandbox === 'standard') n.sandboxAdvanced = { status: 'warn', text: 'Sandbox Advanced: Not licensed. Sandbox Standard is available.' };
  if (ed.dlp) n.dlpMonitor = n.dlpBlock = { status: 'pass', text: ed.dlp === 'advanced' ? 'Data Protection (full web DLP) licensed.' : 'Data Protection Standard licensed.' };
  if (ed.isolation === 'misc') n.urlFiltering = { status: 'info', text: 'Cloud Browser Isolation: standard, for Miscellaneous / Unknown sites (the Isolate rule the wizard creates). Choosing Isolate for other categories needs full Cloud Browser Isolation.' };
  else if (!ed.isolation) n.urlFiltering = { status: 'info', text: 'Cloud Browser Isolation: Not licensed. The Isolate Miscellaneous / Unknown rule is left out.' };
  return n;
}

module.exports = { SCOPE_SKUS, CORE_PREREQS, editions, scopeLicensing, prereqChecks, editionNotes, ZDX_TIERS, UCAAS_PROVIDERS, zdxBlocked, zdxTierFromSubs };
