/**
 * Baseline Framework page (§2) and rule generation from baseline + scope (FWK-05..15).
 * Framework definitions are data (server/frameworks/*.json) with a source citation per control and a research date (FWK-07).
 * Existing 1.x rule content (templates.js) is reused for URL / CAC / file type / firewall / DNS / SSL; the areas new in
 * 2.0 come from zia-areas.js.
 */
const { generateFullTemplate, ACTION_POLICY_TYPES, shortRuleName } = require('../templates');
const areas = require('./zia-areas');
const { normalizeScope } = require('./scope');

// Required (not read from disk at runtime) so the standalone build bundles every definition
const DEFINITIONS = require('../frameworks');
let CACHE = null;
function loadAll() {
  if (!CACHE) CACHE = Object.fromEntries(DEFINITIONS.map(j => [j.id, j]));
  return CACHE;
}

// Order on the Baseline Framework page: the tool's existing compliance list (FWK-02), then the non-mapped tiers (FWK-03)
const COMPLIANCE_ORDER = ['HIPAA', 'HITRUST', 'NIST_800_53', 'NIST_800_171', 'PCI', 'CJIS', 'SOX', 'FERPA', 'GDPR'];
const NON_MAPPED_ORDER = ['STRICT', 'BALANCED', 'PERMISSIVE', 'ZTH_EBOOK'];

function listBaselines() {
  const all = loadAll();
  const pick = (id) => all[id] && {
    id, type: all[id].type, name: all[id].name, fullName: all[id].fullName, description: all[id].description,
    version: all[id].version, researchedAt: all[id].researchedAt, sources: all[id].sources
  };
  return {
    compliance: COMPLIANCE_ORDER.map(pick).filter(Boolean),
    nonMapped: NON_MAPPED_ORDER.map(pick).filter(Boolean)
  };
}

function getBaseline(id) {
  const fw = loadAll()[id];
  if (!fw) throw new Error(`Unknown baseline framework: ${id}`);
  return fw;
}

// Policy types shown on the rule review page, in display order
const POLICY_LABELS = {
  urlFiltering: 'URL Filtering', cloudAppControl: 'Cloud App Control', fileTypeControl: 'File Type Control',
  advancedThreatProtection: 'Advanced Threat Protection', firewallFiltering: 'Cloud Firewall', dnsSecurity: 'DNS Security',
  sslInspection: 'SSL Inspection', dlp: 'Inline Data Loss Prevention', endpointDlp: 'Endpoint Data Protection',
  sandbox: 'Cloud Sandbox', aiPromptCapture: 'AI Prompt Capture', ucaas: 'Unified Communications as a Service (UCaaS)'
};
const SINGLETON_TYPES = new Set(['advancedThreatProtection', 'aiPromptCapture', 'ucaas']);

/** Which policy type each scope item controls (SCP-04: out-of-scope types are removed, not hidden). */
function inScopeTypes(scope) {
  const s = normalizeScope(scope);
  const t = new Set();
  if (s.urlFiltering) t.add('urlFiltering');
  if (s.cloudAppControl) t.add('cloudAppControl');
  if (s.fileTypeControl) t.add('fileTypeControl');
  if (s.advancedThreatProtection) t.add('advancedThreatProtection');
  if (s.firewallFiltering) t.add('firewallFiltering');
  if (s.dnsSecurity) t.add('dnsSecurity');
  if (s.sslInspection) t.add('sslInspection');
  if (s.dlpMonitor || s.dlpBlock) t.add('dlp');
  if (s.endpointDlp) t.add('endpointDlp');
  if (s.sandboxStandard || s.sandboxAdvanced) t.add('sandbox');
  if (s.aiPromptCapture) t.add('aiPromptCapture');
  if (t.size) t.add('ucaas');   // UCaaS apps are switched on for every ZIA run
  return t;
}

/**
 * Build the full policy set.
 * opts: { baseline, scope, prefix, disabledRules, actionSettings:{policy,rules}, settingOverrides:{'advancedThreatProtection:key':bool,'aiPromptCapture:key':bool},
 *         cbiProfile, sslCertificate }
 * Returns the template plus `catalog` (every rule before user choices, for the review page).
 */
function generate(opts) {
  const catalogTemplate = build(opts, false);
  const template = build(opts, true);
  template.catalog = buildCatalog(catalogTemplate.policies);
  return template;
}

function build(opts, withChoices) {
  const fw = getBaseline(opts.baseline);
  const scope = normalizeScope(opts.scope);
  const prefix = opts.prefix || 'ZTP';
  const types = inScopeTypes(scope);
  const disabled = withChoices ? (opts.disabledRules || {}) : {};
  const actionSettings = withChoices ? (opts.actionSettings || { policy: {}, rules: {} }) : { policy: {}, rules: {} };
  const overrides = withChoices ? (opts.settingOverrides || {}) : {};
  const notes = [];

  // 1. Existing rule content for the classic areas. templates.js applies on/off and Allow / Block / Isolate for these
  //    (keyed by each rule's stable actionKey) and keeps names within 31 characters.
  const base = generateFullTemplate({
    tier: fw.baseTier, complianceFramework: fw.complianceKey, prefix,
    enableUrlFiltering: types.has('urlFiltering'), enableFirewall: types.has('firewallFiltering'),
    enableSslInspection: types.has('sslInspection'), enableMalwareProtection: true, enableAdvancedSettings: false,
    enableSandbox: false, enableDnsSecurity: types.has('dnsSecurity'), enableFileTypeControl: types.has('fileTypeControl'),
    enableCloudAppControl: types.has('cloudAppControl'), enableDlp: false,
    actionSettings, disabledRules: disabled, cbiProfile: opts.cbiProfile || null, sslCertificate: opts.sslCertificate || null
  });
  const policies = {};
  for (const k of ['urlFiltering', 'cloudAppControl', 'fileTypeControl', 'firewallFiltering', 'dnsSecurity', 'sslInspection']) {
    if (types.has(k) && Array.isArray(base.policies[k]) && base.policies[k].length) {
      policies[k] = base.policies[k].map(r => ({ ...r, toggleKey: r.toggleKey || r.actionKey, canOverride: !!ACTION_POLICY_TYPES[k] && !r.locked }));
    }
  }
  const off = (base.disabledItems || []).map(d => ({ key: d.key, name: d.name, type: d.policyType }));
  const objects = { customCategories: base.customCategories || [], dlpDictionaries: [], dlpEngines: [] };

  // 2. Areas added in 2.0
  if (types.has('advancedThreatProtection')) {
    policies.advancedThreatProtection = {
      name: `${prefix}-ATP-Defaults`,
      settings: areas.atpSettings(base.policies.malwareProtection).map(s => ({ ...s, toggleKey: `advancedThreatProtection:${s.key}` }))
    };
  }
  if (types.has('sandbox')) {
    const { rules, notes: n } = areas.sandboxRules(prefix, scope.sandboxAdvanced ? 'advanced' : 'standard');
    policies.sandbox = rules; notes.push(...n);
  }
  if (types.has('dlp')) {
    if (scope.dlpMonitor) policies.dlp = areas.dlpMonitorRules(prefix, fw);
    else {
      const b = areas.dlpBlockObjects(prefix, fw);
      policies.dlp = b.rules; objects.dlpDictionaries = b.dictionaries; objects.dlpEngines = b.engines;
    }
  }
  if (types.has('endpointDlp')) policies.endpointDlp = areas.endpointDlpRules(prefix, fw);
  if (types.has('aiPromptCapture')) {
    // SCP-54: every app on by default; each can be switched off
    policies.aiPromptCapture = { name: `${prefix}-AI-Prompt-Capture`, settings: areas.AI_PROMPT_APPS.map(a => ({ ...a, value: true, toggleKey: `aiPromptCapture:${a.key}` })) };
  }
  if (types.has('ucaas')) {
    policies.ucaas = { name: `${prefix}-UCaaS`, settings: areas.UCAAS_APPS.map(a => ({ ...a, value: true, toggleKey: `ucaas:${a.key}` })) };
  }

  // 3. New rule types: names within 31 characters (stable, so re-runs match by name), defaults, on/off and DLP Allow / Block
  for (const type of ['sandbox', 'dlp', 'endpointDlp']) {
    const rules = policies[type];
    if (!rules) continue;
    for (const r of rules) {
      r.toggleKey = r.actionKey;
      r.name = shortRuleName(r.name, prefix);
      r.canOverride = type === 'dlp' && !r.allowOnly;
      r.defaultAction = r.defaultAction || (type === 'sandbox' ? r.firstTimeOperation : r.action);
    }
    policies[type] = rules.filter(r => { if (disabled[r.toggleKey]) { off.push({ key: r.toggleKey, name: r.name, type }); return false; } return true; });
    if (type === 'dlp') {
      for (const r of policies.dlp) {
        if (!r.canOverride) continue;
        const rc = actionSettings.rules && actionSettings.rules[r.toggleKey];
        const pc = actionSettings.policy && actionSettings.policy.dlp;
        const choice = (rc === 'ALLOW' || rc === 'BLOCK') ? rc : (pc === 'ALLOW' || pc === 'BLOCK') ? pc : null;
        if (choice) { r.action = choice; r.userChoice = choice; }
        r.effectiveAction = r.action;
        r.weakened = r.defaultAction === 'BLOCK' && r.action === 'ALLOW';
      }
    }
    if (!policies[type].length) delete policies[type];
  }
  for (const d of objects.dlpDictionaries) d.name = shortRuleName(d.name, prefix);
  for (const e of objects.dlpEngines) { e.name = shortRuleName(e.name, prefix); e.dictRefs = e.dictRefs.map(r => r.custom ? { custom: shortRuleName(r.custom, prefix) } : r); }
  for (const r of (policies.dlp || [])) if (r.engineRef && r.engineRef.custom) r.engineRef.custom = shortRuleName(r.engineRef.custom, prefix);

  // 4. Settings (ATP, AI prompt capture): per-setting values and switches
  for (const type of SINGLETON_TYPES) {
    const p = policies[type];
    if (!p) continue;
    for (const s of p.settings) {
      if (overrides[s.toggleKey] !== undefined) s.value = !!overrides[s.toggleKey];
      if (disabled[s.toggleKey]) {
        // AI prompt capture: off = don't capture; ATP: off = leave the tenant's current value alone
        if (type === 'aiPromptCapture' || type === 'ucaas') s.value = false; else s.skip = true;
        off.push({ key: s.toggleKey, name: s.label, type });
      }
    }
  }

  // 5. v2.6.1: fit the firewall and DNS rules to the tenant's editions (opts.editions from the licensing check; unknown = keep all)
  const licenceSkipped = fitToEditions(policies, opts.editions, prefix, notes);

  // DLP block: drop engines / dictionaries no remaining rule uses
  if (objects.dlpEngines.length) {
    const used = new Set((policies.dlp || []).map(r => r.engineRef && r.engineRef.custom).filter(Boolean));
    objects.dlpEngines = objects.dlpEngines.filter(e => used.has(e.name));
    const dUsed = new Set(objects.dlpEngines.flatMap(e => e.dictRefs.map(d => d.custom).filter(Boolean)));
    objects.dlpDictionaries = objects.dlpDictionaries.filter(d => dUsed.has(d.name));
  }

  return {
    metadata: {
      name: `${prefix}-${fw.id}`, prefix, baseline: { id: fw.id, name: fw.name, type: fw.type, version: fw.version, researchedAt: fw.researchedAt },
      scope, generatedAt: new Date().toISOString(), version: '2.0.0', sources: fw.sources
    },
    policies, ...objects,
    actionChanges: (base.actionChanges || []).concat((policies.dlp || []).filter(r => r.userChoice && r.userChoice !== r.defaultAction)
      .map(r => ({ key: r.toggleKey, name: r.name, policyType: 'dlp', from: r.defaultAction, to: r.action, weakened: !!r.weakened }))),
    disabledItems: off,
    licenceSkipped,
    generationNotes: notes
  };
}

/** Rule review page data: every rule / setting grouped by policy type (FWK-10, filtered by scope). */
function buildCatalog(policies) {
  const order = Object.keys(POLICY_LABELS);
  return order.filter(t => policies[t]).map(type => {
    const p = policies[type];
    if (!Array.isArray(p)) {
      return { type, label: POLICY_LABELS[type], singleton: true,
        settings: p.settings.map(s => ({ key: s.toggleKey, label: s.label, group: s.group || null, defaultValue: s.value })) };
    }
    return {
      type, label: POLICY_LABELS[type], canOverride: p.some(r => r.canOverride), canIsolate: type === 'urlFiltering',
      rules: p.map(r => ({
        key: r.toggleKey, name: r.name, description: r.description || '', locked: !!r.locked, canOverride: !!r.canOverride,
        allowOnly: !!r.allowOnly, defaultAction: r.defaultAction || '', categoryCount: Array.isArray(r.urlCategories) ? r.urlCategories.length : undefined
      }))
    };
  });
}

/**
 * Firewall Standard: application-based rules need Advanced Cloud Firewall. The geo-block and QUIC rules are rebuilt on
 * network services (ports); the rest are left out and listed as not licensed. DNS tunnel rules need Advanced Cloud Firewall too.
 * Returns [{ type, name, reason }] for the review page.
 */
const GEO_SERVICES = ['SSH', 'FTP', 'TELNET', 'SMB'];
function fitToEditions(policies, ed, prefix, notes) {
  const out = [];
  if (!ed) return out;
  if (ed.firewall === 'standard' && Array.isArray(policies.firewallFiltering)) {
    const keep = [];
    for (const r of policies.firewallFiltering) {
      const apps = r.nwApplications || [];
      const geo = (r.destCountries || []).length || (r.sourceCountries || []).length;
      if (geo && apps.length) {
        const { nwApplications, ...rest } = r;
        keep.push({ ...rest, nwServiceNames: GEO_SERVICES, customServices: [{ name: `${prefix}-RDP`, tcp: [3389] }], standardFit: true,
          description: `${r.description || ''} (Cloud Firewall Standard: matched by port: SSH, RDP, FTP, Telnet, SMB.)`.trim() });
      } else if (apps.length === 1 && apps[0] === 'QUIC') {
        const { nwApplications, ...rest } = r;
        keep.push({ ...rest, nwServiceNames: ['QUIC'], standardFit: true });
      } else out.push({ type: 'firewallFiltering', name: r.name, reason: 'Needs Advanced Cloud Firewall (not licensed)' });
    }
    policies.firewallFiltering = keep;
    if (!keep.length) delete policies.firewallFiltering;
    if (out.length) notes.push(`Cloud Firewall Standard: ${out.length} application-based rule(s) left out (not licensed); geo-blocking and QUIC use ports.`);
  }
  if (ed.dns && !ed.dnsTunnels && Array.isArray(policies.dnsSecurity)) {
    const before = out.length;
    policies.dnsSecurity = policies.dnsSecurity.filter(r => {
      const tun = (r.applications || []).some(a => /^DNSTUN_/.test(a)) || /Tunnels/i.test(r.name);
      if (tun) out.push({ type: 'dnsSecurity', name: r.name, reason: 'DNS tunnel detection needs Advanced Cloud Firewall (not licensed)' });
      return !tun;
    });
    if (!policies.dnsSecurity.length) delete policies.dnsSecurity;
    if (out.length > before) notes.push('DNS tunnel rules left out: DNS tunnel detection is not licensed.');
  }
  return out;
}

module.exports = { fitToEditions, listBaselines, getBaseline, generate, inScopeTypes, POLICY_LABELS, SINGLETON_TYPES };
