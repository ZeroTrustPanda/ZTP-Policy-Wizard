/**
 * v2.5.1: what AI Guard enforces (a compliance profile turned into an AI Guard detection policy plus a policy-match rule),
 * and the ZIA allow for the sanctioned AI apps so they reach AI Guard instead of being blocked, cautioned or isolated.
 *
 * Live findings (ZTH, 2026-10-22):
 * - POST /aiguard/v1/detections/policies needs BOTH inputDetectorPolicies and outputDetectorPolicies (send [] for an empty side);
 *   a body with only one side fails with a 500 from the downstream service.
 * - Accepted detectors: input  toxicity, prompt_injection, pii, pii_deepscan, personal_data, malicious_url, gibberish, invisible_text, brand_and_reputation_risk
 *                       output the same minus prompt_injection, plus refusal and url_reachability. secrets / code are refused (400).
 * - Actions BLOCK | DETECT | ALLOW (MASK is refused); pii entities also take DISABLE.
 * - Match rules: type APPLICATION with llmProviders [{ llmProvider: '<provider name>', llmProviderModels: [] }], type USER, type DAS_APPLICATION.
 * - ZIA: the AI apps are URL category AI_ML_APPS; cloud apps CHATGPT_AI, OPENAI, CLAUDE_AI, ANTHROPIC_AI, MICROSOFT_COPILOT, GOOGLE_GEMINI,
 *   GITHUB_COPILOT, PERPLEXITY, PERPLEXITY_AI_APP, GROK_AI, MISTRAL, GOOGLE_NOTEBOOKLM, GLEAN_AI.
 */
'use strict';

const PII_ENTITIES = ['CREDIT_CARD', 'CRYPTO', 'EMAIL_ADDRESS', 'IP_ADDRESS', 'LOCATION', 'IBAN_CODE', 'US_BANK_NUMBER', 'US_DRIVER_LICENSE', 'US_ITIN',
  'US_PASSPORT', 'US_SSN', 'DATE_TIME', 'URL', 'MEDICAL_LICENSE', 'SWIFT_CODE', 'STREET_ADDRESS', 'DATE_OF_BIRTH', 'US_DEA_NUMBER', 'PERSON', 'PHONE_NUMBER'];

/** Per app: ZIA cloud applications (Cloud App Control) and AI Guard LLM providers (policy-match rule). */
const APP_MAP = {
  chatgpt: { cloudApps: ['CHATGPT_AI', 'OPENAI'], providers: ['Default OpenAI Provider'] },
  m365copilot: { cloudApps: ['MICROSOFT_COPILOT'], providers: ['Default Microsoft 365 Copilot Provider', 'Default Microsoft Copilot Provider'] },
  claude: { cloudApps: ['CLAUDE_AI', 'ANTHROPIC_AI'], providers: ['Default Anthropic Provider'] },
  gemini: { cloudApps: ['GOOGLE_GEMINI'], providers: ['Default Google Gemini Provider', 'Default Google Gemini Workspace Provider', 'Default Google Gemini Enterprise Provider'] },
  githubcopilot: { cloudApps: ['GITHUB_COPILOT'], providers: [] },
  perplexity: { cloudApps: ['PERPLEXITY', 'PERPLEXITY_AI_APP'], providers: ['Default PerplexityAI Provider'] },
  grok: { cloudApps: ['GROK_AI'], providers: ['Default xAI Provider'] },
  mistral: { cloudApps: ['MISTRAL'], providers: [] },
  notebooklm: { cloudApps: ['GOOGLE_NOTEBOOKLM'], providers: [] },
  glean: { cloudApps: ['GLEAN_AI'], providers: ['Default Glean Provider'] }
};

/**
 * Compliance profiles. block = identifiers that are blocked in Block mode (detected in Monitor mode); detect = always detect only.
 * deep = also run pii_deepscan / personal_data (context-aware PII), useful where names + health or financial context matter.
 */
const PROFILES = {
  HIPAA: { name: 'HIPAA (PHI)', why: 'HIPAA identifiers that turn health information into PHI.',
    block: ['US_SSN', 'DATE_OF_BIRTH', 'MEDICAL_LICENSE', 'US_DEA_NUMBER', 'STREET_ADDRESS', 'US_DRIVER_LICENSE', 'CREDIT_CARD', 'US_BANK_NUMBER'],
    detect: ['PERSON', 'PHONE_NUMBER', 'EMAIL_ADDRESS', 'IP_ADDRESS', 'URL'], deep: true },
  HITRUST: { name: 'HITRUST (PHI + PII)', why: 'HITRUST CSF privacy controls: PHI identifiers plus financial and government ids.',
    block: ['US_SSN', 'DATE_OF_BIRTH', 'MEDICAL_LICENSE', 'US_DEA_NUMBER', 'STREET_ADDRESS', 'US_DRIVER_LICENSE', 'US_PASSPORT', 'CREDIT_CARD', 'US_BANK_NUMBER'],
    detect: ['PERSON', 'PHONE_NUMBER', 'EMAIL_ADDRESS', 'IP_ADDRESS'], deep: true },
  PCI: { name: 'PCI DSS (cardholder data)', why: 'Primary account numbers and bank details.',
    block: ['CREDIT_CARD', 'US_BANK_NUMBER', 'IBAN_CODE', 'SWIFT_CODE'], detect: ['PERSON'], deep: false },
  GDPR: { name: 'GDPR (personal data)', why: 'Personal data of identifiable people.',
    block: ['IBAN_CODE', 'CREDIT_CARD', 'US_PASSPORT', 'DATE_OF_BIRTH'], detect: ['PERSON', 'EMAIL_ADDRESS', 'PHONE_NUMBER', 'STREET_ADDRESS', 'LOCATION', 'IP_ADDRESS'], deep: true },
  CJIS: { name: 'CJIS (criminal justice information)', why: 'Identifiers that link a person to CJI.',
    block: ['US_SSN', 'US_DRIVER_LICENSE', 'US_PASSPORT', 'DATE_OF_BIRTH'], detect: ['PERSON', 'STREET_ADDRESS', 'LOCATION'], deep: true },
  FERPA: { name: 'FERPA (student records)', why: 'Directory and non-directory student identifiers.',
    block: ['US_SSN', 'DATE_OF_BIRTH'], detect: ['PERSON', 'EMAIL_ADDRESS', 'PHONE_NUMBER', 'STREET_ADDRESS'], deep: true },
  SOX: { name: 'SOX (financial data)', why: 'Financial account and taxpayer identifiers.',
    block: ['CREDIT_CARD', 'US_BANK_NUMBER', 'IBAN_CODE', 'SWIFT_CODE', 'US_ITIN', 'US_SSN'], detect: ['PERSON'], deep: false },
  NIST_800_171: { name: 'NIST 800-171 (CUI)', why: 'Government and financial identifiers in controlled unclassified information.',
    block: ['US_SSN', 'US_PASSPORT', 'US_DRIVER_LICENSE', 'US_ITIN', 'CREDIT_CARD', 'US_BANK_NUMBER'], detect: ['PERSON', 'EMAIL_ADDRESS', 'IP_ADDRESS'], deep: true },
  NIST_800_53: { name: 'NIST 800-53 (PII)', why: 'PII handling controls (PT / SI families).',
    block: ['US_SSN', 'US_PASSPORT', 'US_DRIVER_LICENSE', 'US_ITIN', 'CREDIT_CARD', 'US_BANK_NUMBER'], detect: ['PERSON', 'EMAIL_ADDRESS', 'IP_ADDRESS'], deep: true },
  GENERAL: { name: 'General (high-risk PII)', why: 'Card, bank and government ids every organisation protects.',
    block: ['US_SSN', 'CREDIT_CARD', 'US_BANK_NUMBER', 'US_PASSPORT', 'US_DRIVER_LICENSE', 'US_ITIN'], detect: ['PERSON'], deep: false }
};
const profileFor = (id) => PROFILES[id] ? id : 'GENERAL';

/**
 * Build the detection policy body. mode 'monitor': compliance data is DETECT; 'block': the profile's block list is BLOCK.
 * In both modes prompt injection, malicious URLs and invisible text are blocked: they are attacks, not compliance data.
 */
function buildPolicy(name, profileId, mode) {
  const P = PROFILES[profileFor(profileId)];
  const block = mode === 'block';
  const entities = PII_ENTITIES.map(t => ({ entityType: t, action: P.block.includes(t) ? (block ? 'BLOCK' : 'DETECT') : P.detect.includes(t) ? 'DETECT' : 'DISABLE' }));
  const pii = { detector: 'pii', enabled: true, severity: 'CRITICAL', configuration: { entities, threshold: 0.8, anonymization: 'NONE', defaultAction: 'ALLOW', replaceWithMaskedContent: false } };
  const det = (detector, action, threshold, severity = 'HIGH') => ({ detector, enabled: true, severity, configuration: { action, threshold } });
  const deepAction = block ? 'BLOCK' : 'DETECT';
  const input = [
    det('prompt_injection', 'BLOCK', 0.75, 'CRITICAL'),
    det('malicious_url', 'BLOCK', 0.8, 'CRITICAL'),
    det('invisible_text', 'BLOCK', 0.8),
    det('toxicity', 'DETECT', 0.87, 'LOW'),
    pii,
    ...(P.deep ? [det('pii_deepscan', deepAction, 0.87), det('personal_data', 'DETECT', 0.8, 'LOW')] : [])
  ];
  const output = [
    det('malicious_url', 'BLOCK', 0.8, 'CRITICAL'),
    det('toxicity', 'DETECT', 0.87, 'LOW'),
    { ...pii, severity: 'HIGH' },
    ...(P.deep ? [det('pii_deepscan', 'DETECT', 0.87, 'LOW')] : [])
  ];
  return { name, inputDetectorPolicies: input, outputDetectorPolicies: output };
}

const providersFor = (appIds) => [...new Set(appIds.flatMap(id => (APP_MAP[id] || {}).providers || []))];
const cloudAppsFor = (appIds) => [...new Set(appIds.flatMap(id => (APP_MAP[id] || {}).cloudApps || []))];
const hostsFor = (apps, appIds) => [...new Set(apps.filter(a => appIds.includes(a.id)).flatMap(a => a.domains))];

// Does the tenant's detector list already do what we want? AI Guard adds its own fields and entity types (JP_* as DISABLE, live ZTH),
// so only what the wizard sets is compared: each wanted detector's enabled / severity / action / threshold and its non-disabled entities.
function sameDetectors(have, want) {
  have = have || [];
  if (have.length !== want.length) return false;
  return want.every(w => {
    const h = have.find(x => x.detector === w.detector);
    if (!h || !!h.enabled !== !!w.enabled || h.severity !== w.severity) return false;
    const hc = h.configuration || {}, wc = w.configuration || {};
    if (wc.action !== undefined && hc.action !== wc.action) return false;
    if (wc.threshold !== undefined && Math.abs(Number(hc.threshold) - wc.threshold) > 0.001) return false;
    if (wc.defaultAction !== undefined && hc.defaultAction !== wc.defaultAction) return false;
    if (wc.entities) {
      const live = (l) => JSON.stringify((l || []).filter(e => e.action !== 'DISABLE').map(e => e.entityType + ':' + e.action).sort());
      if (live(hc.entities) !== live(wc.entities)) return false;
    }
    return true;
  });
}

/**
 * ZIA allow for the sanctioned AI apps.
 * - Cloud App Control (AI_ML): "<prefix>-AIG-Allow-AI" at order 1, Allow web use for the picked apps. Uploads still follow the other rules.
 * - URL Filtering: only when an enabled Block / Caution / Isolate rule covers a picked app's URL category, a custom URL category of the
 *   picked apps' domains and an Allow rule at order 1.
 * Rules that would otherwise stop the picked apps are listed as notes (they keep applying to every other AI app).
 */
async function ziaAllow(ctx) {
  const { client, input, dryRun, rec, undo, warnings, N, list, apps } = ctx;
  const ids = (input.ziaAllow || []).filter(id => APP_MAP[id]);
  if (!ids.length) { rec({ category: 'Cloud App Control', name: N.allow, action: 'SKIPPED', note: 'no AI app picked for a ZIA allow' }); return; }
  const path = '/api/v1/webApplicationRules/AI_ML';
  // ZIA refuses a rule whose action an app does not support (some AI apps list no granular actions): keep only apps that take Allow web use
  const cloudApps = [];
  const noAllow = [];
  for (const app of cloudAppsFor(ids)) {
    try {
      const acts = list(await client.apiCall('POST', `${path}/availableActions`, { cloudApps: [app], type: 'AI_ML' }));
      if (acts.includes('ALLOW_AI_ML_WEB_USE')) cloudApps.push(app); else noAllow.push(app);
    } catch (e) { cloudApps.push(app); }   // unknown: let the create decide
  }
  if (noAllow.length) warnings.push(`ZIA has no "Allow web use" action for ${noAllow.join(', ')}, so they are left out of "${N.allow}". If a category-wide AI rule blocks or cautions them, add an exception in the ZIA portal.`);
  if (!cloudApps.length) { rec({ category: 'Cloud App Control', name: N.allow, action: 'SKIPPED', error: `None of the picked apps (${noAllow.join(', ')}) takes an Allow action in ZIA.` }); }
  else try {
    const rules = list(await client.apiCall('GET', path));
    const ex = rules.find(r => r.name === N.allow);
    // what would stop the picked apps today
    const stoppers = rules.filter(r => r !== ex && r.state !== 'DISABLED' && (r.actions || []).some(a => /^(DENY|BLOCK|CAUTION|ISOLATE)_AI_ML_WEB_USE$/.test(a))
      && (!(r.applications || []).length || (r.applications || []).some(a => cloudApps.includes(a))));
    if (stoppers.length) warnings.push(`ZIA Cloud App Control: ${stoppers.map(r => `"${r.name}" (${(r.actions || []).filter(a => /WEB_USE/.test(a)).join(', ')})`).join(', ')} would stop the picked AI apps; "${N.allow}" at order 1 allows them first. Those rules still apply to every other AI app.`);
    const want = { name: N.allow, description: 'Sanctioned AI apps go through ZIA inspection to AI Guard. Created by the ZTP Policy Wizard.', state: 'ENABLED', rank: 7, type: 'AI_ML', actions: ['ALLOW_AI_ML_WEB_USE'], applications: cloudApps };
    if (!ex) {
      if (!dryRun) { const c = await client.apiCall('POST', path, { ...want, order: 1 }); undo.push({ op: 'DELETE', path: `${path}/${c.id}`, label: `Cloud App Control: ${N.allow}` }); }
      rec({ category: 'Cloud App Control', name: N.allow, action: 'CREATE', note: `order 1, Allow: ${cloudApps.join(', ')}` });
    } else {
      const same = ex.order === 1 && ex.state !== 'DISABLED' && JSON.stringify([...(ex.applications || [])].sort()) === JSON.stringify([...cloudApps].sort()) && JSON.stringify(ex.actions) === JSON.stringify(want.actions);
      if (same) rec({ category: 'Cloud App Control', name: N.allow, action: 'NO_CHANGE' });
      else {
        if (!dryRun) { undo.push({ op: 'PUT', path: `${path}/${ex.id}`, body: ex, label: `Cloud App Control: ${N.allow}` }); await client.apiCall('PUT', `${path}/${ex.id}`, { ...ex, ...want, id: ex.id, order: 1 }); }
        rec({ category: 'Cloud App Control', name: N.allow, action: 'UPDATE', changes: ['applications / order'] });
      }
    }
  } catch (e) { rec({ category: 'Cloud App Control', name: N.allow, action: 'FAILED', error: e.message }); }

  // URL filtering: categories of the picked apps, and any rule that would block / caution / isolate them
  try {
    const hosts = hostsFor(apps, ids).map(h => h.replace(/^\./, ''));
    const looked = list(await client.apiCall('POST', '/api/v1/urlLookup', hosts.slice(0, 100)));
    const cats = new Set(looked.flatMap(u => u.urlClassifications || []));
    const urlRules = list(await client.apiCall('GET', '/api/v1/urlFilteringRules'));
    const catRule = urlRules.find(r => r.name === N.allowUrl);
    const hits = urlRules.filter(r => r !== catRule && r.state !== 'DISABLED' && /^(BLOCK|CAUTION|ISOLATE)$/.test(r.action) && (r.urlCategories || []).some(c => cats.has(c)));
    if (!hits.length && !catRule) { rec({ category: 'URL Filtering', name: N.allowUrl, action: 'NO_CHANGE', note: `not needed: no URL rule blocks, cautions or isolates ${[...cats].join(', ') || 'these apps'}` }); return; }
    if (hits.length) warnings.push(`ZIA URL Filtering: ${hits.map(r => `"${r.name}" (${r.action})`).join(', ')} cover the AI apps' category (${[...cats].join(', ')}); "${N.allowUrl}" allows the picked apps first.`);
    // custom URL category with the picked apps' domains
    const customs = list(await client.apiCall('GET', '/api/v1/urlCategories?customOnly=true'));
    let cat = customs.find(c => c.configuredName === N.allowUrl);
    const urls = hostsFor(apps, ids);
    if (!cat) {
      if (dryRun) cat = { id: 'NEW', configuredName: N.allowUrl };
      else { cat = await client.apiCall('POST', '/api/v1/urlCategories', { configuredName: N.allowUrl, superCategory: 'USER_DEFINED', customCategory: true, urls, description: 'Sanctioned AI apps (AI Guard). Created by the ZTP Policy Wizard.' }); undo.push({ op: 'DELETE', path: `/api/v1/urlCategories/${cat.id}`, label: `URL Category: ${N.allowUrl}` }); }
      rec({ category: 'URL Category', name: N.allowUrl, action: 'CREATE', note: `${urls.length} domains` });
    } else {
      const same = JSON.stringify([...(cat.urls || [])].sort()) === JSON.stringify([...urls].sort());
      if (!same && !dryRun) { undo.push({ op: 'PUT', path: `/api/v1/urlCategories/${cat.id}`, body: cat, label: `URL Category: ${N.allowUrl}` }); await client.apiCall('PUT', `/api/v1/urlCategories/${cat.id}`, { ...cat, urls }); }
      rec({ category: 'URL Category', name: N.allowUrl, action: same ? 'NO_CHANGE' : 'UPDATE', ...(same ? {} : { changes: ['urls'] }) });
    }
    const body = { name: N.allowUrl, description: 'Allow the sanctioned AI apps (AI Guard inspects them). Created by the ZTP Policy Wizard.', state: 'ENABLED', rank: 7, action: 'ALLOW',
      urlCategories: [cat.id], protocols: ['ANY_RULE'], blockOverride: false, enforceTimeValidity: false };
    if (!catRule) {
      if (!dryRun) { const c = await client.apiCall('POST', '/api/v1/urlFilteringRules', { ...body, order: 1 }); undo.push({ op: 'DELETE', path: `/api/v1/urlFilteringRules/${c.id}`, label: `URL Filtering: ${N.allowUrl}` }); }
      rec({ category: 'URL Filtering', name: N.allowUrl, action: 'CREATE', note: 'order 1, Allow' });
    } else if (catRule.order !== 1 || catRule.action !== 'ALLOW' || catRule.state === 'DISABLED') {
      if (!dryRun) { undo.push({ op: 'PUT', path: `/api/v1/urlFilteringRules/${catRule.id}`, body: catRule, label: `URL Filtering: ${N.allowUrl}` }); await client.apiCall('PUT', `/api/v1/urlFilteringRules/${catRule.id}`, { ...catRule, ...body, id: catRule.id, order: 1 }); }
      rec({ category: 'URL Filtering', name: N.allowUrl, action: 'UPDATE', changes: ['order / action'] });
    } else rec({ category: 'URL Filtering', name: N.allowUrl, action: 'NO_CHANGE' });
  } catch (e) { rec({ category: 'URL Filtering', name: N.allowUrl, action: 'FAILED', error: e.message }); }
}

/**
 * AI Guard detection policy for the compliance profile, and a policy-match rule for the picked apps' LLM providers.
 * The rule goes after the tenant's existing rules so it never pre-empts a policy the customer already has.
 */
async function aiguardPolicy(ctx) {
  const { client, input, dryRun, rec, undo, warnings, N, aiguardCall } = ctx;
  const c = input.compliance;
  if (!c || c.profile === 'NONE') { rec({ category: 'AI Guard Policy', name: N.policy, action: 'SKIPPED', note: 'no compliance profile chosen' }); return; }
  const profile = profileFor(c.profile);
  const mode = c.mode === 'block' ? 'block' : 'monitor';
  const want = buildPolicy(N.policy, profile, mode);
  const AG = (m, p, b) => aiguardCall(client, m, '/aiguard/v1' + p, b);
  const lst = (r) => (Array.isArray(r) ? r : (r && (r.items || r.list)) || []);
  let pol;
  try {
    const ex = lst(await AG('GET', '/detections/policies')).find(p => p.name === N.policy);
    if (!ex) {
      if (dryRun) pol = { id: 0 };
      else { pol = await AG('POST', '/detections/policies', want); undo.push({ api: 'aiguard', op: 'DELETE', path: `/aiguard/v1/detections/policies/${pol.id}`, label: `AI Guard Policy: ${N.policy}` }); }
      rec({ category: 'AI Guard Policy', name: N.policy, action: 'CREATE', note: `${PROFILES[profile].name}, ${mode === 'block' ? 'Block' : 'Monitor'}` });
    } else {
      pol = ex;
      const same = sameDetectors(ex.inputDetectorPolicies, want.inputDetectorPolicies) && sameDetectors(ex.outputDetectorPolicies, want.outputDetectorPolicies);
      if (same) rec({ category: 'AI Guard Policy', name: N.policy, action: 'NO_CHANGE', note: `${PROFILES[profile].name}, ${mode === 'block' ? 'Block' : 'Monitor'}` });
      else {
        if (!dryRun) {
          undo.push({ api: 'aiguard', op: 'PUT', path: `/aiguard/v1/detections/policies/${ex.id}`, body: { name: ex.name, inputDetectorPolicies: ex.inputDetectorPolicies || [], outputDetectorPolicies: ex.outputDetectorPolicies || [] }, label: `AI Guard Policy: ${N.policy}` });
          await AG('PUT', `/detections/policies/${ex.id}`, want);   // PUT replaces the whole policy
        }
        rec({ category: 'AI Guard Policy', name: N.policy, action: 'UPDATE', changes: ['detectors'], note: `${PROFILES[profile].name}, ${mode === 'block' ? 'Block' : 'Monitor'}` });
      }
    }
  } catch (e) { rec({ category: 'AI Guard Policy', name: N.policy, action: 'FAILED', error: e.message }); return; }

  // policy-match rule: the picked apps' LLM providers → this policy
  try {
    const appIds = input.apps && input.apps.length ? input.apps : [];
    const all = lst(await AG('GET', '/llm-providers'));
    const names = providersFor(appIds).filter(n => all.some(p => p.name === n));
    if (!names.length) { rec({ category: 'AI Guard Policy Rule', name: N.policyRule, action: 'SKIPPED', error: 'None of the picked apps has an AI Guard LLM provider on this tenant.' }); return; }
    const rules = lst(await AG('GET', '/detections/policy-match-rules'));
    const ex = rules.find(r => r.name === N.policyRule);
    const mc = { type: 'APPLICATION', llmProviders: names.map(n => ({ llmProvider: n, llmProviderModels: [] })), llmApplications: [], sourceIpAddresses: [], applicationGroups: [], customRequestHeaders: [] };
    const others = rules.filter(r => r !== ex && r.enabled !== false && ((r.matchCriteria || {}).llmProviders || []).some(p => names.includes(p.llmProvider)));
    if (others.length) warnings.push(`AI Guard: ${others.map(r => `"${r.name}"`).join(', ')} already match${others.length === 1 ? 'es' : ''} some of these providers and come${others.length === 1 ? 's' : ''} first; "${N.policyRule}" is added after the existing rules.`);
    const order = Math.max(0, ...rules.filter(r => r !== ex).map(r => r.ruleOrder || 0)) + 1;
    const body = { policyId: pol.id, name: N.policyRule, enabled: true, ruleOrder: ex ? ex.ruleOrder : order, matchCriteria: mc };
    if (!ex) {
      if (!dryRun) { const r = await AG('POST', '/detections/policy-match-rules', body); undo.push({ api: 'aiguard', op: 'DELETE', path: `/aiguard/v1/detections/policy-match-rules/${r.id}`, label: `AI Guard Policy Rule: ${N.policyRule}` }); }
      rec({ category: 'AI Guard Policy Rule', name: N.policyRule, action: 'CREATE', note: `order ${order}: ${names.join(', ')}` });
    } else {
      const have = ((ex.matchCriteria || {}).llmProviders || []).map(p => p.llmProvider).sort();
      const same = String(ex.policyId) === String(pol.id) && ex.enabled !== false && JSON.stringify(have) === JSON.stringify([...names].sort());
      if (same) rec({ category: 'AI Guard Policy Rule', name: N.policyRule, action: 'NO_CHANGE' });
      else {
        if (!dryRun) { undo.push({ api: 'aiguard', op: 'PUT', path: `/aiguard/v1/detections/policy-match-rules/${ex.id}`, body: { policyId: ex.policyId, name: ex.name, enabled: ex.enabled, ruleOrder: ex.ruleOrder, matchCriteria: ex.matchCriteria }, label: `AI Guard Policy Rule: ${N.policyRule}` }); await AG('PUT', `/detections/policy-match-rules/${ex.id}`, body); }
        rec({ category: 'AI Guard Policy Rule', name: N.policyRule, action: 'UPDATE', changes: ['providers / policy'] });
      }
    }
  } catch (e) { rec({ category: 'AI Guard Policy Rule', name: N.policyRule, action: 'FAILED', error: e.message }); }
}

module.exports = { PROFILES, APP_MAP, PII_ENTITIES, buildPolicy, profileFor, cloudAppsFor, providersFor, ziaAllow, aiguardPolicy };
