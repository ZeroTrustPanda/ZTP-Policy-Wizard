/**
 * v2.5: AI Guard. ZIA inspects the AI apps' traffic and proxy-chains it to AI Guard (forward.prod.zsaiguard.net:9443),
 * following Zscaler's "Integrating ZIA with AI Guard" guide:
 *   root certificate (Proxy Chaining) → proxy → proxy gateway (UI only: the API is read-only) → block QUIC →
 *   destination group (wildcard FQDNs of the AI apps) → forwarding rule (Proxy Chaining to the gateway).
 * Added by the wizard because the guide assumes it: an SSL Inspect rule for the AI apps placed above the
 * "Office 365 One Click Rule" bypass (otherwise Microsoft 365 Copilot is never decrypted), and Gen AI prompt capture.
 * Same dry-run / apply contract as the other products: the ledger lists Create / Update / No change, undo is recorded.
 */
'use strict';
const AP = require('./aiguard-policy');
const list = (r) => (Array.isArray(r) ? r : (r && (r.list || r.items || r.content)) || []);

const AI_GUARD_PROXY = { address: 'forward.prod.zsaiguard.net', port: 9443 };
// AI Guard forwarders: the guide's forward.prod.zsaiguard.net and the older forward.zseclipse.net both appear on live tenants
const AIG_HOST = /^forward(\.[a-z0-9-]+)*\.(zsaiguard|zseclipse)\.net$/i;

/** Apps from the guide's supported-apps table (Sept 2026). prompt = the ZIA prompt-capture switch for the app, when there is one. */
const AI_APPS = [
  { id: 'chatgpt', name: 'OpenAI ChatGPT / Codex', domains: ['.chatgpt.com', '.chat.openai.com'], prompt: 'enableChatGptPrompt', default: true },
  { id: 'm365copilot', name: 'Microsoft 365 Copilot', domains: ['.substrate.office.com', '.substrate.svc.cloud.microsoft', '.copilot.microsoft.com', '.augloop.office.com', 'www.copilot.com'], prompt: 'enableMicrosoftCoPilotPrompt', default: true, copilot: true },
  { id: 'claude', name: 'Anthropic Claude (web, desktop, Claude Code)', domains: ['.claude.ai', '.api.anthropic.com'], prompt: 'enableClaudePrompt', default: true },
  { id: 'gemini', name: 'Google Gemini', domains: ['.gemini.google.com'], prompt: 'enableGeminiPrompt', default: true },
  { id: 'githubcopilot', name: 'GitHub Copilot', domains: ['.api.business.githubcopilot.com', '.api.enterprise.githubcopilot.com', '.api.individual.githubcopilot.com'] },
  { id: 'perplexity', name: 'Perplexity', domains: ['.perplexity.ai'], prompt: 'enablePerPlexityPrompt' },
  { id: 'grok', name: 'Grok (xAI)', domains: ['.grok.com'], prompt: 'enableGrokPrompt' },
  { id: 'mistral', name: 'Mistral', domains: ['.mistral.ai'], prompt: 'enableMistralAIPrompt' },
  { id: 'notebooklm', name: 'NotebookLM', domains: ['.notebooklm.google.com'] },
  { id: 'glean', name: 'Glean', domains: ['.glean.com'] }
];
// The guide also lists all of .cloud.microsoft for Copilot; that covers most of Microsoft 365, so it is opt-in.
const CLOUD_MICROSOFT = '.cloud.microsoft';
const GENAI_SKUS = ['ZS_DP_GEN_AI'];

// ZIA names are limited to 31 characters: the prefix is shortened when it would not fit
const nm = (prefix, suffix) => `${String(prefix).slice(0, 31 - suffix.length - 1)}-${suffix}`;
const names = (prefix) => ({
  cert: nm(prefix, 'AIG-CA'), proxy: nm(prefix, 'AIG-Proxy'), gateway: nm(prefix, 'AIG-Gateway'), group: nm(prefix, 'AIG-Apps'),
  quic: nm(prefix, 'AIG-NoQUIC'), ssl: nm(prefix, 'AIG-Inspect'), fwd: nm(prefix, 'AIG-Forward'),
  allow: nm(prefix, 'AIG-Allow-AI'), allowUrl: nm(prefix, 'AIG-Allow-URL'), policy: nm(prefix, 'AIG-Compliance'), policyRule: nm(prefix, 'AIG-Compliance-Apps')
});

function domainsFor(input) {
  const ids = new Set(input.apps && input.apps.length ? input.apps : AI_APPS.filter(a => a.default).map(a => a.id));
  const out = [];
  for (const a of AI_APPS) if (ids.has(a.id)) out.push(...a.domains);
  for (const d of input.extraDomains || []) out.push(String(d).trim().toLowerCase().replace(/^\*\./, '.'));
  if (input.includeCloudMicrosoft) out.push(CLOUD_MICROSOFT);
  return [...new Set(out.filter(Boolean))];
}

/** AI Guard ("zguard") over OneAPI: same token as ZIA, base /aiguard/v1. Read-only use here (validation). */
async function aiguardCall(client, method, path, body) {
  if (!client || !client.isAuthenticated() || client.authMode !== 'oneapi') throw new Error('AI Guard needs a OneAPI sign-in.');
  const headers = { 'Content-Type': 'application/json', Accept: 'application/json', Authorization: `Bearer ${client.accessToken}` };
  console.log(`[AIGUARD-API] ${method} ${path}`);
  const res = await client._rawRequest(method, client.baseUrl, path, body ? JSON.stringify(body) : null, headers);
  if (res.statusCode >= 200 && res.statusCode < 300) return res.body === '' ? null : res.body;
  throw new Error(`AI Guard API Error ${res.statusCode}: ${(typeof res.body === 'string' ? res.body : JSON.stringify(res.body)).slice(0, 200)}`);
}

const PEM_RE = /^-----BEGIN CERTIFICATE-----[\s\S]+-----END CERTIFICATE-----\s*$/;
function validate(input) {
  const errors = [];
  if (!input.prefix) errors.push('Set the prefix first (customer intake).');
  const c = input.cert || {};
  if (c.mode === 'upload' && !PEM_RE.test(String(c.pem || '').trim())) errors.push('The AI Guard CA certificate must be a PEM file (-----BEGIN CERTIFICATE-----). Download it from the AI Guard portal: Tenant Settings › Integrations › Download Zscaler AI Guard Proxy Chain Certificate.');
  if (c.mode === 'existing' && !c.id) errors.push('Pick the AI Guard root certificate already uploaded to ZIA, or upload it.');
  if (!c.mode) errors.push('Add the AI Guard CA certificate (upload the .pem or pick one already in ZIA).');
  for (const d of input.extraDomains || []) if (!/^(\*?\.)?[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(String(d).trim())) errors.push(`"${d}" is not a domain or wildcard domain (for example .chat.example.com).`);
  if (input.proxyHost && !AIG_HOST.test(String(input.proxyHost))) errors.push(`"${input.proxyHost}" is not an AI Guard forwarding host (for example forward.prod.zsaiguard.net).`);
  if (!domainsFor(input).length) errors.push('Pick at least one AI app.');
  return errors;
}

/** Read-only checks for the AI Guard step (and readiness). */
async function context(client) {
  const out = { checks: [], rootCertificates: [], gateways: [], subscriptions: null, promptFields: [] };
  const check = (name, status, detail, fix) => out.checks.push({ name, status, detail, ...(fix ? { fix } : {}) });
  try {
    const p = await aiguardCall(client, 'GET', '/aiguard/v1/detections/policies');
    check('AI Guard API (zguard)', 'pass', `Reachable: ${list(p).length} detection polic${list(p).length === 1 ? 'y' : 'ies'} in AI Guard.`);
    out.aiguard = { ok: true, policies: list(p).map(x => x.name).slice(0, 20) };
  } catch (e) {
    const m = String(e.message);
    out.aiguard = { ok: false, error: m.slice(0, 200) };
    check('AI Guard API (zguard)', 'fail', /40[13]/.test(m) ? 'The API client can\'t reach AI Guard (not entitled, or the AI Guard role is missing on the API client).' : `AI Guard didn't answer: ${m.slice(0, 160)}`,
      'Make sure the tenant has an AI Guard subscription linked to ZIA (Zscaler Support links them), and give the ZIdentity API client the AI Guard API role.');
  }
  try {
    const subs = list(await client.apiCall('GET', '/api/v1/subscriptions')).filter(s => s.subscribed !== false && !/EXPIRED|CANCEL/i.test(String(s.status || '')));
    out.subscriptions = subs.map(s => s.id);
    const gen = GENAI_SKUS.find(k => out.subscriptions.includes(k));
    out.genAiLicensed = !!gen;
    check('Gen AI Security licence (prompt capture)', gen ? 'pass' : 'warn', gen ? `Subscription ${gen}.` : 'No Gen AI Security subscription: AI prompt capture in ZIA is left off.');
  } catch (e) { out.genAiLicensed = null; }
  try {
    out.rootCertificates = list(await client.apiCall('GET', '/api/v1/rootCertificates?certTypes=PROXY_CHAINING')).map(c => ({ id: c.id, name: c.name || c.displayName, expiry: c.expiryTime || null }));
  } catch (e) { out.rootCertificatesError = String(e.message).slice(0, 200); }
  try {
    const gws0 = list(await client.apiCall('GET', '/api/v1/proxyGateways'));
    out.existingProxies = list(await client.apiCall('GET', '/api/v1/proxies')).filter(p => p.type === 'PROXYCHAIN' && AIG_HOST.test(String(p.address || '')))
      .map(p => ({ id: p.id, name: p.name, address: p.address, port: p.port, certId: p.cert && p.cert.id, gateway: (gws0.find(g => g.primaryProxy && String(g.primaryProxy.id) === String(p.id)) || {}).name || null }));
    if (out.existingProxies.length) check('Existing AI Guard proxy', 'info', `Found ${out.existingProxies.map(p => `"${p.name}" (${p.address}:${p.port}${p.gateway ? `, gateway "${p.gateway}"` : ''})`).join(', ')}. Choose its root certificate below and the wizard reuses this proxy and gateway instead of creating new ones.`);
  } catch (e) { out.existingProxies = []; }
  try { out.gateways = list(await client.apiCall('GET', '/api/v1/proxyGateways')).map(g => ({ id: g.id, name: g.name, failClosed: g.failClosed, primaryProxy: g.primaryProxy || null, type: g.type })); } catch (e) { out.gatewaysError = String(e.message).slice(0, 200); }
  try {
    const adv = await client.apiCall('GET', '/api/v1/advancedUrlFilterAndCloudAppSettings');
    out.o365OneClick = !!(adv && adv.enableMsftO365);
    out.promptFields = Object.keys(adv || {}).filter(k => /Prompt$/.test(k));
    if (out.o365OneClick) check('Microsoft 365 one-click bypass', 'info', 'On: Microsoft 365 traffic is not inspected by default. The wizard adds an Inspect rule for the AI app domains above the "Office 365 One Click" rule so Copilot reaches AI Guard.');
  } catch (e) { /* not fatal */ }
  check('AI Guard portal settings', 'info', 'In the AI Guard portal turn on Store Prompts/Responses (Tenant Settings › Security) and ZIA User and Group Sync plus ZIA Domain Sync (Tenant Settings › Integrations).');
  return out;
}

/**
 * Plan or apply. Returns { ledger, warnings, followUps, undo, gatewayMissing }.
 * ledger rows: { product:'ZIA', category, name, action: CREATE|UPDATE|NO_CHANGE|SKIPPED|MANUAL|FAILED, error?, changes? }
 */
async function runAiGuard(client, input, { dryRun, logger } = {}) {
  const errs = validate(input);
  if (errs.length) throw Object.assign(new Error(errs.join(' ')), { status: 400 });
  const N = names(input.prefix);
  const ledger = [], warnings = [], followUps = [], undo = [];
  const rec = (row) => { ledger.push({ product: 'ZIA', ...row }); if (logger && !dryRun && row.action !== 'NO_CHANGE') logger.logPolicyApply('AI Guard', row.name, row.action, row.error ? { error: row.error } : { success: true }); };
  const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
  const domains = domainsFor(input);
  let certRef = null, proxy = null, group = null, gateway = null;

  // 1. root certificate (Proxy Chaining)
  try {
    const certs = list(await client.apiCall('GET', '/api/v1/rootCertificates?certTypes=PROXY_CHAINING'));
    if (input.cert.mode === 'existing') {
      const c = certs.find(x => String(x.id) === String(input.cert.id));
      if (!c) throw new Error('The selected root certificate is no longer in ZIA.');
      certRef = { id: c.id, name: c.name || c.displayName };
      rec({ category: 'Root Certificate', name: certRef.name, action: 'NO_CHANGE', note: 'existing, Proxy Chaining' });
    } else {
      const c = certs.find(x => (x.name || x.displayName) === N.cert);
      if (c) { certRef = { id: c.id, name: N.cert }; rec({ category: 'Root Certificate', name: N.cert, action: 'NO_CHANGE', note: 'already uploaded' }); }
      else if (dryRun) { certRef = { id: 0, name: N.cert }; rec({ category: 'Root Certificate', name: N.cert, action: 'CREATE', note: 'AI Guard CA, Proxy Chaining' }); }
      else {
        const created = await client.apiCall('POST', '/api/v1/rootCertificates', { name: N.cert, cert: String(input.cert.pem).trim(), certTypes: ['PROXY_CHAINING'] });
        certRef = { id: created.id, name: N.cert };
        undo.push({ op: 'DELETE', path: `/api/v1/rootCertificates/${created.id}?certTypes=PROXY_CHAINING`, label: `Root Certificate: ${N.cert}` });
        rec({ category: 'Root Certificate', name: N.cert, action: 'CREATE' });
      }
    }
  } catch (e) { rec({ category: 'Root Certificate', name: N.cert, action: 'FAILED', error: e.message }); }

  // 2. proxy
  if (certRef) {
    try {
      const host = AIG_HOST.test(String(input.proxyHost || '')) ? String(input.proxyHost) : AI_GUARD_PROXY.address;
      const want = { name: N.proxy, type: 'PROXYCHAIN', address: host, port: AI_GUARD_PROXY.port, cert: { id: certRef.id, name: certRef.name },
        insertXauHeader: true, base64EncodeXauHeader: false, description: 'AI Guard proxy chaining. Created by the ZTP Policy Wizard.' };
      const allProxies = list(await client.apiCall('GET', '/api/v1/proxies'));
      const ex = allProxies.find(p => p.name === N.proxy);
      // an AI Guard proxy that already uses the chosen certificate is reused rather than duplicated
      const reuse = !ex && certRef.id ? allProxies.find(p => p.type === 'PROXYCHAIN' && AIG_HOST.test(String(p.address || '')) && p.cert && String(p.cert.id) === String(certRef.id)) : null;
      const cmp = (p) => ({ address: p.address, port: Number(p.port), cert: p.cert && String(p.cert.id), x: !!p.insertXauHeader, b: !!p.base64EncodeXauHeader, type: p.type });
      if (reuse) { proxy = { id: reuse.id, name: reuse.name }; rec({ category: 'Proxy', name: reuse.name, action: 'NO_CHANGE', note: `existing AI Guard proxy, ${reuse.address}:${reuse.port}` }); }
      else if (!ex) {
        if (dryRun) { proxy = { id: 0, name: N.proxy }; rec({ category: 'Proxy', name: N.proxy, action: 'CREATE', note: `${host}:${AI_GUARD_PROXY.port}` }); }
        else { const c = await client.apiCall('POST', '/api/v1/proxies', want); proxy = { id: c.id, name: N.proxy }; undo.push({ op: 'DELETE', path: `/api/v1/proxies/${c.id}`, label: `Proxy: ${N.proxy}` }); rec({ category: 'Proxy', name: N.proxy, action: 'CREATE' }); }
      } else if (same(cmp(ex), cmp(want)) || (dryRun && !certRef.id)) {
        proxy = { id: ex.id, name: N.proxy };
        rec({ category: 'Proxy', name: N.proxy, action: dryRun && !certRef.id ? 'UPDATE' : 'NO_CHANGE', ...(dryRun && !certRef.id ? { changes: ['cert'] } : {}) });
      } else {
        proxy = { id: ex.id, name: N.proxy };
        const changes = Object.keys(cmp(want)).filter(k => cmp(ex)[k] !== cmp(want)[k]);
        if (!dryRun) { undo.push({ op: 'PUT', path: `/api/v1/proxies/${ex.id}`, body: ex, label: `Proxy: ${N.proxy}` }); await client.apiCall('PUT', `/api/v1/proxies/${ex.id}`, { ...want, id: ex.id }); }
        rec({ category: 'Proxy', name: N.proxy, action: 'UPDATE', changes });
      }
    } catch (e) { rec({ category: 'Proxy', name: N.proxy, action: 'FAILED', error: e.message }); }
  } else rec({ category: 'Proxy', name: N.proxy, action: 'SKIPPED', error: 'Needs the root certificate.' });

  // 3. proxy gateway: the API is read-only, so it is a manual step until it exists
  try {
    const gws = list(await client.apiCall('GET', '/api/v1/proxyGateways'));
    gateway = (proxy && proxy.id ? gws.find(g => g.primaryProxy && String(g.primaryProxy.id) === String(proxy.id)) : null) || gws.find(g => g.name === N.gateway) || null;
    if (gateway) {
      const okGw = gateway.failClosed !== false && (!proxy || !proxy.id || (gateway.primaryProxy && String(gateway.primaryProxy.id) === String(proxy.id)));
      rec({ category: 'Proxy Gateway', name: gateway.name, action: 'NO_CHANGE', note: okGw ? 'found: Fail Close on, primary proxy = AI Guard proxy' : 'found, but check Fail Close and the primary proxy' });
      if (!okGw) warnings.push(`Proxy gateway "${gateway.name}" should have Fail Close on and "${proxy ? proxy.name : N.proxy}" as its primary proxy.`);
    } else {
      rec({ category: 'Proxy Gateway', name: N.gateway, action: 'MANUAL', note: 'create in the ZIA portal (the API cannot create gateways)' });
      followUps.push(`In ZIA › Infrastructure › Internet & SaaS › Network Policies › Proxies and Gateways › Proxy Gateways, add "${N.gateway}": Fail Close on, Primary Proxy "${N.proxy}", Secondary None. Then run the AI Guard dry run again to create the forwarding rule.`);
    }
  } catch (e) { rec({ category: 'Proxy Gateway', name: N.gateway, action: 'FAILED', error: e.message }); }

  // 4. destination group (wildcard FQDN)
  try {
    const want = { name: N.group, type: 'DSTN_DOMAIN', addresses: domains, description: 'AI apps sent to AI Guard. Created by the ZTP Policy Wizard.' };
    const ex = list(await client.apiCall('GET', '/api/v1/ipDestinationGroups')).find(g => g.name === N.group);
    if (!ex) {
      if (dryRun) { group = { id: 0, name: N.group }; rec({ category: 'Destination Group', name: N.group, action: 'CREATE', note: `${domains.length} wildcard domains` }); }
      else { const c = await client.apiCall('POST', '/api/v1/ipDestinationGroups', want); group = { id: c.id, name: N.group }; undo.push({ op: 'DELETE', path: `/api/v1/ipDestinationGroups/${c.id}`, label: `Destination Group: ${N.group}` }); rec({ category: 'Destination Group', name: N.group, action: 'CREATE' }); }
    } else {
      group = { id: ex.id, name: N.group };
      const a = [...(ex.addresses || [])].sort(), b = [...domains].sort();
      if (same(a, b)) rec({ category: 'Destination Group', name: N.group, action: 'NO_CHANGE' });
      else {
        if (!dryRun) { undo.push({ op: 'PUT', path: `/api/v1/ipDestinationGroups/${ex.id}`, body: ex, label: `Destination Group: ${N.group}` }); await client.apiCall('PUT', `/api/v1/ipDestinationGroups/${ex.id}`, { ...ex, addresses: domains }); }
        rec({ category: 'Destination Group', name: N.group, action: 'UPDATE', changes: ['addresses'] });
      }
    }
  } catch (e) { rec({ category: 'Destination Group', name: N.group, action: 'FAILED', error: e.message }); }

  // 5. block QUIC so browsers fall back to TCP 443, which ZIA can inspect and chain
  if (input.blockQuic !== false) {
    try {
      const svc = list(await client.apiCall('GET', '/api/v1/networkServices?search=QUIC')).find(s => s.name === 'QUIC' || s.tag === 'QUIC');
      if (!svc) throw new Error('The predefined QUIC network service was not found on this tenant.');
      const rules = list(await client.apiCall('GET', '/api/v1/firewallFilteringRules'));
      const ex = rules.find(r => r.name === N.quic);
      const want = { name: N.quic, order: 1, rank: 7, state: 'ENABLED', action: 'BLOCK_ICMP', nwServices: [{ id: svc.id }], description: 'Drop QUIC (UDP 443) so AI apps use TLS over TCP, which ZIA inspects and chains to AI Guard. Created by the ZTP Policy Wizard.' };
      if (!ex) {
        if (!dryRun) { const c = await client.apiCall('POST', '/api/v1/firewallFilteringRules', want); undo.push({ op: 'DELETE', path: `/api/v1/firewallFilteringRules/${c.id}`, label: `Firewall: ${N.quic}` }); }
        rec({ category: 'Firewall Filtering', name: N.quic, action: 'CREATE', note: 'Block/ICMP, network service QUIC' });
      } else if (ex.action === 'BLOCK_ICMP' && ex.state !== 'DISABLED' && (ex.nwServices || []).some(s => String(s.id) === String(svc.id))) rec({ category: 'Firewall Filtering', name: N.quic, action: 'NO_CHANGE' });
      else {
        if (!dryRun) { undo.push({ op: 'PUT', path: `/api/v1/firewallFilteringRules/${ex.id}`, body: ex, label: `Firewall: ${N.quic}` }); await client.apiCall('PUT', `/api/v1/firewallFilteringRules/${ex.id}`, { ...ex, ...want, order: ex.order, id: ex.id }); }
        rec({ category: 'Firewall Filtering', name: N.quic, action: 'UPDATE', changes: ['action', 'nwServices', 'state'] });
      }
    } catch (e) { rec({ category: 'Firewall Filtering', name: N.quic, action: 'FAILED', error: e.message }); }
  }

  // 6. SSL: inspect the AI apps, above the Microsoft 365 one-click bypass and Zscaler's exemptions
  if (input.sslInspect !== false && group) {
    try {
      const rules = list(await client.apiCall('GET', '/api/v1/sslInspectionRules')).filter(r => !r.defaultRule).sort((a, b) => a.order - b.order);
      const bypass = rules.find(r => r.predefined && /Office 365 One Click/i.test(r.name)) || rules.find(r => r.predefined && /Recommended Exemptions/i.test(r.name));
      const ex = rules.find(r => r.name === N.ssl);
      // the rule only matches the AI destination group, so it goes first: no bypass rule (custom or predefined) can catch the AI apps before it
      const firstNoDecrypt = rules.filter(r => r !== ex && r.action && r.action.type === 'DO_NOT_DECRYPT' && r.state !== 'DISABLED').sort((a, b) => a.order - b.order)[0];
      const targetOrder = rules.length ? 1 : Infinity;
      const body = { name: N.ssl, description: 'Decrypt AI apps (ChatGPT, Microsoft 365 Copilot, Claude, Gemini…) so ZIA can chain them to AI Guard. Must stay above the Office 365 One Click rule. Created by the ZTP Policy Wizard.',
        state: 'ENABLED', rank: 7, roadWarriorForKerberos: false, destIpGroups: [{ id: group.id, name: group.name }],
        action: { type: 'DECRYPT', decryptSubActions: { serverCertificates: 'ALLOW', ocspCheck: true, blockSslTrafficWithNoSniEnabled: true, minClientTLSVersion: 'CLIENT_TLS_1_2', minServerTLSVersion: 'SERVER_TLS_1_2', blockUndecrypt: true, http2Enabled: false },
          showEUN: false, showEUNATP: false, overrideDefaultCertificate: false } };
      const order = Number.isFinite(targetOrder) ? targetOrder : (rules.length ? rules[rules.length - 1].order + 1 : 1);
      if (!ex) {
        if (!dryRun) {
          let c;
          try { c = await client.apiCall('POST', '/api/v1/sslInspectionRules', { ...body, order }); }
          catch (e) {
            // some tenants refuse a custom rule above predefined ones: put it right after them and say so
            if (!/not allowed at order/i.test(e.message)) throw e;
            const after = Math.max(0, ...rules.filter(r => r.predefined).map(r => r.order)) + 1;
            c = await client.apiCall('POST', '/api/v1/sslInspectionRules', { ...body, order: after });
            warnings.push(`ZIA did not allow "${N.ssl}" above its predefined SSL rules. Move it above "${bypass ? bypass.name : 'the Office 365 One Click Rule'}" in the ZIA portal, otherwise Microsoft 365 Copilot is not inspected.`);
          }
          undo.push({ op: 'DELETE', path: `/api/v1/sslInspectionRules/${c.id}`, label: `SSL Inspection: ${N.ssl}` });
        }
        rec({ category: 'SSL Inspection', name: N.ssl, action: 'CREATE', note: `order ${order}, above every Do Not Decrypt rule${bypass ? ` (including "${bypass.name}")` : ''}` });
      } else {
        const above = !firstNoDecrypt || ex.order < firstNoDecrypt.order;
        const okBody = ex.action && ex.action.type === 'DECRYPT' && ex.state !== 'DISABLED' && (ex.destIpGroups || []).some(g => String(g.id) === String(group.id));
        if (above && okBody) rec({ category: 'SSL Inspection', name: N.ssl, action: 'NO_CHANGE' });
        else {
          if (!dryRun) { undo.push({ op: 'PUT', path: `/api/v1/sslInspectionRules/${ex.id}`, body: ex, label: `SSL Inspection: ${N.ssl}` }); await client.apiCall('PUT', `/api/v1/sslInspectionRules/${ex.id}`, { ...body, id: ex.id, order: above ? ex.order : order }); }
          rec({ category: 'SSL Inspection', name: N.ssl, action: 'UPDATE', changes: [!above && 'order', !okBody && 'action / destination group'].filter(Boolean) });
        }
      }
      if (domains.some(d => /substrate|copilot/.test(d))) followUps.push('Microsoft 365 Copilot also needs WebSocket inspection: ask Zscaler Support to enable it for the tenant.');
    } catch (e) { rec({ category: 'SSL Inspection', name: N.ssl, action: 'FAILED', error: e.message }); }
  }

  // 7. Gen AI prompt capture for the chosen apps (needs the Gen AI Security licence)
  if (input.promptCapture !== false) {
    try {
      const subs = list(await client.apiCall('GET', '/api/v1/subscriptions')).filter(s => s.subscribed !== false).map(s => s.id);
      if (!GENAI_SKUS.some(k => subs.includes(k))) rec({ category: 'Prompt Capture', name: 'Gen AI prompt capture', action: 'SKIPPED', error: 'No Gen AI Security subscription on this tenant.' });
      else {
        const adv = await client.apiCall('GET', '/api/v1/advancedUrlFilterAndCloudAppSettings');
        const ids = new Set(input.apps && input.apps.length ? input.apps : AI_APPS.filter(a => a.default).map(a => a.id));
        const fields = AI_APPS.filter(a => ids.has(a.id) && a.prompt && a.prompt in adv).map(a => a.prompt);
        const off = fields.filter(f => adv[f] !== true);
        if (!off.length) rec({ category: 'Prompt Capture', name: 'Gen AI prompt capture', action: 'NO_CHANGE', note: fields.join(', ') });
        else {
          if (!dryRun) { undo.push({ op: 'PUT', path: '/api/v1/advancedUrlFilterAndCloudAppSettings', body: adv, label: 'Prompt Capture' }); await client.apiCall('PUT', '/api/v1/advancedUrlFilterAndCloudAppSettings', { ...adv, ...Object.fromEntries(off.map(f => [f, true])) }); }
          rec({ category: 'Prompt Capture', name: 'Gen AI prompt capture', action: 'UPDATE', changes: off });
        }
      }
    } catch (e) { rec({ category: 'Prompt Capture', name: 'Gen AI prompt capture', action: 'FAILED', error: e.message }); }
  }

  // 8. forwarding rule: proxy-chain the AI apps to the gateway
  if (gateway && group) {
    try {
      const rules = list(await client.apiCall('GET', '/api/v1/forwardingRules'));
      const ex = rules.find(r => r.name === N.fwd);
      const want = { name: N.fwd, type: 'FORWARDING', forwardMethod: 'PROXYCHAIN', state: 'ENABLED', rank: 7, destIpGroups: [{ id: group.id, name: group.name }], proxyGateway: { id: gateway.id, name: gateway.name },
        description: 'Send AI apps to AI Guard. Created by the ZTP Policy Wizard.' };
      if (!ex) {
        if (!dryRun) { const c = await client.apiCall('POST', '/api/v1/forwardingRules', { ...want, order: 1 }); undo.push({ op: 'DELETE', path: `/api/v1/forwardingRules/${c.id}`, label: `Forwarding: ${N.fwd}` }); }
        rec({ category: 'Forwarding Control', name: N.fwd, action: 'CREATE', note: `Proxy Chaining → ${gateway.name}` });
      } else {
        const okR = ex.forwardMethod === 'PROXYCHAIN' && ex.state !== 'DISABLED' && ex.proxyGateway && String(ex.proxyGateway.id) === String(gateway.id) && (ex.destIpGroups || []).some(g => String(g.id) === String(group.id));
        if (okR) rec({ category: 'Forwarding Control', name: N.fwd, action: 'NO_CHANGE' });
        else {
          if (!dryRun) { undo.push({ op: 'PUT', path: `/api/v1/forwardingRules/${ex.id}`, body: ex, label: `Forwarding: ${N.fwd}` }); await client.apiCall('PUT', `/api/v1/forwardingRules/${ex.id}`, { ...ex, ...want, id: ex.id, order: ex.order }); }
          rec({ category: 'Forwarding Control', name: N.fwd, action: 'UPDATE', changes: ['forwardMethod / gateway / destination group'] });
        }
      }
    } catch (e) { rec({ category: 'Forwarding Control', name: N.fwd, action: 'FAILED', error: e.message }); }
  } else rec({ category: 'Forwarding Control', name: N.fwd, action: 'SKIPPED', error: gateway ? 'Needs the destination group.' : `Waiting for the proxy gateway "${N.gateway}" (manual step).` });

  // 9. ZIA allow for the sanctioned AI apps (so they reach AI Guard instead of being blocked, cautioned or isolated)
  await AP.ziaAllow({ client, input, dryRun, rec, undo, warnings, N, list, apps: AI_APPS });
  // 10. AI Guard: the compliance profile as a detection policy, matched to the picked apps' LLM providers
  if (input.compliance && input.compliance.profile !== 'NONE') {
    try { await aiguardCall(client, 'GET', '/aiguard/v1/detections/policies'); await AP.aiguardPolicy({ client, input, dryRun, rec, undo, warnings, N, aiguardCall }); }
    catch (e) { rec({ category: 'AI Guard Policy', name: N.policy, action: 'FAILED', error: `The AI Guard API is not reachable with this API client: ${e.message}` }); }
  } else rec({ category: 'AI Guard Policy', name: N.policy, action: 'SKIPPED', note: 'no compliance profile chosen' });

  followUps.push(input.compliance && input.compliance.profile !== 'NONE'
    ? `In the AI Guard portal: Tenant Settings › Security › Store Prompts/Responses on; Tenant Settings › Integrations › ZIA User and Group Sync and ZIA Domain Sync on. Review "${N.policy}" (Policy › Configurations) and "${N.policyRule}" (Policy › Controls).`
    : 'In the AI Guard portal: Tenant Settings › Security › Store Prompts/Responses on; Tenant Settings › Integrations › ZIA User and Group Sync and ZIA Domain Sync on; then add a detection policy and a policy control (Policy › Configurations, Policy › Controls).');
  if (input.includeCloudMicrosoft) warnings.push('All of .cloud.microsoft is sent through inspection and AI Guard. Microsoft asks for this domain to be allowed in full for Copilot; other Microsoft 365 apps also use it, so test Outlook and Teams after applying.');
  if (domains.some(d => /anthropic|claude/.test(d))) followUps.push('Claude Code on devices without the Zscaler root CA in the system store: set NODE_EXTRA_CA_CERTS to the Zscaler root certificate in ~/.claude/settings.json (env), or use the native installer.');

  const activated = !dryRun && ledger.some(r => r.action === 'CREATE' || r.action === 'UPDATE') ? await client.apiCall('POST', '/api/v1/status/activate').then(() => true, () => false) : null;
  return { ledger, warnings, followUps, undo, activated, gatewayMissing: !gateway, names: N, domains };
}

module.exports = { aiguardCall, AI_APPS, CLOUD_MICROSOFT, AI_GUARD_PROXY, AIG_HOST, GENAI_SKUS, names, domainsFor, validate, context, runAiGuard };
