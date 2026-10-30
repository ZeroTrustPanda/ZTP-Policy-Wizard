/**
 * v2.8: what ZIA cannot see. SSL inspection exemptions, Client Connector bypasses (DNS / IP exclusions, VPN gateways) and
 * PAC files that send traffic DIRECT. Used by the SSL and bypass coverage panel and by the "why" trace behind Prove it.
 * The approach (list every cause of uninspected traffic, never guess, keep unrecognised things out of any conclusion) follows
 * Zscaler Made Easy; see About.
 *
 * All reads; nothing is written. PAC files are never run: a small reader finds `if (…) return "DIRECT"` statements at the top
 * level of FindProxyForURL whose conditions are plain host tests (dnsDomainIs, shExpMatch, host ==, localHostOrDomainIs).
 * Anything else is reported as "not evaluated", never as a bypass.
 */
'use strict';
const { readProfileLists } = require('../zcc-templates');

const list = (r) => (Array.isArray(r) ? r : (r && (r.list || r.items)) || []);
const glob = (pat, s) => new RegExp('^' + String(pat).replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$', 'i').test(s);

// ---------- PAC ----------
/** Top-level `if (cond) return "DIRECT"` statements of a PAC file: [{ cond, terms:[{fn, arg}], certain }]. */
function pacDirectRules(src) {
  const text = String(src || '').replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])\/\/.*$/gm, '$1');
  const start = text.search(/function\s+FindProxyForURL\s*\(/);
  if (start < 0) return { rules: [], parsed: false };
  const body = text.slice(text.indexOf('{', start) + 1);
  const rules = [];
  let depth = 0;
  for (let i = 0; i < body.length; i++) {
    const ch = body[i];
    if (ch === '{') { depth++; continue; }
    if (ch === '}') { if (depth === 0) break; depth--; continue; }
    if (depth !== 0 || !/\bif\b/.test(body.slice(i, i + 3)) || /\w/.test(body[i - 1] || '')) continue;
    // condition in balanced parentheses
    let j = body.indexOf('(', i); if (j < 0) break;
    let d = 0, k = j;
    for (; k < body.length; k++) { if (body[k] === '(') d++; else if (body[k] === ')') { d--; if (!d) break; } }
    const cond = body.slice(j + 1, k);
    const after = body.slice(k + 1, k + 80);
    const m = after.match(/^\s*\{?\s*return\s+["']DIRECT["']\s*;?\s*\}?/);
    i = k;
    if (!m) continue;
    const certain = !/&&|!(?!=)/.test(cond);
    const terms = [];
    for (const part of cond.split('||')) {
      const t = part.trim();
      let mm;
      if ((mm = t.match(/^dnsDomainIs\s*\(\s*host\s*,\s*["']([^"']+)["']\s*\)$/))) terms.push({ fn: 'dnsDomainIs', arg: mm[1] });
      else if ((mm = t.match(/^localHostOrDomainIs\s*\(\s*host\s*,\s*["']([^"']+)["']\s*\)$/))) terms.push({ fn: 'localHostOrDomainIs', arg: mm[1] });
      else if ((mm = t.match(/^shExpMatch\s*\(\s*(host|url)\s*,\s*["']([^"']+)["']\s*\)$/))) terms.push({ fn: `shExpMatch:${mm[1]}`, arg: mm[2] });
      else if ((mm = t.match(/^host\s*===?\s*["']([^"']+)["']$/))) terms.push({ fn: 'equals', arg: mm[1] });
      else terms.push({ fn: 'unknown', arg: t.slice(0, 80) });
    }
    rules.push({ cond: cond.replace(/\s+/g, ' ').slice(0, 200), terms, certain });
  }
  return { rules, parsed: true };
}
function termMatches(term, host) {
  const h = host.toLowerCase();
  if (term.fn === 'dnsDomainIs') { const a = term.arg.toLowerCase(); return h === a.replace(/^\./, '') || h.endsWith(a.startsWith('.') ? a : `.${a}`) || h === a; }
  if (term.fn === 'localHostOrDomainIs' || term.fn === 'equals') return h === term.arg.toLowerCase();
  if (term.fn === 'shExpMatch:host') return glob(term.arg, h);
  if (term.fn === 'shExpMatch:url') return glob(term.arg, `https://${h}/`) || glob(term.arg, `http://${h}/`);
  return null;   // unknown: can't tell
}
/** Does this PAC certainly send `host` DIRECT? Returns the rule or null. */
function pacSendsDirect(pac, host) {
  for (const r of pac.rules) {
    if (!r.certain) continue;
    if (r.terms.some(t => termMatches(t, host) === true)) return r;
  }
  return null;
}

// ---------- Client Connector lists ----------
function inDomainList(entries, host) {
  const h = host.toLowerCase();
  return (entries || []).find(e => { const x = String(e).trim().toLowerCase(); if (!x || x === '*') return false; return x.startsWith('*.') ? (h.endsWith(x.slice(1)) || h === x.slice(2)) : h === x; }) || null;
}

/** Everything the panel and the trace need, read once. zcc may be null (Client Connector not connected). */
async function readFacts(zia, zcc) {
  const facts = { ssl: null, pac: [], zcc: null, notes: [], refused: [] };
  try {
    const rules = list(await zia.apiCall('GET', '/api/v1/sslInspectionRules'));
    facts.ssl = rules.map(r => ({ id: r.id, name: r.name, order: r.order, state: r.state, defaultRule: !!r.defaultRule, predefined: !!r.predefined,
      type: (r.action && r.action.type) || '', bypassOtherPolicies: !!(r.action && r.action.doNotDecryptSubActions && r.action.doNotDecryptSubActions.bypassOtherPolicies),
      urlCategories: r.urlCategories || [], cloudApplications: r.cloudApplications || [],
      scoped: ['users', 'groups', 'departments', 'locations', 'locationGroups', 'devices', 'deviceGroups', 'platforms', 'sourceIpGroups', 'destIpGroups'].some(k => (r[k] || []).length) }));
  } catch (e) { facts.refused.push(`SSL Inspection rules: ${e.message.slice(0, 120)}`); }
  try {
    for (const p of list(await zia.apiCall('GET', '/api/v1/pacFiles'))) {
      const parsed = pacDirectRules(p.pacContent);
      facts.pac.push({ id: p.id, name: p.name, url: p.pacUrl || '', subUrl: p.pacSubURL || '', parsed: parsed.parsed, direct: parsed.rules });
    }
  } catch (e) { facts.refused.push(`PAC files: ${e.message.slice(0, 120)}`); }
  if (zcc) {
    try {
      const profiles = [];
      for (const dt of [3, 4]) {
        for (const p of list(await zcc.getAppProfiles(dt).catch(() => []))) {
          const lists = readProfileLists(p) || {};
          profiles.push({ name: p.name, platform: dt === 3 ? 'Windows' : 'macOS', active: String(p.active) === '1' || p.active === true, pacUrl: p.pac_url || '',
            dnsExclusions: lists.dnsExclusions || [], ipExclusions: lists.ipExclusions || [], vpnGateways: lists.vpnGateways || [] });
        }
      }
      facts.zcc = profiles;
    } catch (e) { facts.refused.push(`Client Connector app profiles: ${e.message.slice(0, 120)}`); }
  } else facts.notes.push('Client Connector is not connected in this session, so its bypasses are not included.');
  return facts;
}

/** First SSL rule that decides a host in these categories (scoped rules are skipped and noted). */
function sslDecision(facts, categories) {
  if (!facts.ssl) return null;
  const cats = new Set(categories || []);
  const rules = facts.ssl.filter(r => r.state !== 'DISABLED' && !r.defaultRule).sort((a, b) => a.order - b.order);
  const scopedAbove = [];
  for (const r of rules) {
    if (r.cloudApplications.length && !r.urlCategories.length) continue;   // app-based rules: the host-to-app mapping is not known here
    const anyCat = !r.urlCategories.length || r.urlCategories.includes('ANY');
    if (!anyCat && !r.urlCategories.some(c => cats.has(c))) continue;
    if (r.scoped) { scopedAbove.push(r.name); continue; }
    return { rule: r.name, order: r.order, inspected: r.type === 'DECRYPT', bypassOtherPolicies: r.bypassOtherPolicies, predefined: r.predefined, scopedAbove };
  }
  const def = facts.ssl.find(r => r.defaultRule);
  return def ? { rule: def.name, order: null, inspected: def.type === 'DECRYPT', bypassOtherPolicies: def.bypassOtherPolicies, isDefault: true, scopedAbove } : null;
}

/** Does Client Connector or a PAC file send this host around ZIA? Certain matches only. */
function hostBypass(facts, host) {
  const out = [];
  for (const p of facts.zcc || []) {
    if (!p.active) continue;
    const d = inDomainList(p.dnsExclusions, host);
    if (d) out.push({ where: `Client Connector app profile "${p.name}" (${p.platform})`, what: `DNS exclusion ${d}: the tunnel does not carry this domain (Z-Tunnel 2.0).` });
    const v = inDomainList(p.vpnGateways, host);
    if (v) out.push({ where: `Client Connector app profile "${p.name}" (${p.platform})`, what: `VPN gateway bypass ${v}.` });
  }
  for (const pac of facts.pac) {
    const r = pacSendsDirect({ rules: pac.direct || [] }, host);
    if (r) out.push({ where: `PAC file "${pac.name}"`, what: `returns DIRECT for this host (${r.cond.slice(0, 100)}), so browsers using this PAC go around ZIA.` });
  }
  return out;
}

/** The coverage panel: every cause of traffic ZIA does not inspect, biggest first. */
function summarize(facts) {
  const items = [];
  const ssl = facts.ssl || [];
  const active = ssl.filter(r => r.state !== 'DISABLED');
  const def = ssl.find(r => r.defaultRule);
  const catchAll = active.find(r => !r.defaultRule && r.type === 'DECRYPT' && !r.scoped && (!r.urlCategories.length || r.urlCategories.includes('ANY')) && !r.cloudApplications.length);
  if (facts.ssl) {
    if (!catchAll && def && def.type !== 'DECRYPT') items.push({ severity: 'high', area: 'SSL Inspection', title: 'Nothing is inspected by default',
      found: `The default SSL rule is "${def.type.replace(/_/g, ' ').toLowerCase()}" and no rule inspects all remaining traffic.`,
      means: 'Traffic that no rule names is not decrypted, so URL paths, file types, sandbox, DLP and most threat checks cannot see it.',
      do: 'Add an "inspect everything else" rule at the bottom (the wizard\'s SSL Inspection catch-all does this).', outcome: 'Every test that depends on content (DLP, sandbox, file type, malware in HTTPS) can pass.' });
    for (const r of active.filter(x => !x.defaultRule && x.type === 'DO_NOT_DECRYPT')) {
      const anyCat = !r.urlCategories.length || r.urlCategories.includes('ANY');
      items.push({ severity: anyCat && !r.cloudApplications.length && !r.scoped ? 'high' : r.bypassOtherPolicies ? 'medium' : 'info', area: 'SSL Inspection', title: `Not inspected: ${r.name}`,
        found: `${r.predefined ? 'Zscaler-managed rule' : 'Rule'} at order ${r.order} does not decrypt ${anyCat && !r.cloudApplications.length ? 'any traffic it matches (no categories set)' : `${r.urlCategories.length ? `${r.urlCategories.length} categor${r.urlCategories.length === 1 ? 'y' : 'ies'}` : ''}${r.urlCategories.length && r.cloudApplications.length ? ' and ' : ''}${r.cloudApplications.length ? `${r.cloudApplications.length} app(s)` : ''}`}${r.scoped ? ' for some users or locations' : ''}.`,
        means: r.bypassOtherPolicies ? 'It also bypasses the other policies (URL filtering, Cloud App Control and so on) for that traffic.' : 'Content inspection (DLP, sandbox, file type) cannot see that traffic; URL filtering by domain still applies.',
        do: r.predefined ? 'Usually keep it (privacy and certificate-pinned apps); make sure POV test sites are not in these categories.' : 'Check the categories are intended exemptions (health, finance, privacy); keep test sites out of them.',
        outcome: 'Tests aimed at these categories will show "not inspected" by design.' });
    }
  }
  for (const p of (facts.zcc || []).filter(x => x.active)) {
    const n = p.dnsExclusions.filter(x => x && x !== '*').length + p.ipExclusions.filter(x => x && x !== '0.0.0.0/0').length + p.vpnGateways.length;
    if (!n) continue;
    items.push({ severity: 'medium', area: 'Client Connector', title: `Bypassed by app profile "${p.name}" (${p.platform})`,
      found: `${p.dnsExclusions.length} DNS exclusion(s), ${p.ipExclusions.length} IP exclusion(s) and ${p.vpnGateways.length} VPN gateway bypass(es)${p.dnsExclusions.length ? `, for example ${p.dnsExclusions.slice(0, 3).join(', ')}` : ''}.`,
      means: 'Traffic to these destinations leaves the device without going through ZIA, so no ZIA policy applies to it.',
      do: 'Keep the list to what must go direct (VPN head-ends, local resources); remove broad wildcards before testing.', outcome: 'POV tests aimed at these destinations will not reach ZIA.' });
  }
  for (const pac of facts.pac) {
    const certain = pac.direct.filter(r => r.certain);
    if (!certain.length) continue;
    const hosts = certain.flatMap(r => r.terms.filter(t => t.fn !== 'unknown').map(t => t.arg)).slice(0, 5);
    items.push({ severity: 'info', area: 'PAC file', title: `Sent DIRECT by PAC "${pac.name}"`,
      found: `${certain.length} rule(s) return DIRECT${hosts.length ? `, for example ${hosts.join(', ')}` : ''}.${pac.direct.length > certain.length ? ` ${pac.direct.length - certain.length} more DIRECT rule(s) have conditions this check does not evaluate.` : ''}`,
      means: 'Browsers and apps that use this PAC file connect to those destinations directly, around ZIA.', do: 'Confirm each DIRECT entry is intended (internal names, the ZIA PAC host itself).', outcome: 'Fewer surprises when a test destination is in the list.' });
  }
  const rank = { high: 0, medium: 1, info: 2 };
  items.sort((a, b) => rank[a.severity] - rank[b.severity]);
  return { items, notes: facts.notes, refused: facts.refused,
    headline: !facts.ssl ? 'SSL Inspection rules could not be read.' : catchAll ? `Inspected by default (rule "${catchAll.name}"), with ${items.filter(i => i.area === 'SSL Inspection').length} exemption(s).` : (def && def.type === 'DECRYPT') ? 'Inspected by default (the default rule decrypts).' : 'Not inspected by default: only traffic a rule names is decrypted.',
    volumeNote: 'This shows configuration, not traffic volume. The share of traffic actually inspected is in the ZIA portal (Analytics › Web Insights, SSL).' };
}

module.exports = { pacDirectRules, pacSendsDirect, readFacts, sslDecision, hostBypass, summarize, inDomainList };
