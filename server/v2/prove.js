/**
 * v2.6: "Prove it" for every kind of web test: what ZIA would do with a destination, by policy type.
 *   url       → URL lookup categories → first enabled URL Filtering rule that covers them
 *   threat    → the same lookup, highlighting security-alert categories, plus the ATP / malware switches that apply
 *   cloudApp  → first enabled Cloud App Control rule for the app (its type and actions)
 *   firewall  → first enabled Firewall Filtering rule for a destination IP / host, port and protocol
 *   dns       → first enabled DNS Control rule for a domain (its categories) or a DoH request
 * The engines are simplified on purpose: users, groups, departments, locations and time windows are not evaluated,
 * and a rule scoped to them is reported with a note. The exact transaction is in the ZIA portal's Insights logs
 * (API clients cannot read per-transaction logs).
 * Built-in destinations are safe, well-known test targets; anyone can type their own.
 */
'use strict';
const net = require('net');
const list = (r) => (Array.isArray(r) ? r : (r && (r.list || r.items)) || []);

const CATALOG = {
  url: {
    label: 'URL filtering', hint: 'A site in a category the POV blocks, cautions or isolates.',
    items: [
      { label: 'Gambling (bet365.com)', target: 'https://www.bet365.com/' },
      { label: 'Hacking (hackthissite.org)', target: 'https://www.hackthissite.org/' },
      { label: 'Peer-to-peer (thepiratebay.org)', target: 'https://thepiratebay.org/' },
      { label: 'Anonymizer / proxy (hide.me)', target: 'https://hide.me/en/proxy' },
      { label: 'Streaming media (netflix.com)', target: 'https://www.netflix.com/' },
      { label: 'Social networking (facebook.com)', target: 'https://www.facebook.com/' },
      { label: 'Online shopping (amazon.com)', target: 'https://www.amazon.com/' },
      { label: 'Games (store.steampowered.com)', target: 'https://store.steampowered.com/' },
      { label: 'AI & ML apps (chatgpt.com)', target: 'https://chatgpt.com/' },
      { label: 'Web mail (mail.google.com)', target: 'https://mail.google.com/' },
      { label: 'File sharing (wetransfer.com)', target: 'https://wetransfer.com/' },
      { label: 'Finance, usually SSL-exempt (chase.com)', target: 'https://www.chase.com/' },
      { label: 'Health, usually SSL-exempt (mayoclinic.org)', target: 'https://www.mayoclinic.org/' }
    ]
  },
  threat: {
    label: 'Threat protection (ATP, malware, sandbox)', hint: 'Safe, industry-standard test pages and files (EICAR, AMTSO).',
    items: [
      { label: 'EICAR test file (eicar.com)', target: 'https://secure.eicar.org/eicar.com' },
      { label: 'EICAR as text (eicar.com.txt)', target: 'https://secure.eicar.org/eicar.com.txt' },
      { label: 'EICAR in a zip (eicar_com.zip)', target: 'https://secure.eicar.org/eicar_com.zip' },
      { label: 'EICAR in a zip in a zip (eicar_com2.zip)', target: 'https://secure.eicar.org/eicar_com2.zip' },
      { label: 'AMTSO: malware download', target: 'https://www.amtso.org/feature-settings-check-download-of-malware/' },
      { label: 'AMTSO: compressed malware', target: 'https://www.amtso.org/feature-settings-check-download-of-compressed-malware/' },
      { label: 'AMTSO: drive-by download', target: 'https://www.amtso.org/feature-settings-check-drive-by-download-test/' },
      { label: 'AMTSO: potentially unwanted application', target: 'https://www.amtso.org/feature-settings-check-potentially-unwanted-applications/' },
      { label: 'AMTSO: phishing page', target: 'https://www.amtso.org/feature-settings-check-phishing-page/' },
      { label: 'AMTSO: cloud lookup', target: 'https://www.amtso.org/feature-settings-check-cloud-lookups/' }
    ]
  },
  cloudApp: {
    label: 'Cloud apps (web apps)', hint: 'An app the POV allows, limits (view-only, no upload) or blocks.',
    items: [
      { label: 'ChatGPT', target: 'CHATGPT_AI', type: 'AI_ML' },
      { label: 'Claude', target: 'CLAUDE_AI', type: 'AI_ML' },
      { label: 'Google Gemini', target: 'GOOGLE_GEMINI', type: 'AI_ML' },
      { label: 'Microsoft Copilot', target: 'MICROSOFT_COPILOT', type: 'AI_ML' },
      { label: 'Google Drive', target: 'GDRIVE', type: 'FILE_SHARE' },
      { label: 'Dropbox', target: 'DROPBOX', type: 'FILE_SHARE' },
      { label: 'Box', target: 'BOXNET', type: 'FILE_SHARE' },
      { label: 'OneDrive', target: 'ONEDRIVE', type: 'FILE_SHARE' },
      { label: 'WeTransfer', target: 'WETRANSFER', type: 'FILE_SHARE' },
      { label: 'Facebook', target: 'FACEBOOK', type: 'SOCIAL_NETWORKING' },
      { label: 'LinkedIn', target: 'LINKEDIN', type: 'SOCIAL_NETWORKING' },
      { label: 'X (Twitter)', target: 'TWITTER', type: 'SOCIAL_NETWORKING' },
      { label: 'Gmail', target: 'GOOGLE_WEBMAIL', type: 'WEBMAIL' },
      { label: 'Slack', target: 'SLACK', type: 'ENTERPRISE_COLLABORATION' },
      { label: 'Microsoft Teams', target: 'MSTEAM', type: 'ENTERPRISE_COLLABORATION' },
      { label: 'GitHub', target: 'GITHUB', type: 'SYSTEM_AND_DEVELOPMENT' }
    ]
  },
  firewall: {
    label: 'Firewall', hint: 'Non-web traffic: a destination, a port and a protocol.',
    items: [
      { label: 'SSH to a server in China (202.108.22.5:22)', target: '202.108.22.5:22/tcp' },
      { label: 'RDP to the internet (portquiz.net:3389)', target: 'portquiz.net:3389/tcp' },
      { label: 'Telnet (towel.blinkenlights.nl:23)', target: 'towel.blinkenlights.nl:23/tcp' },
      { label: 'FTP (ftp.gnu.org:21)', target: 'ftp.gnu.org:21/tcp' },
      { label: 'SMB to the internet (portquiz.net:445)', target: 'portquiz.net:445/tcp' },
      { label: 'QUIC / HTTP3 (www.youtube.com:443 UDP)', target: 'www.youtube.com:443/udp' },
      { label: 'DNS over TLS (1.1.1.1:853)', target: '1.1.1.1:853/tcp' },
      { label: 'Outbound DNS to 8.8.8.8:53', target: '8.8.8.8:53/udp' },
      { label: 'Any port test (portquiz.net:8080)', target: 'portquiz.net:8080/tcp' }
    ]
  },
  dns: {
    label: 'DNS control', hint: 'A domain lookup (or DNS over HTTPS) the POV blocks or redirects.',
    items: [
      { label: 'DNS over HTTPS: cloudflare-dns.com', target: 'cloudflare-dns.com', doh: true },
      { label: 'DNS over HTTPS: dns.google', target: 'dns.google', doh: true },
      { label: 'Gambling domain (bet365.com)', target: 'bet365.com' },
      { label: 'Peer-to-peer domain (thepiratebay.org)', target: 'thepiratebay.org' },
      { label: 'Hacking domain (hackthissite.org)', target: 'hackthissite.org' },
      { label: 'Anonymizer domain (hide.me)', target: 'hide.me' },
      { label: 'Ordinary domain (zscaler.com)', target: 'www.zscaler.com' }
    ]
  }
};

const scopedNote = (r) => ((r.users || []).length || (r.groups || []).length || (r.departments || []).length || (r.locations || []).length || (r.locationGroups || []).length || (r.timeWindows || []).length)
  ? 'This rule only applies to certain users, groups, departments, locations or times; for everyone else the next matching rule applies.' : null;
const ruleOut = (r, extra = {}) => ({ name: r.name, order: r.order, action: r.action || (r.actions || []).join(', '), predefined: !!r.predefined, note: scopedNote(r), ...extra });
// Default rules (negative order on ZIA, e.g. -1, -3) are evaluated last, after every ordered rule
const byOrder = (a, b) => (!!a.defaultRule - !!b.defaultRule) || ((a.order || 0) - (b.order || 0));
const host = (t) => { try { return new URL(/^[a-z]+:\/\//i.test(t) ? t : `https://${t}`).hostname; } catch (e) { return null; } };

async function lookup(client, h) {
  const l = list(await client.apiCall('POST', '/api/v1/urlLookup', [h]))[0] || {};
  return { categories: [...(l.urlClassifications || [])], alerts: [...(l.urlClassificationsWithSecurityAlert || [])] };
}

async function proveUrl(client, target) {
  const h = host(target);
  if (!h) throw Object.assign(new Error('Enter a URL or domain, for example https://www.example.com'), { status: 400 });
  const { categories, alerts } = await lookup(client, h);
  const cats = [...categories, ...alerts];
  const rules = list(await client.apiCall('GET', '/api/v1/urlFilteringRules')).filter(r => r.state !== 'DISABLED').sort(byOrder);
  const hits = [];
  for (const r of rules) {
    const rc = r.urlCategories || [];
    if (!rc.length || rc.includes('ANY') || rc.some(c => cats.includes(c))) { hits.push(ruleOut(r)); if (!scopedNote(r)) break; }
  }
  return { type: 'url', target: h, categories, securityAlerts: alerts, match: hits[0] || null, alsoChecked: hits.slice(1),
    verdict: hits.length ? `${hits[0].action} by "${hits[0].name}"` : 'No URL Filtering rule matches; the default (allow) applies.' };
}

async function proveThreat(client, target) {
  const u = await proveUrl(client, target);
  let atp = null;
  try {
    const s = await client.apiCall('GET', '/api/v1/cyberThreatProtection/advancedThreatSettings');
    const keys = ['malwareSitesBlocked', 'phishingBlocked', 'cryptominingBlocked', 'knownPhishingSitesBlocked', 'suspectPhishingSitesBlocked', 'malicious_urls_capture', 'riskTolerance', 'adSpywareSitesBlocked'];
    atp = Object.fromEntries(Object.entries(s || {}).filter(([k]) => keys.includes(k) || /Blocked$/.test(k)).slice(0, 14));
  } catch (e) { atp = null; }
  let sandbox = [];
  try { sandbox = list(await client.apiCall('GET', '/api/v1/sandboxRules')).filter(r => r.state !== 'DISABLED').sort(byOrder).slice(0, 4).map(r => ruleOut(r, { ba: r.baRuleAction, firstTime: r.firstTimeEnable ? r.firstTimeOperation : null })); } catch (e) { /* not licensed */ }
  const file = /\.(com|txt|zip|exe|pdf|docx?|xlsx?)$/i.test(target.split('?')[0]);
  return { ...u, type: 'threat', atp, sandbox,
    verdict: u.securityAlerts.length ? `Security-alert category (${u.securityAlerts.join(', ')}); Advanced Threat Protection blocks it when that class is on.`
      : file ? 'A download: malware protection (antivirus) scans it; EICAR is blocked as a virus, and unknown files go to the Cloud Sandbox rules below.' : u.verdict };
}

async function proveCloudApp(client, target, type) {
  const app = String(target || '').trim().toUpperCase();
  if (!/^[A-Z0-9_]+$/.test(app)) throw Object.assign(new Error('Pick an app (or type its ZIA app name, for example CHATGPT_AI).'), { status: 400 });
  let t = type;
  if (!t) { const hit = list(await client.apiCall('GET', `/api/v1/cloudApplications/policy?search=${encodeURIComponent(app.toLowerCase().replace(/_/g, ' '))}`)).find(a => a.app === app); t = hit && hit.parent; }
  if (!t) throw Object.assign(new Error(`ZIA does not know the app ${app}.`), { status: 400 });
  const rules = list(await client.apiCall('GET', `/api/v1/webApplicationRules/${t}`)).filter(r => r.state !== 'DISABLED').sort(byOrder);
  const hits = rules.filter(r => !(r.applications || []).length || (r.applications || []).includes(app)).map(r => ruleOut(r, { actions: r.actions || [], allApps: !(r.applications || []).length }));
  const first = hits[0];
  return { type: 'cloudApp', target: app, appType: t, match: first || null, alsoChecked: hits.slice(1, 4),
    verdict: first ? `"${first.name}": ${first.actions.join(', ')}${first.allApps ? ' (all apps of this type)' : ''}` : 'No Cloud App Control rule covers this app; URL Filtering decides.' };
}

function parseFw(target) {
  const m = String(target || '').trim().match(/^(\[?[^\]\s]+?\]?)(?::(\d{1,5}))?(?:\/(tcp|udp))?$/i);
  if (!m) return null;
  return { dest: m[1].replace(/^\[|\]$/g, ''), port: m[2] ? Number(m[2]) : null, proto: (m[3] || 'tcp').toUpperCase() };
}
const portIn = (port, ranges) => (ranges || []).some(r => { const s = Number(r.start), e = Number(r.end || r.start); return port >= s && port <= e; });
const APP_PORTS = { SSH: [22], RDP: [3389], FTP: [20, 21], TELNET: [23], SMB: [445, 139], VNC: [5900], DNS: [53], HTTP: [80], HTTPS: [443], QUIC: [443] };

async function proveFirewall(client, target) {
  const f = parseFw(target);
  if (!f || !f.port) throw Object.assign(new Error('Enter a destination and port, for example 203.0.113.10:22/tcp or rdp.example.net:3389'), { status: 400 });
  const rules = list(await client.apiCall('GET', '/api/v1/firewallFilteringRules')).filter(r => r.state !== 'DISABLED').sort(byOrder);
  let services = [];
  try { services = list(await client.apiCall('GET', '/api/v1/networkServices')); } catch (e) { /* names only */ }
  const svcById = new Map(services.map(s => [String(s.id), s]));
  const svcMatches = (ref) => {
    const s = svcById.get(String(ref.id)) || services.find(x => x.name === ref.name);
    if (!s) return null;   // unknown: can't tell
    if (f.proto === 'UDP') return portIn(f.port, s.destUdpPorts) || (s.name === 'QUIC' && f.port === 443);
    return portIn(f.port, s.destTcpPorts);
  };
  const isIp = net.isIP(f.dest) > 0;
  const hits = [];
  for (const r of rules) {
    const svcs = r.nwServices || [], apps = r.nwApplications || [];
    const svcOk = !svcs.length || svcs.some(sv => svcMatches(sv) !== false);
    const appOk = !apps.length || apps.some(a => (APP_PORTS[String(a).toUpperCase()] || []).includes(f.port));
    const addr = r.destAddresses || [];
    const addrOk = !addr.length || (isIp ? addr.includes(f.dest) : addr.some(a => String(a).toLowerCase() === f.dest.toLowerCase()));
    if (!(svcOk && appOk && addrOk)) continue;
    const conds = [];
    if ((r.destCountries || []).length) conds.push(`only if the destination is in ${(r.destCountries || []).map(c => String(c).replace('COUNTRY_', '')).join(', ')}`);
    if ((r.destIpCategories || []).length) conds.push(`only if the destination is in ${(r.destIpCategories || []).join(', ')}`);
    if ((r.sourceCountries || []).length) conds.push(`only from ${(r.sourceCountries || []).map(c => String(c).replace('COUNTRY_', '')).join(', ')}`);
    hits.push(ruleOut(r, { conditions: conds }));
    if (!conds.length && !scopedNote(r)) break;
  }
  const first = hits[0];
  return { type: 'firewall', target: `${f.dest}:${f.port}/${f.proto.toLowerCase()}`, match: first || null, alsoChecked: hits.slice(1, 4),
    verdict: first ? `${first.action} by "${first.name}"${first.conditions.length ? ` (${first.conditions.join('; ')})` : ''}` : 'No Firewall rule matches; the default firewall rule applies.' };
}

async function proveDns(client, target, doh) {
  const h = host(target);
  if (!h) throw Object.assign(new Error('Enter a domain, for example example.com'), { status: 400 });
  const { categories, alerts } = await lookup(client, h);
  const cats = [...categories, ...alerts];
  const rules = list(await client.apiCall('GET', '/api/v1/firewallDnsRules')).filter(r => r.state !== 'DISABLED').sort(byOrder);
  const hits = [];
  for (const r of rules) {
    // ZPA resolver rules (REDIR_ZPA) only match the domains of ZPA application segments
    if (r.action === 'REDIR_ZPA' || r.zpaIpGroup) continue;
    const protos = r.protocols || [];
    if (protos.length && !protos.includes('ANY_RULE') && !(doh ? protos.includes('DOHTTPS_RULE') : protos.some(p => p !== 'DOHTTPS_RULE'))) continue;
    const rc = [...(r.destIpCategories || []), ...(r.resCategories || [])];
    if (rc.length && !rc.some(c => cats.includes(c))) continue;
    // rules aimed at particular DNS applications (tunnels, DoH providers) only catch a DoH lookup when they cover DoH
    if ((r.applications || []).length && !(doh && protos.includes('DOHTTPS_RULE'))) continue;
    hits.push(ruleOut(r, { redirect: r.dnsGateway ? r.dnsGateway.name : (r.redirectIp || null) }));
    if (!scopedNote(r)) break;
  }
  const first = hits[0];
  // DoH: whether DNS over HTTPS may be used at all is a Cloud App Control decision (type DNS_OVER_HTTPS)
  let dohApp = null;
  if (doh) {
    try {
      const car = list(await client.apiCall('GET', '/api/v1/webApplicationRules/DNS_OVER_HTTPS')).filter(r => r.state !== 'DISABLED').sort(byOrder)[0];
      if (car) dohApp = ruleOut(car, { actions: car.actions || [] });
    } catch (e) { /* not available */ }
  }
  const dnsWords = first ? `${first.action}${first.redirect ? ` to ${first.redirect}` : ''} by "${first.name}"` : 'no DNS Control rule matches this domain (default DNS rule)';
  const verdict = doh
    ? (dohApp ? `DNS over HTTPS: ${dohApp.actions.join(', ')} by "${dohApp.name}" (Cloud App Control); lookups over DoH: ${dnsWords}.` : `DNS over HTTPS is not restricted by Cloud App Control; lookups over DoH: ${dnsWords}.`)
    : (first ? dnsWords : 'No DNS Control rule matches; the default DNS rule applies.');
  return { type: 'dns', target: h, doh: !!doh, categories, securityAlerts: alerts, match: first || dohApp || null, dohApp, alsoChecked: hits.slice(1, 4), verdict };
}

async function proveOne(client, { type, target, appType, doh }) {
  const t = type || 'url';
  if (!String(target || '').trim()) throw Object.assign(new Error('Pick a destination or type one.'), { status: 400 });
  if (t === 'url') return proveUrl(client, target);
  if (t === 'threat') return proveThreat(client, target);
  if (t === 'cloudApp') return proveCloudApp(client, target, appType);
  if (t === 'firewall') return proveFirewall(client, target);
  if (t === 'dns') return proveDns(client, target, doh);
  throw Object.assign(new Error(`Unknown Prove it type ${t}.`), { status: 400 });
}

/**
 * v2.8: the "why" behind a verdict. The path a web request takes, in order: does Client Connector or a PAC file send it
 * around ZIA, is it decrypted (and does the SSL rule skip the other policies), then which rule decides. Each step names the
 * rule or setting. With an expected result, the verdict says whether the configuration agrees.
 * facts: from coverage.readFacts (cached by the caller); missing facts make that step "not checked", never a guess.
 */
const EXPECT = { BLOCK: /BLOCK|DENY/, ALLOW: /^ALLOW|ALLOW_/, CAUTION: /CAUTION/, ISOLATE: /ISOLATE/ };
function agreement(expect, result, trace) {
  if (!expect || expect === 'ANY') return null;
  const around = trace.some(s => s.step === 'forwarding' && s.bypass);
  if (expect === 'INSPECTED' || expect === 'NOT_INSPECTED') {
    const ssl = trace.find(s => s.step === 'ssl');
    if (!ssl || ssl.inspected === null || ssl.inspected === undefined) return null;
    return around ? false : (expect === 'INSPECTED') === !!ssl.inspected;
  }
  if (around) return false;
  const m = result.type === 'dns' && result.doh && result.dohApp ? result.dohApp : result.match;
  if (!m) return expect === 'ALLOW' ? true : false;
  if (m.note) return null;   // scoped rule: depends on the user
  const act = String(m.action || (m.actions || []).join(',')).toUpperCase();
  return EXPECT[expect] ? EXPECT[expect].test(act) : null;
}
async function prove(client, args, { facts = null } = {}) {
  const r = await proveOne(client, args);
  const trace = [];
  const cov = require('./coverage');
  const h = (r.type === 'url' || r.type === 'threat' || r.type === 'dns') ? r.target : null;
  if (h && facts) {
    const by = cov.hostBypass(facts, h);
    trace.push({ step: 'forwarding', bypass: by.length > 0, text: by.length ? `Goes around ZIA: ${by.map(b => `${b.where} ${b.what}`).join(' ')}` : `Reaches ZIA: no Client Connector bypass${(facts.pac || []).length ? ' or PAC DIRECT rule' : ''} matches ${h}.${facts.zcc ? '' : ' (Client Connector bypasses not checked: not connected.)'}` });
  }
  if ((r.type === 'url' || r.type === 'threat') && facts && facts.ssl) {
    const d = cov.sslDecision(facts, [...(r.categories || []), ...(r.securityAlerts || [])]);
    if (d) trace.push({ step: 'ssl', inspected: d.inspected, text: `${d.inspected ? 'Decrypted' : 'Not decrypted'} by ${d.isDefault ? 'the default SSL rule' : `"${d.rule}" (order ${d.order})`}${!d.inspected && d.bypassOtherPolicies ? '; this rule also skips the other policies, so URL filtering and Cloud App Control do not apply' : !d.inspected ? '; URL filtering by domain still applies, content checks (DLP, file type, sandbox) do not' : ''}.${d.scopedAbove.length ? ` ${d.scopedAbove.length} rule(s) above apply only to some users or locations.` : ''}` });
  }
  trace.push({ step: 'policy', text: r.verdict });
  const agrees = agreement(args.expect, r, trace);
  return { ...r, trace, expect: args.expect || null, agrees,
    agreement: agrees === null ? (args.expect && args.expect !== 'ANY' ? 'Cannot tell from configuration alone (a scoped rule or an unread setting decides); run the test.' : null)
      : agrees ? `Agrees with the expected result (${String(args.expect).toLowerCase().replace(/_/g, ' ')}).` : `Does not agree with the expected result (${String(args.expect).toLowerCase().replace(/_/g, ' ')}); see the steps above for where it changes.` };
}

module.exports = { CATALOG, prove, parseFw, agreement };
