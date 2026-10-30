/**
 * v2.8: POV posture score. A short, read-only check of the areas a POV touches (SSL, threat, URL, firewall, DNS, file type,
 * DLP, cloud and AI apps, advanced settings, Client Connector), taken at the start of the POV and again at the end, so the
 * readout can show what the POV changed.
 *
 * Scoring follows Jason Smith's assessment model in Zscaler Made Easy (see About):
 *   score = configured ÷ (configured + action needed + review) × 100
 *   a check whose read the API refused is "Not permitted" and left out of the score, never counted as a failure
 *   informational checks are left out too; with nothing scored the result is "Not assessed", not 0
 *   maturity: 90+ Optimized, 75+ Managed, 50+ Developing, 25+ Initial, below that Ad hoc
 *   every finding reads in four sentences: what was found, what it means, what to do, the outcome
 * The checks themselves are the wizard's own, about 40 of them, chosen for what a POV can prove.
 */
'use strict';
const list = (r) => (Array.isArray(r) ? r : (r && (r.list || r.items)) || []);

const SECURITY_RISK = ['NEWLY_REG_DOMAINS', 'P2P_COMMUNICATION', 'REMOTE_ACCESS'];
const PRIVACY_RISK = ['ADWARE_OR_SPYWARE', 'DYNAMIC_DNS'];
const unscoped = (r) => !['users', 'groups', 'departments', 'locations', 'locationGroups', 'devices', 'deviceGroups', 'timeWindows', 'sourceIpGroups'].some(k => (r[k] || []).length);
const on = (r) => r && r.state !== 'DISABLED';
const blocks = (a) => /BLOCK|DENY/.test(String(a || ''));

/** Read everything once; a refused or failed read is remembered so its checks become "Not permitted" / "Not checked". */
async function readAll(zia, zcc) {
  const ctx = { refused: {}, data: {} };
  const read = async (key, fn) => {
    try { ctx.data[key] = await fn(); }
    catch (e) { ctx.data[key] = undefined; ctx.refused[key] = /\b(401|403)\b|not authorized|NOT_AUTHORIZED|permission/i.test(String(e.message)) ? 'notPermitted' : /NOT_SUBSCRIBED|subscription/i.test(String(e.message)) ? 'notLicensed' : 'error'; }
  };
  const Z = (p) => () => zia.apiCall('GET', p);
  await read('ssl', async () => list(await Z('/api/v1/sslInspectionRules')()));
  await read('atp', Z('/api/v1/cyberThreatProtection/advancedThreatSettings'));
  await read('url', async () => list(await Z('/api/v1/urlFilteringRules')()));
  await read('fw', async () => list(await Z('/api/v1/firewallFilteringRules')()));
  await read('dns', async () => list(await Z('/api/v1/firewallDnsRules')()));
  await read('ftc', async () => list(await Z('/api/v1/fileTypeRules')()));
  await read('sandbox', async () => list(await Z('/api/v1/sandboxRules')()));
  await read('dlp', async () => list(await Z('/api/v1/webDlpRules')()));
  await read('edlp', async () => list(await Z('/api/v1/endPointDlpRules')()));
  await read('cacAi', async () => list(await Z('/api/v1/webApplicationRules/AI_ML')()));
  await read('cacFile', async () => list(await Z('/api/v1/webApplicationRules/FILE_SHARE')()));
  await read('cacDoh', async () => list(await Z('/api/v1/webApplicationRules/DNS_OVER_HTTPS')()));
  await read('appSettings', Z('/api/v1/advancedUrlFilterAndCloudAppSettings'));
  await read('adv', Z('/api/v1/advancedSettings'));
  if (zcc) {
    await read('zccApp', async () => [...list(await zcc.getAppProfiles(3).catch(e => { throw e; })), ...list(await zcc.getAppProfiles(4).catch(() => []))]);
    await read('zccFwd', async () => list(await zcc.getForwardingProfiles()));
  } else { ctx.refused.zccApp = 'notConnected'; ctx.refused.zccFwd = 'notConnected'; }
  return ctx;
}

// Each check: id, area, label, needs (data keys), fn(d) → { status: 'pass'|'fail'|'review'|'info', found, means?, do?, outcome? }
const CHECKS = [
  // ---------- SSL inspection ----------
  { id: 'SSL-1', area: 'SSL Inspection', label: 'Traffic is inspected by default', needs: ['ssl'], fn: (d) => {
    const ca = d.ssl.find(r => on(r) && !r.defaultRule && unscoped(r) && r.action && r.action.type === 'DECRYPT' && !(r.urlCategories || []).filter(c => c !== 'ANY').length && !(r.cloudApplications || []).length);
    const def = d.ssl.find(r => r.defaultRule);
    return ca || (def && def.action && def.action.type === 'DECRYPT') ? { status: 'pass', found: `"${(ca || def).name}" decrypts everything no other rule names.` }
      : { status: 'fail', found: 'No rule inspects remaining traffic, and the default SSL rule does not decrypt.', means: 'Most HTTPS traffic is not inspected, so DLP, sandbox, file type control and malware scanning cannot see it.', do: 'Add an "inspect everything else" SSL rule at the bottom.', outcome: 'Content-based protections apply to HTTPS.' };
  } },
  { id: 'SSL-2', area: 'SSL Inspection', label: 'Old TLS is refused on inspected traffic', needs: ['ssl'], fn: (d) => {
    const dec = d.ssl.filter(r => on(r) && r.action && r.action.type === 'DECRYPT');
    if (!dec.length) return { status: 'info', found: 'No rule decrypts traffic.' };
    const weak = dec.filter(r => { const v = ((r.action.decryptSubActions || {}).minServerTLSVersion) || ''; return !/1_2|1_3/.test(v); });
    return !weak.length ? { status: 'pass', found: 'Every decrypting rule requires TLS 1.2 or later from servers.' }
      : { status: 'review', found: `${weak.length} decrypting rule(s) accept servers below TLS 1.2 (${weak.slice(0, 3).map(r => r.name).join(', ')}).`, means: 'Users can reach servers that only offer deprecated protocols.', do: 'Set the minimum server TLS version to 1.2.', outcome: 'Connections to weak servers are refused.' };
  } },
  { id: 'SSL-3', area: 'SSL Inspection', label: 'Traffic that cannot be decrypted is blocked', needs: ['ssl'], fn: (d) => {
    const dec = d.ssl.filter(r => on(r) && r.action && r.action.type === 'DECRYPT');
    if (!dec.length) return { status: 'info', found: 'No rule decrypts traffic.' };
    const open = dec.filter(r => (r.action.decryptSubActions || {}).blockUndecrypt === false);
    return !open.length ? { status: 'pass', found: 'Undecryptable traffic is blocked on the decrypting rules.' }
      : { status: 'review', found: `${open.length} decrypting rule(s) let undecryptable traffic through.`, means: 'Tools that pin certificates or use non-standard TLS pass uninspected.', do: 'Turn on "Block undecryptable traffic" and exempt known pinned apps by name.', outcome: 'Nothing passes uninspected by accident.' };
  } },
  { id: 'SSL-4', area: 'SSL Inspection', label: 'No blanket "do not inspect" rule', needs: ['ssl'], fn: (d) => {
    const bad = d.ssl.filter(r => on(r) && !r.defaultRule && unscoped(r) && r.action && r.action.type === 'DO_NOT_DECRYPT' && !(r.urlCategories || []).filter(c => c !== 'ANY').length && !(r.cloudApplications || []).length);
    return !bad.length ? { status: 'pass', found: 'Every exemption names its categories or apps.' }
      : { status: 'fail', found: `"${bad[0].name}" exempts all traffic from inspection.`, means: 'Every rule below it is never reached.', do: 'Limit it to the categories or apps that need it.', outcome: 'Inspection applies to everything else.' };
  } },
  { id: 'SSL-5', area: 'SSL Inspection', label: 'Health and finance sites are exempt for privacy', needs: ['ssl'], fn: (d) => {
    const ex = new Set(d.ssl.filter(r => on(r) && r.action && r.action.type === 'DO_NOT_DECRYPT').flatMap(r => r.urlCategories || []));
    const miss = ['HEALTH', 'FINANCE'].filter(c => !ex.has(c));
    return !miss.length ? { status: 'pass', found: 'Health and finance categories are not decrypted.' }
      : { status: 'review', found: `Not exempt: ${miss.join(', ').toLowerCase()}.`, means: 'Users\' banking and health traffic is decrypted, which many privacy policies and works councils do not allow.', do: 'Add a privacy exemption rule for these categories.', outcome: 'Inspection stays within privacy policy.' };
  } },
  // ---------- Threat protection ----------
  ...[
    ['ATP-1', 'malwareSitesBlocked', 'Known malicious sites are blocked'],
    ['ATP-2', 'cmdCtlServerBlocked', 'Command-and-control servers are blocked'],
    ['ATP-3', 'cmdCtlTrafficBlocked', 'Botnet traffic to unknown servers is blocked'],
    ['ATP-4', 'knownPhishingSitesBlocked', 'Known phishing sites are blocked'],
    ['ATP-5', 'suspectedPhishingSitesBlocked', 'Suspected phishing sites are blocked'],
    ['ATP-6', 'browserExploitsBlocked', 'Browser exploits are blocked'],
    ['ATP-7', 'cryptoMiningBlocked', 'Cryptomining is blocked'],
    ['ATP-8', 'potentialMaliciousRequestsBlocked', 'Cross-site scripting requests are blocked']
  ].map(([id, key, label]) => ({ id, area: 'Threat protection', label, needs: ['atp'], fn: (d) => {
    if (d.atp[key] === undefined) return { status: 'info', found: 'This setting is not reported for this tenant.' };
    return d.atp[key] ? { status: 'pass', found: 'On.' } : { status: 'fail', found: 'Off.', means: 'This class of threat is allowed through Advanced Threat Protection.', do: `Turn on "${label}" in Advanced Threat Protection.`, outcome: 'The threat is blocked before it reaches the user.' };
  } })),
  { id: 'SBX-1', area: 'Threat protection', label: 'Unknown executables are sandboxed', needs: ['sandbox'], fn: (d) => {
    const r = d.sandbox.find(x => on(x) && !x.defaultRule && (x.fileTypes || []).some(t => /EXECUTABLE|WINDOWS_LIBRARY|_EXE|DLL/.test(t)));
    return r ? { status: 'pass', found: `"${r.name}" sends unknown executables to the sandbox.` }
      : { status: 'fail', found: 'No sandbox rule covers executables.', means: 'New malware with no known signature can be downloaded and run.', do: 'Add a sandbox rule for executables and libraries.', outcome: 'Unknown files are detonated before delivery.' };
  } },
  { id: 'SBX-2', area: 'Threat protection', label: 'Sandbox uses AI instant verdict', needs: ['sandbox'], fn: (d) => {
    const rs = d.sandbox.filter(x => on(x) && !x.defaultRule);
    if (!rs.length) return { status: 'info', found: 'No sandbox rules.' };
    return rs.some(x => x.mlActionEnabled) ? { status: 'pass', found: 'AI instant verdict is on for at least one rule.' }
      : { status: 'review', found: 'AI instant verdict is off on every sandbox rule.', means: 'Users wait for a full sandbox run (or get the file unscanned) when an instant verdict would do.', do: 'Turn on AI Instant Verdict (needs Sandbox Advanced).', outcome: 'Most unknown files are judged in seconds.' };
  } },
  // ---------- URL filtering ----------
  { id: 'URL-1', area: 'URL Filtering', label: 'High-risk categories are blocked or isolated', needs: ['url'], fn: (d) => {
    const covered = new Set(d.url.filter(r => on(r) && unscoped(r) && /BLOCK|ISOLATE|CAUTION/.test(r.action || '')).flatMap(r => r.urlCategories || []));
    const miss = SECURITY_RISK.filter(c => !covered.has(c) && !covered.has('ANY'));
    return !miss.length ? { status: 'pass', found: 'Newly registered domains, P2P and remote access sites are controlled.' }
      : { status: 'fail', found: `Not controlled: ${miss.map(c => c.toLowerCase().replace(/_/g, ' ')).join(', ')}.`, means: 'These are common first steps of phishing and ransomware.', do: 'Block or isolate these categories.', outcome: 'Fewer initial-access paths.' };
  } },
  { id: 'URL-2', area: 'URL Filtering', label: 'Anonymizers are blocked', needs: ['url'], fn: (d) => {
    const ok = d.url.some(r => on(r) && unscoped(r) && blocks(r.action) && (r.urlCategories || []).includes('ANONYMIZER'));
    return ok ? { status: 'pass', found: 'An unscoped rule blocks anonymizers.' }
      : { status: 'fail', found: 'No unscoped rule blocks anonymizers.', means: 'Users can tunnel around every other web policy.', do: 'Block the Anonymizer category.', outcome: 'Policy cannot be bypassed through proxy sites.' };
  } },
  { id: 'URL-3', area: 'URL Filtering', label: 'Spyware and dynamic DNS sites are blocked', needs: ['url'], fn: (d) => {
    const covered = new Set(d.url.filter(r => on(r) && unscoped(r) && blocks(r.action)).flatMap(r => r.urlCategories || []));
    const miss = PRIVACY_RISK.filter(c => !covered.has(c));
    return !miss.length ? { status: 'pass', found: 'Both are blocked.' } : { status: 'review', found: `Not blocked: ${miss.map(c => c.toLowerCase().replace(/_/g, ' ')).join(', ')}.`, means: 'Malware callbacks often use these.', do: 'Block them.', outcome: 'Fewer command-and-control paths.' };
  } },
  { id: 'URL-4', area: 'URL Filtering', label: 'Uncategorized sites are isolated or controlled', needs: ['url'], fn: (d) => {
    const ok = d.url.some(r => on(r) && unscoped(r) && /BLOCK|ISOLATE|CAUTION/.test(r.action || '') && (r.urlCategories || []).some(c => /MISCELLANEOUS_OR_UNKNOWN|NON_CATEGORIZABLE/.test(c)));
    return ok ? { status: 'pass', found: 'Unknown sites are isolated, cautioned or blocked.' } : { status: 'review', found: 'Unknown and uncategorizable sites are allowed.', means: 'Brand-new attack sites are often uncategorized.', do: 'Isolate them in Browser Isolation (users still reach them safely).', outcome: 'Unknown sites cannot deliver code to the endpoint.' };
  } },
  // ---------- Firewall ----------
  { id: 'FW-1', area: 'Cloud Firewall', label: 'QUIC is blocked so web traffic stays inspectable', needs: ['fw'], fn: (d) => {
    const ok = d.fw.some(r => on(r) && unscoped(r) && blocks(r.action) && ((r.nwApplications || []).includes('QUIC') || (r.nwServices || []).some(s => /QUIC/i.test(s.name || ''))));
    return ok ? { status: 'pass', found: 'A firewall rule blocks QUIC.' } : { status: 'fail', found: 'QUIC is not blocked.', means: 'Browsers use HTTP/3 over UDP, which ZIA cannot inspect, so web policy is skipped for Google and other sites.', do: 'Block QUIC; browsers fall back to TCP.', outcome: 'All web traffic is inspected.' };
  } },
  { id: 'FW-2', area: 'Cloud Firewall', label: 'Risky outbound protocols are controlled', needs: ['fw'], fn: (d) => {
    const names = (r) => [...(r.nwApplications || []), ...(r.nwServices || []).map(s => String(s.name || '').toUpperCase())];
    const covered = new Set(d.fw.filter(r => on(r) && blocks(r.action)).flatMap(names));
    const miss = ['TELNET', 'SMB'].filter(p => ![...covered].some(c => c.includes(p)));
    return !miss.length ? { status: 'pass', found: 'Telnet and SMB to the internet are blocked.' } : { status: 'review', found: `Not blocked to the internet: ${miss.join(', ')}.`, means: 'Clear-text and file-sharing protocols are common exfiltration and worm paths.', do: 'Block them outbound (or limit to named destinations).', outcome: 'A smaller attack surface.' };
  } },
  { id: 'FW-3', area: 'Cloud Firewall', label: 'Default firewall rule denies', needs: ['fw'], fn: (d) => {
    const def = d.fw.find(r => r.defaultRule);
    if (!def) return { status: 'info', found: 'The default rule was not returned.' };
    return blocks(def.action) ? { status: 'pass', found: `The default rule is ${def.action.toLowerCase().replace(/_/g, ' ')}.` }
      : { status: 'review', found: 'The default firewall rule allows anything not matched.', means: 'New or unknown protocols are allowed by default.', do: 'Allow what is needed explicitly, then make the default block.', outcome: 'Deny by default, allow by exception.' };
  } },
  // ---------- DNS ----------
  { id: 'DNS-1', area: 'DNS Security', label: 'DNS tunnels are blocked', needs: ['dns'], fn: (d) => {
    const ok = d.dns.some(r => on(r) && blocks(r.action) && (r.applications || []).some(a => /^DNSTUN/.test(a)));
    return ok ? { status: 'pass', found: 'A DNS rule blocks tunnel applications.' } : { status: 'fail', found: 'No DNS rule blocks DNS tunnels.', means: 'Data can leave hidden in DNS queries.', do: 'Block DNS tunnel applications (needs Advanced Cloud Firewall).', outcome: 'DNS cannot be used for exfiltration.' };
  } },
  { id: 'DNS-2', area: 'DNS Security', label: 'DNS over HTTPS is controlled', needs: ['dns'], fn: (d) => {
    const dnsRule = d.dns.some(r => on(r) && (r.protocols || []).includes('DOHTTPS_RULE'));
    const cac = (d.cacDoh || []).some(r => on(r) && (r.actions || []).some(a => /DENY|BLOCK/.test(a)));
    return dnsRule || cac ? { status: 'pass', found: 'DoH is covered by policy.' } : { status: 'review', found: 'No rule covers DNS over HTTPS.', means: 'Browsers that use DoH resolve names outside DNS policy.', do: 'Add DNS policy for DoH or block unsanctioned DoH providers.', outcome: 'Name resolution stays visible and filtered.' };
  } },
  { id: 'DNS-3', area: 'DNS Security', label: 'Risky domains are blocked at DNS', needs: ['dns'], fn: (d) => {
    const ok = d.dns.some(r => on(r) && blocks(r.action) && ((r.destIpCategories || []).length || (r.resCategories || []).length));
    return ok ? { status: 'pass', found: 'A DNS rule blocks categories.' } : { status: 'review', found: 'No DNS rule blocks by category.', means: 'Non-web apps can still resolve malicious domains.', do: 'Block security categories at DNS.', outcome: 'Protection for traffic that is not web.' };
  } },
  // ---------- File type ----------
  { id: 'FTC-1', area: 'File Type Control', label: 'Executable and script downloads are controlled', needs: ['ftc'], fn: (d) => {
    const ok = d.ftc.some(r => on(r) && /BLOCK|CAUTION/.test(r.filteringAction || '') && (r.fileTypes || []).some(t => /EXECUTABLE|POWERSHELL|SCRIPT|BAT/.test(t)));
    return ok ? { status: 'pass', found: 'A file type rule blocks or cautions executables or scripts.' } : { status: 'review', found: 'Executables and scripts can be downloaded freely.', means: 'Users can run tools and payloads from any site.', do: 'Block or caution these types, with exceptions for software sites.', outcome: 'Fewer unapproved programs.' };
  } },
  { id: 'FTC-2', area: 'File Type Control', label: 'Password-protected archives are controlled', needs: ['ftc'], fn: (d) => {
    const ok = d.ftc.some(r => on(r) && /BLOCK|CAUTION/.test(r.filteringAction || '') && (r.passwordProtected || (r.fileTypes || []).some(t => /ZIP|RAR|P7Z/.test(t)) && r.passwordProtected !== false));
    return ok ? { status: 'pass', found: 'Archives are controlled.' } : { status: 'review', found: 'Password-protected archives pass uninspected.', means: 'They cannot be scanned for malware or DLP.', do: 'Block or caution password-protected archives.', outcome: 'Hidden payloads and data are stopped.' };
  } },
  // ---------- DLP ----------
  { id: 'DLP-1', area: 'Data protection', label: 'Web DLP is in use', needs: ['dlp'], fn: (d) => {
    const n = d.dlp.filter(r => on(r)).length;
    return n ? { status: 'pass', found: `${n} web DLP rule(s) enabled.` } : { status: 'fail', found: 'No web DLP rule is enabled.', means: 'Sensitive data can be uploaded anywhere unseen.', do: 'Start in monitor mode with the profile\'s engines.', outcome: 'Visibility of sensitive data leaving the organization.' };
  } },
  { id: 'DLP-2', area: 'Data protection', label: 'At least one DLP rule blocks', needs: ['dlp'], fn: (d) => {
    const rs = d.dlp.filter(r => on(r));
    if (!rs.length) return { status: 'info', found: 'No web DLP rules.' };
    return rs.some(r => blocks(r.action)) ? { status: 'pass', found: 'A DLP rule blocks.' } : { status: 'review', found: 'Every DLP rule only monitors.', means: 'Incidents are logged but nothing is stopped.', do: 'Move the most precise rules (low false positives) to block.', outcome: 'Real prevention for the highest-risk data.' };
  } },
  { id: 'DLP-3', area: 'Data protection', label: 'Custom detection for the organization\'s data', needs: ['dlp'], fn: (d) => {
    const rs = d.dlp.filter(r => on(r));
    if (!rs.length) return { status: 'info', found: 'No web DLP rules.' };
    const custom = rs.some(r => (r.dlpEngines || []).some(e => !/^(HIPAA|PCI|GLBA|GDPR|SSN|OFFENSIVE|CYBER|PHI|CCPA)/i.test(String(e.name || ''))));
    return custom ? { status: 'pass', found: 'Rules use custom engines.' } : { status: 'review', found: 'Only Zscaler\'s predefined engines are used.', means: 'Organization-specific data (MRNs, member IDs, CUI markings, source code) is not detected.', do: 'Add custom dictionaries and engines for it.', outcome: 'Detection matches the customer\'s own data.' };
  } },
  { id: 'DLP-4', area: 'Data protection', label: 'Endpoint DLP covers USB and print', needs: ['edlp'], fn: (d) => {
    const n = (d.edlp || []).filter(r => on(r)).length;
    return n ? { status: 'pass', found: `${n} endpoint DLP rule(s) enabled.` } : { status: 'review', found: 'No endpoint DLP rules.', means: 'Data copied to USB or printed is not seen.', do: 'Add endpoint DLP in monitor mode.', outcome: 'Visibility of data leaving through the device.' };
  } },
  // ---------- Cloud and AI apps ----------
  { id: 'APP-1', area: 'Cloud and AI apps', label: 'Generative AI apps are governed', needs: ['cacAi'], fn: (d) => {
    const ok = (d.cacAi || []).some(r => on(r) && unscoped(r) && (r.actions || []).some(a => /CAUTION|ISOLATE|DENY|BLOCK/.test(a)));
    return ok ? { status: 'pass', found: 'An AI & ML rule cautions, isolates or blocks AI apps.' } : { status: 'fail', found: 'AI apps are allowed with no control.', means: 'Users can paste any data into any AI app.', do: 'Caution or isolate unsanctioned AI apps and allow the sanctioned ones.', outcome: 'AI use is visible and steered to approved apps.' };
  } },
  { id: 'APP-2', area: 'Cloud and AI apps', label: 'AI prompts are captured', needs: ['appSettings'], fn: (d) => {
    const keys = Object.keys(d.appSettings || {}).filter(k => /Prompt$/.test(k));
    if (!keys.length) return { status: 'info', found: 'Prompt capture settings are not reported for this tenant.' };
    const onKeys = keys.filter(k => d.appSettings[k]);
    return onKeys.length ? { status: 'pass', found: `Prompt capture is on for ${onKeys.length} of ${keys.length} AI apps.` } : { status: 'review', found: 'Prompt capture is off for every AI app.', means: 'There is no record of what was sent to AI apps.', do: 'Turn on prompt capture for the AI apps in use.', outcome: 'Prompts are available for DLP review and investigations.' };
  } },
  { id: 'APP-3', area: 'Cloud and AI apps', label: 'Uploads to personal file sharing are controlled', needs: ['cacFile'], fn: (d) => {
    const ok = (d.cacFile || []).some(r => on(r) && (r.actions || []).some(a => /DENY_FILE_SHARE_UPLOAD|BLOCK_FILE_SHARE|CAUTION_FILE_SHARE_UPLOAD|ISOLATE_FILE_SHARE/.test(a)));
    return ok ? { status: 'pass', found: 'A file sharing rule limits uploads.' } : { status: 'review', found: 'Uploads to file sharing apps are unrestricted.', means: 'Data can move to personal Dropbox, Drive or WeTransfer.', do: 'Allow viewing, deny uploads to unsanctioned file sharing.', outcome: 'Data stays in sanctioned storage.' };
  } },
  // ---------- Advanced settings ----------
  ...[
    ['ADV-1', 'blockHttpTunnelOnNonHttpPorts', 'HTTP tunnels on non-HTTP ports are blocked', 'Tools can tunnel through the proxy on other ports.'],
    ['ADV-2', 'blockDomainFrontingOnHostHeader', 'Domain fronting is blocked', 'Malware can hide its destination behind a trusted CDN host.'],
    ['ADV-3', 'blockNonCompliantHttpRequestOnHttpPorts', 'Non-compliant HTTP requests are blocked', 'Malformed requests used for smuggling and evasion pass.']
  ].map(([id, key, label, means]) => ({ id, area: 'Advanced settings', label, needs: ['adv'], fn: (d) => {
    if (d.adv[key] === undefined) return { status: 'info', found: 'Not reported for this tenant.' };
    return d.adv[key] ? { status: 'pass', found: 'On.' } : { status: 'review', found: 'Off.', means, do: `Turn on "${label}" in Advanced Settings.`, outcome: 'One fewer way around inspection.' };
  } })),
  // ---------- Client Connector ----------
  { id: 'ZCC-1', area: 'Client Connector', label: 'Users cannot uninstall or turn off Client Connector', needs: ['zccApp'], fn: (d) => {
    const ps = d.zccApp.filter(p => String(p.active) === '1' || p.active === true);
    if (!ps.length) return { status: 'info', found: 'No active app profiles.' };
    const open = ps.filter(p => !(p.uninstall_password || p.disable_password || p.logout_password));
    return !open.length ? { status: 'pass', found: 'Every active app profile has a tamper password set.' }
      : { status: 'fail', found: `${open.length} active app profile(s) have no uninstall, disable or logout password (${open.slice(0, 3).map(p => p.name).join(', ')}).`, means: 'Users can switch protection off.', do: 'Set uninstall, disable and logout passwords; issue one-time passwords when needed.', outcome: 'Protection stays on.' };
  } },
  { id: 'ZCC-2', area: 'Client Connector', label: 'Client Connector installs the root certificate', needs: ['zccApp'], fn: (d) => {
    const ps = d.zccApp.filter(p => String(p.active) === '1' || p.active === true);
    if (!ps.length) return { status: 'info', found: 'No active app profiles.' };
    const off = ps.filter(p => String(p.install_ssl_certs) !== '1' && p.install_ssl_certs !== true);
    return !off.length ? { status: 'pass', found: 'Every active profile installs the Zscaler root certificate.' } : { status: 'review', found: `${off.length} profile(s) do not install it.`, means: 'Inspected sites show certificate errors unless the certificate is pushed another way.', do: 'Turn on "Install Zscaler SSL certificate", or confirm it is pushed by MDM or GPO.', outcome: 'Inspection is invisible to users.' };
  } },
  { id: 'ZCC-3', area: 'Client Connector', label: 'Z-Tunnel 2.0 forwards all traffic', needs: ['zccFwd'], fn: (d) => {
    const acts = d.zccFwd.flatMap(f => f.forwardingProfileActions || []).filter(a => String(a.actionType) === '1');
    if (!acts.length) return { status: 'info', found: 'No forwarding profile tunnels to ZIA.' };
    const t2 = acts.filter(a => String(a.enablePacketTunnel) === '1' || a.enablePacketTunnel === true);
    return t2.length === acts.length ? { status: 'pass', found: 'Every tunnel action uses Z-Tunnel 2.0.' } : { status: 'review', found: `${acts.length - t2.length} of ${acts.length} tunnel action(s) use Z-Tunnel 1.0 (web ports only).`, means: 'Non-web traffic leaves without firewall, DNS and IPS policy.', do: 'Use Z-Tunnel 2.0.', outcome: 'Firewall and DNS policy apply to every port.' };
  } }
];

const MATURITY = [[90, 'Optimized'], [75, 'Managed'], [50, 'Developing'], [25, 'Initial'], [0, 'Ad hoc']];

async function assess(zia, zcc) {
  const ctx = await readAll(zia, zcc);
  const results = [];
  for (const c of CHECKS) {
    const why = c.needs.map(k => ctx.refused[k]).find(Boolean);
    if (why) { results.push({ id: c.id, area: c.area, label: c.label, status: why === 'notPermitted' ? 'notPermitted' : why === 'notConnected' ? 'notChecked' : why === 'notLicensed' ? 'notLicensed' : 'notChecked',
      found: why === 'notPermitted' ? 'Coverage unknown: the API client is not allowed to read this.' : why === 'notConnected' ? 'Not checked: Client Connector is not connected in this session.' : why === 'notLicensed' ? 'Not licensed on this tenant.' : 'Not checked: the read failed.' }); continue; }
    try { results.push({ id: c.id, area: c.area, label: c.label, ...c.fn(ctx.data) }); }
    catch (e) { results.push({ id: c.id, area: c.area, label: c.label, status: 'notChecked', found: `Not checked: ${e.message.slice(0, 120)}` }); }
  }
  return summarize(results);
}

function summarize(results) {
  const n = (s) => results.filter(r => r.status === s).length;
  const scored = n('pass') + n('fail') + n('review');
  const score = scored ? Math.round(n('pass') / scored * 100) : null;
  const maturity = score === null ? 'Not assessed' : MATURITY.find(([min]) => score >= min)[1];
  const areas = {};
  for (const r of results) {
    const a = areas[r.area] || (areas[r.area] = { pass: 0, fail: 0, review: 0, other: 0 });
    if (['pass', 'fail', 'review'].includes(r.status)) a[r.status]++; else a.other++;
  }
  return { at: new Date().toISOString(), score, maturity, counts: { pass: n('pass'), fail: n('fail'), review: n('review'), info: n('info'), notPermitted: n('notPermitted'), notChecked: n('notChecked') + n('notLicensed') },
    areas: Object.entries(areas).map(([area, v]) => ({ area, ...v, score: v.pass + v.fail + v.review ? Math.round(v.pass / (v.pass + v.fail + v.review) * 100) : null })), results,
    method: 'Score = configured ÷ (configured + action needed + review). Checks the API could not read, informational checks and checks not run are left out of the score.' };
}

/** Before vs after: per check, what moved. */
function compare(before, after) {
  if (!before || !after) return null;
  const b = Object.fromEntries((before.results || []).map(r => [r.id, r]));
  const improved = [], regressed = [];
  for (const r of after.results || []) {
    const was = b[r.id];
    if (!was) continue;
    if (was.status !== 'pass' && r.status === 'pass' && ['fail', 'review'].includes(was.status)) improved.push({ id: r.id, area: r.area, label: r.label, from: was.status });
    if (was.status === 'pass' && ['fail', 'review'].includes(r.status)) regressed.push({ id: r.id, area: r.area, label: r.label, to: r.status });
  }
  return { from: before.score, to: after.score, delta: before.score !== null && after.score !== null ? after.score - before.score : null, fromMaturity: before.maturity, toMaturity: after.maturity, improved, regressed };
}

module.exports = { assess, compare, summarize, CHECKS, MATURITY };
