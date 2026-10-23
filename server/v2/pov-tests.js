/**
 * v2.2: POV test runbook, "prove it" checks and the DLP test kit.
 *  - Runbook: one test per policy the wizard created in this session (matched by rule name), with steps,
 *    expected result and pass / fail tracking (kept in the session and added to the summary report).
 *  - Prove it: what ZIA does with a URL (URL lookup → first matching URL Filtering rule) plus the
 *    Z-Insights counts for the last hour. Per-transaction logs are not available to API clients
 *    (the transaction-log endpoints refuse client-credential tokens), so this shows the policy match and totals.
 *  - DLP test kit: synthetic, clearly labelled test data that matches the DLP rules (no real person's data).
 */
'use strict';
const list = (r) => (Array.isArray(r) ? r : (r && (r.list || r.items)) || []);

// Each test: id, product, title, match (rule/object name suffix regex), steps, expect, links
const TESTS = [
  { id: 'url-block', product: 'ZIA', title: 'Blocked web category', match: /-Block-(Legal-Liability|Security-Risk|Privacy-Risk)/,
    steps: ['Browse to a site in a blocked category, for example a gambling or hacking site.'], expect: 'The Zscaler block page names the rule.' , prove: 'https://www.bet365.com/' },
  { id: 'url-caution', product: 'ZIA', title: 'Caution page', match: /-Caution-/,
    steps: ['Browse to a streaming or shopping site.'], expect: 'A Caution page appears; Continue lets the user through and the visit is logged.', prove: 'https://www.netflix.com/' },
  { id: 'url-isolate', product: 'ZIA', title: 'Isolate Miscellaneous / Unknown', match: /-Isolate-Misc-Unknown/,
    steps: ['Browse to a brand-new or uncategorized site.'], expect: 'The site opens in a Cloud Browser Isolation session (pixels only; copy / paste and downloads follow the isolation profile).' },
  { id: 'ssl-inspect', product: 'ZIA', title: 'SSL inspection after the Zscaler exemptions', match: /-SSL-(Inspect-Remaining|Inspect-All|Inspect-Catch-All)/,
    steps: ['Open https://www.wikipedia.org and look at the certificate.', 'Open a banking site in the Finance category.'], expect: 'Wikipedia shows the Zscaler certificate (inspected); the bank shows its own certificate (exempt).' },
  { id: 'ssl-tls', product: 'ZIA', title: 'Old TLS versions blocked', match: /-SSL-(Inspect-Remaining|Inspect-All|Inspect-Catch-All)/,
    steps: ['Open https://tls-v1-1.badssl.com:1011/'], expect: 'Blocked: TLS 1.0 and 1.1 are below the minimum (TLS 1.2).' },
  { id: 'doh', product: 'ZIA', title: 'DNS over HTTPS inspected', match: /-DNS-DoH-Block-Risky/,
    steps: ['In Firefox, turn on DNS over HTTPS (Settings › Privacy & Security › DNS over HTTPS › Max protection).', 'Open https://1.1.1.1/help.'],
    expect: '1.1.1.1/help reports DoH in use, and ZIA DNS logs show the lookups; lookups of risky domains over DoH are blocked.' },
  { id: 'resolver', product: 'ZIA', title: 'DNS answered by the Zscaler Trusted Resolver', match: /-DNS-Trusted-Resolver/,
    steps: ['Set the test machine\'s DNS server to 8.8.8.8.', 'Run nslookup www.zscaler.com and browse to a site.'], expect: 'Names still resolve and browsing works; the DNS logs show the requests redirected to the Zscaler Trusted Resolver.' },
  { id: 'dns-tunnel', product: 'ZIA', title: 'DNS tunnels blocked', match: /-DNS-Block-(Critical|High)-Tunnels/,
    steps: ['Run a DNS tunnel test tool (for example iodine or dnscat2) from the test machine.'], expect: 'The tunnel lookups are blocked and logged as DNS tunnel traffic.' },
  { id: 'geo', product: 'ZIA', title: 'Remote access to high-risk countries dropped', match: /-FW-Geo-Block-Out/,
    steps: ['From the test machine, try ssh to a server in one of the blocked countries (for example ssh 202.108.22.5).'], expect: 'The connection times out (dropped); the firewall log shows the Geo-Block rule.' },
  { id: 'quic', product: 'ZIA', title: 'QUIC blocked (traffic stays inspectable)', match: /-Block-QUIC/,
    steps: ['Open https://www.youtube.com in Chrome and check chrome://net-internals/#quic.'], expect: 'Sessions fall back to TCP/HTTP2; no QUIC sessions to Google.' },
  { id: 'sandbox', product: 'ZIA', title: 'Cloud Sandbox quarantine', match: /-Sandbox-|-SBX-/,
    steps: ['In the test kit, download the unique sandbox PDF (a new, never-seen file every time).', 'Upload it to a file share (OneDrive, Box or Google Drive), then download it again from there through ZIA.', 'Open Sandbox in ZIA Insights for the report.'],
    expect: 'The first download is held (quarantine) until the sandbox verdict, then allowed as benign; the sandbox report shows the analysis. Known-bad files are blocked outright.' },
  { id: 'malware', product: 'ZIA', title: 'Known malware blocked', match: /Advanced Threat|ATP/i,
    steps: ['Open the EICAR links in the test kit: eicar.com, eicar.com.txt, eicar_com.zip and eicar_com2.zip (a zip in a zip).', 'Open the AMTSO malware, drive-by and phishing checks from the test kit.'],
    expect: 'Every EICAR download is blocked by malware protection, zipped ones too, and the AMTSO checks are blocked by Advanced Threat Protection; each block page names the policy.' },
  { id: 'dlp', product: 'ZIA', title: 'DLP blocks sensitive data uploads', match: /-DLP-/,
    steps: ['Download the DLP file for the customer\'s vertical (and the generic PII file) from the test kit.', 'Upload it (or paste a few lines) to https://dlptest.com/http-post/ through ZIA.'], expect: 'Block mode: the upload is blocked and the DLP incident names the engine and dictionary. Monitor mode: it goes through and the incident is logged.' },
  { id: 'cac-fileshare', product: 'ZIA', title: 'File sharing: view but no upload', match: /-CAC-FileShare-ViewOnly/,
    steps: ['Open Google Drive or Dropbox and browse files.', 'Try to upload a file.'], expect: 'Viewing works; the upload is blocked.' },
  { id: 'cac-social', product: 'ZIA', title: 'Social media: view but no posting', match: /-CAC-(Social-ViewNoPost|LinkedIn-ReadOnly)/,
    steps: ['Open LinkedIn or Facebook and read the feed.', 'Try to post or comment.'], expect: 'Reading works; posting is blocked.' },
  { id: 'cac-genai', product: 'ZIA', title: 'Generative AI: chat allowed, uploads denied', match: /-CAC-GenAI-NoUpload/,
    steps: ['Open ChatGPT and send a prompt.', 'Try to upload a document.'], expect: 'Chat works; the upload is denied. AI Prompt Capture records the prompt.' },
  { id: 'ftc', product: 'ZIA', title: 'File type control', match: /-FTC-/,
    steps: ['Download a Windows executable or a script file from the web.'], expect: 'Blocked by the File Type Control rule.' },
  { id: 'zpa-access', product: 'ZPA', title: 'Private app reachable through ZPA only', match: /-access-policy$/,
    steps: ['With Client Connector signed in, open the internal application.', 'Turn off Private Access in Client Connector and try again.'], expect: 'Reachable with ZPA on, unreachable with it off; the app is never exposed to the internet.' },
  { id: 'zpa-timeout', product: 'ZPA', title: 'Re-authentication timeout', match: /-timeout-policy$/,
    steps: ['Show the timeout policy in the ZPA portal; leave a session idle for an hour.'], expect: 'ZPA asks the user to sign in again after the idle or session timeout.' },
  { id: 'zpa-inspect', product: 'ZPA', title: 'AppProtection blocks web attacks', match: /-inspection-policy$/,
    steps: ['On the private web app, add an SQL injection string to a URL, for example ?id=1%27%20OR%20%271%27=%271'], expect: 'AppProtection blocks or logs the request (OWASP rule) before it reaches the app.' },
  { id: 'zpa-isolate', product: 'ZPA', title: 'Browser Access in isolation', match: /-isolation-policy$/,
    steps: ['Open the Browser Access URL from a browser without Client Connector.'], expect: 'The app opens in an isolated browser session.' },
  { id: 'zpa-ba', product: 'ZPA', title: 'Browser Access with no client', match: /-browser-access$/,
    steps: ['Open the Browser Access URL (shown in the ZPA step) on a machine without Client Connector.'], expect: 'Sign in through the identity provider, then the app opens; no client needed.' },
  { id: 'zpa-pra', product: 'ZPA', title: 'Privileged Remote Access console', match: /-pra-(rdp|ssh)-console$/,
    steps: ['Open the PRA portal URL and sign in.', 'Open the RDP or SSH console.'], expect: 'A browser-based RDP / SSH session to the server, with no client and no inbound ports.' },
  { id: 'zcc-tamper', product: 'ZCC', title: 'Client Connector tamper protection', match: /App Profile/,
    steps: ['As the user, try to Exit, Log out or turn off Internet Security in Client Connector.', 'Try to uninstall it.', 'Issue a one-time password from Devices & Install and use it.'], expect: 'Each action asks for the password; the one-time password works once.' },
  { id: 'aiguard-chain', product: 'AIGUARD', title: 'AI prompts reach AI Guard', match: /-AIG-Forward$/,
    steps: ['On a test machine with Client Connector, open ChatGPT, Claude or Copilot and send a harmless prompt.', 'Send a prompt that the AI Guard detection policy should catch (for example a toxic phrase, or a fake card number).', 'Open the AI Guard portal › Insights.'],
    expect: 'Both prompts appear in AI Guard with the user name; the second is flagged (or blocked) by the detection policy. ZIA Web Insights shows the request forwarded by Proxy Chaining.' },
  { id: 'aiguard-copilot', product: 'AIGUARD', title: 'Microsoft 365 Copilot inspected', match: /-AIG-Inspect$/,
    steps: ['Open Copilot (copilot.microsoft.com or Copilot Chat in Microsoft 365) and send a prompt.', 'In ZIA Web Insights, filter on the user and copilot.microsoft.com / substrate.office.com.'],
    expect: 'The transactions show as inspected (not bypassed by the Office 365 one-click rule) and the prompt is visible in AI Guard.' },
  { id: 'aiguard-quic', product: 'AIGUARD', title: 'QUIC blocked for AI apps', match: /-AIG-NoQUIC$/,
    steps: ['In Chrome, open chatgpt.com and check chrome://net-internals or the Network tab protocol column.'], expect: 'Traffic uses HTTP/2 or HTTP/1.1 over TCP (h3 / QUIC is dropped by the firewall rule).' },
  { id: 'aiguard-compliance', product: 'AIGUARD', title: 'AI compliance profile catches sensitive data', match: /-AIG-Compliance$/,
    steps: ['Send a prompt with a made-up identifier from the profile (for example SSN 078-05-1120, the well-known specimen number, or a test card 4111 1111 1111 1111).', 'Send a prompt that tries a prompt injection ("ignore your previous instructions and …").', 'Open the AI Guard portal › Insights.'],
    expect: 'Monitor: the identifier prompt is answered and logged as a detection. Block: it is stopped with the AI Guard block message. The prompt injection is blocked in both modes.' },
  { id: 'aiguard-allow', product: 'AIGUARD', title: 'Sanctioned AI apps allowed, others still controlled', match: /-AIG-Allow-AI$/,
    steps: ['Open a sanctioned app (for example ChatGPT) and send a prompt.', 'Open an AI app that was not picked (for example a lesser-known chatbot).'],
    expect: 'The sanctioned app works with no caution or isolation page and its prompt reaches AI Guard; the other app still gets the tier\'s Block / Caution.' },
  { id: 'zdx-ucaas', product: 'ZDX', title: 'Call quality monitoring', match: /Teams|Zoom|Webex/,
    steps: ['Join a Teams or Zoom meeting from the test machine.', 'Open ZDX › Applications.'], expect: 'ZDX shows the app score and the network path for the meeting.' }
];

// v2.6: the Prove it each test opens with (type + default destination); the dropdown offers the rest of that type's list
const PROVE = {
  'url-block': { type: 'url', target: 'https://www.bet365.com/' }, 'url-caution': { type: 'url', target: 'https://www.netflix.com/' },
  'url-isolate': { type: 'url', target: 'https://hide.me/en/proxy' }, 'ssl-inspect': { type: 'url', target: 'https://www.chase.com/' }, 'ssl-tls': { type: 'url', target: 'https://tls-v1-1.badssl.com:1011/' },
  doh: { type: 'dns', target: 'cloudflare-dns.com', doh: true }, resolver: { type: 'dns', target: 'www.zscaler.com' }, 'dns-tunnel': { type: 'dns', target: 'thepiratebay.org' },
  geo: { type: 'firewall', target: '202.108.22.5:22/tcp' }, quic: { type: 'firewall', target: 'www.youtube.com:443/udp' },
  sandbox: { type: 'threat', target: 'https://www.amtso.org/feature-settings-check-download-of-malware/' }, malware: { type: 'threat', target: 'https://secure.eicar.org/eicar.com.txt' },
  'cac-fileshare': { type: 'cloudApp', target: 'DROPBOX', appType: 'FILE_SHARE' }, 'cac-social': { type: 'cloudApp', target: 'LINKEDIN', appType: 'SOCIAL_NETWORKING' },
  'cac-genai': { type: 'cloudApp', target: 'CHATGPT_AI', appType: 'AI_ML' }, ftc: { type: 'threat', target: 'https://secure.eicar.org/eicar_com.zip' },
  'aiguard-allow': { type: 'cloudApp', target: 'CHATGPT_AI', appType: 'AI_ML' }, 'aiguard-chain': { type: 'url', target: 'https://claude.ai/' }, 'aiguard-copilot': { type: 'url', target: 'https://copilot.microsoft.com/' },
  'aiguard-quic': { type: 'firewall', target: 'chatgpt.com:443/udp' }
};

/** Tests for what actually ran in this session (rows from every run's ledger). */
function runbook(runs, results = {}) {
  const rows = [];
  for (const p of ['zia', 'zcc', 'zpa', 'aiguard']) for (const r of (runs[p] || [])) for (const e of (r.ledger || [])) if (!['FAILED', 'SKIPPED', 'MANUAL'].includes(e.action)) rows.push({ ...e, product: p.toUpperCase() });
  for (const r of (runs.zdx || [])) for (const a of (r.apps || [])) rows.push({ product: 'ZDX', category: 'App', name: a.name || '' });
  const out = [];
  for (const t of TESTS) {
    const hits = rows.filter(r => r.product === t.product && (t.match.test(r.name || '') || t.match.test(r.category || '')));
    if (!hits.length) continue;
    const pv = PROVE[t.id] || (t.prove ? { type: 'url', target: t.prove } : null);
    out.push({ id: t.id, product: t.product, title: t.title, steps: t.steps, expect: t.expect, prove: pv,
      objects: [...new Set(hits.map(h => h.name))].slice(0, 6), result: results[t.id] || null });
  }
  return out;
}

/** What ZIA does with a URL: categories, first matching URL Filtering rule, plus Z-Insights totals for the last hour. */
async function proveUrl(client, url) {
  let host;
  try { host = new URL(/^https?:\/\//i.test(url) ? url : `https://${url}`).hostname; } catch (e) { throw Object.assign(new Error('Enter a URL or domain, for example https://www.example.com'), { status: 400 }); }
  const look = list(await client.apiCall('POST', '/api/v1/urlLookup', [host]))[0] || {};
  const cats = [...(look.urlClassifications || []), ...(look.urlClassificationsWithSecurityAlert || [])];
  const rules = list(await client.apiCall('GET', '/api/v1/urlFilteringRules')).filter(r => r.state !== 'DISABLED').sort((a, b) => a.order - b.order);
  const scoped = (r) => (r.users || []).length || (r.groups || []).length || (r.departments || []).length || (r.locations || []).length || (r.locationGroups || []).length;
  let match = null;
  for (const r of rules) {
    const rc = r.urlCategories || [];
    if (!rc.length || rc.includes('ANY') || rc.some(c => cats.includes(c))) { match = { name: r.name, order: r.order, action: r.action, scoped: !!scoped(r) }; if (!scoped(r)) break; }
  }
  return { host, categories: cats, securityAlert: (look.urlClassificationsWithSecurityAlert || []).length > 0, match,
    note: match && match.scoped ? 'The first matching rule is limited to certain users, groups or locations; the next unscoped rule applies to everyone else.' : null };
}

/** Z-Insights totals for the last hour (aggregates only). */
async function insights(client) {
  const now = Date.now(), start = now - 3600e3, T = `start_time: ${start}, end_time: ${now}`;
  // Z-Insights lives at /zins/graphql on the same OneAPI gateway (not under /zia)
  const q = async (query) => {
    if (client.authMode !== 'oneapi') return null;
    try {
      const r = await client._rawRequest('POST', client.baseUrl, '/zins/graphql', JSON.stringify({ query }), { 'Content-Type': 'application/json', Authorization: `Bearer ${client.accessToken}` });
      const b = typeof r.body === 'string' ? JSON.parse(r.body) : r.body;
      return r.statusCode < 300 && b ? b.data : null;
    } catch (e) { return null; }
  };
  const d1 = await q(`{ WEB_TRAFFIC { threat_class(${T}, traffic_unit: TRANSACTIONS) { entries { name total } } } }`);
  const d2 = await q(`{ ZERO_TRUST_FIREWALL { action(${T}) { entries { name total } } } }`);
  return { window: 'last hour', webThreats: d1 && d1.WEB_TRAFFIC ? d1.WEB_TRAFFIC.threat_class.entries : null, firewallActions: d2 && d2.ZERO_TRUST_FIREWALL ? d2.ZERO_TRUST_FIREWALL.action.entries : null };
}

// ---------- DLP test kit (synthetic data only) ----------
const rnd = (n) => Math.floor(Math.random() * n);
const pad = (n, w) => String(n).padStart(w, '0');
function fakeSsn() { let a; do { a = 1 + rnd(899); } while (a === 666); return `${pad(a, 3)}-${pad(1 + rnd(99), 2)}-${pad(1 + rnd(9999), 4)}`; }
const MBI_L = 'ACDEFGHJKMNPQRTUVWXY';
const MBI_AN = MBI_L + '0123456789';
function fakeMbi() { const L = () => MBI_L[rnd(MBI_L.length)], A = () => MBI_AN[rnd(MBI_AN.length)], D = () => String(rnd(10)); return `${1 + rnd(9)}${L()}${A()}${D()}-${L()}${A()}${D()}-${L()}${L()}${D()}${D()}`; }
const TEST_CARDS = ['4111 1111 1111 1111', '5555 5555 5555 4444', '3782 822463 10005', '6011 1111 1111 1117'];   // published card-network test numbers
const ICD = ['E11.9', 'I10.0', 'J45.909', 'M54.5', 'F41.1', 'K21.9', 'N18.3', 'C50.911'];
const FIRST = ['Alex', 'Jordan', 'Taylor', 'Morgan', 'Casey', 'Riley', 'Jamie', 'Avery'], LAST = ['Testpatient', 'Sample', 'Example', 'Demo'];

function dlpKit() {
  const banner = 'SYNTHETIC TEST DATA generated by the ZTP Policy Wizard for a Zscaler DLP proof of value. Not real people.';
  const phiRows = Array.from({ length: 12 }, (_, i) => [`${FIRST[i % FIRST.length]} ${LAST[i % LAST.length]}`, `19${50 + rnd(50)}-${pad(1 + rnd(12), 2)}-${pad(1 + rnd(28), 2)}`,
    `MRN: ${String(100000 + rnd(899999))}${'ABC'[rnd(3)]}`, fakeMbi(), ICD[i % ICD.length], 'diagnosis code']);
  const phi = [`# ${banner}`, 'Patient,Date of birth,Medical record,Medicare MBI,ICD-10 diagnosis,Note', ...phiRows.map(r => r.join(','))].join('\r\n') + '\r\n';
  const pci = [banner, '', 'Cardholder test numbers (card-network test values):', ...TEST_CARDS.map((c, i) => `Card ${i + 1}: ${c}  exp 12/30  name ${FIRST[i]} ${LAST[0]}`)].join('\r\n') + '\r\n';
  const ssn = [banner, '', 'Employee,Social Security number', ...Array.from({ length: 10 }, (_, i) => `${FIRST[i % FIRST.length]} ${LAST[(i + 1) % LAST.length]},${fakeSsn()}`)].join('\r\n') + '\r\n';
  return [
    { name: 'zscaler-pov-PHI-test.csv', type: 'text/csv', description: 'Patient records: MRN, Medicare MBI and ICD-10 codes (custom HIPAA dictionaries).', content: phi },
    { name: 'zscaler-pov-PCI-test.txt', type: 'text/plain', description: 'Card-network test card numbers (PCI engine).', content: pci },
    { name: 'zscaler-pov-SSN-test.csv', type: 'text/csv', description: 'Synthetic Social Security numbers (SSN dictionary).', content: ssn }
  ];
}

module.exports = { TESTS, PROVE, runbook, proveUrl, insights, dlpKit };
