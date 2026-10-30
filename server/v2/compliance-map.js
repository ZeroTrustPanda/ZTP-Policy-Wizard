/**
 * v2.7: every policy the wizard writes maps to the selected compliance profile's controls, or says why it does not.
 *
 *   rule  → objectives (what the rule achieves: malware protection, data loss prevention, TLS inspection …)
 *   profile.objectives[objective] → that profile's own control ids (server/frameworks/<id>.json, each id in its catalog)
 *
 * A rule whose objectives have no control in the profile gets a reason instead:
 *   best_practice   Zscaler best practice: hardening the profile does not require
 *   differentiator  Differentiating use case shown in the POV (coaching pages, isolation, AI visibility)
 *   operational     Keeps approved business traffic working (allow lists, UCaaS one-click settings)
 *   privacy         Protects user or patient privacy (TLS inspection exemptions)
 *   weakens         Lowers protection; chosen by the permissive baseline
 */
'use strict';

const OBJECTIVES = {
  MALWARE: 'Malicious code protection', THREAT_SITES: 'Block malicious, phishing and risky destinations',
  ACCEPTABLE_USE: 'Acceptable-use content filtering', PRODUCTIVITY: 'Productivity and bandwidth use',
  LEAST_FUNCTION: 'Least functionality (unneeded apps, protocols, file types)', BOUNDARY: 'Boundary protection',
  ALLOW_EXCEPTION: 'Deny by default, allow by exception', INFO_FLOW: 'Information flow to external cloud services',
  DATA_LOSS: 'Prevent sensitive data loss', DATA_MONITOR: 'Monitor and log sensitive data use', MEDIA: 'Removable media, print and personal cloud',
  INSPECT_TLS: 'Inspect encrypted traffic', PRIVACY_EXEMPT: 'Privacy exemption from inspection', DNS: 'Secure, filtered name resolution',
  DNS_TUNNEL: 'DNS tunnel and exfiltration detection', SANDBOX: 'Detonate unknown files', ISOLATION: 'Isolate risky web content',
  MOBILE_CODE: 'Mobile code and browser exploit protection', AI_GOV: 'Generative AI governance', TIME_SYNC: 'Time synchronization',
  REMOTE_ACCESS: 'Least-privilege access to private apps', SESSION: 'Session termination', APP_PROTECT: 'Protect private web apps from attacks'
};

const REASONS = {
  best_practice: 'Zscaler best practice',
  differentiator: 'Differentiating use case',
  operational: 'Operational',
  privacy: 'Privacy',
  weakens: 'Weakens protection'
};

// rule key → { o: objectives, r: reason code when the profile has no control for them, t: one line on why }
const R = (o, r, t) => ({ o, r, t });
const RULES = {
  // URL Filtering
  'urlFiltering:Block-Legal-Liability': R(['ACCEPTABLE_USE'], 'best_practice', 'Acceptable-use filtering (adult, gambling, drugs, violence) lowers legal liability.'),
  'urlFiltering:Block-Privacy-Risk': R(['THREAT_SITES'], 'best_practice', 'Spyware, adware and dynamic DNS sites.'),
  'urlFiltering:Block-Security-Risk': R(['THREAT_SITES', 'LEAST_FUNCTION'], 'best_practice', 'Newly registered and uncategorizable sites, P2P and remote access.'),
  'urlFiltering:Isolate-Misc-Unknown': R(['ISOLATION', 'THREAT_SITES'], 'differentiator', 'Unknown sites open in Cloud Browser Isolation instead of being blocked.'),
  'urlFiltering:Caution-Bandwidth-Loss': R(['PRODUCTIVITY'], 'differentiator', 'Coaching page instead of a hard block.'),
  'urlFiltering:Caution-Productivity-Loss': R(['PRODUCTIVITY'], 'differentiator', 'Coaching page instead of a hard block.'),
  'urlFiltering:Block-Bandwidth-Loss': R(['PRODUCTIVITY'], 'best_practice', 'Streaming and entertainment blocked (strict).'),
  'urlFiltering:Block-Productivity-Loss': R(['PRODUCTIVITY'], 'best_practice', 'Gaming, shopping and social media blocked (strict).'),
  'urlFiltering:Block-Custom-Category': R(['BOUNDARY'], 'best_practice', 'Customer deny list.'),
  'urlFiltering:Block-Security-Globally': R(['THREAT_SITES'], 'best_practice', 'Critical security risk categories.'),
  'urlFiltering:Block-FileHost-Webmail': R(['INFO_FLOW', 'DATA_LOSS'], 'best_practice', 'File hosting and personal webmail.'),
  'urlFiltering:Caution-New-Domains': R(['THREAT_SITES'], 'differentiator', 'Coaching page on newly registered domains.'),
  'urlFiltering:Block-Crypto': R(['LEAST_FUNCTION', 'MALWARE'], 'best_practice', 'Cryptocurrency and mining sites.'),
  'urlFiltering:Block-Remote-Access': R(['LEAST_FUNCTION', 'BOUNDARY'], 'best_practice', 'Unsanctioned remote access tools used in ransomware.'),
  'urlFiltering:Caution-AI': R(['AI_GOV'], 'differentiator', 'Coaching page on unsanctioned AI apps.'),
  'urlFiltering:Block-Translation': R(['DATA_LOSS'], 'best_practice', 'Public translation services where pasted text leaves the organization.'),
  'urlFiltering:Block-P2P': R(['LEAST_FUNCTION', 'DATA_LOSS'], 'best_practice', 'Peer-to-peer sites.'),
  // Cloud App Control
  'cloudAppControl:CAC-FileShare-ViewOnly': R(['INFO_FLOW', 'DATA_LOSS'], 'differentiator', 'Read-only file sharing (download yes, upload no).'),
  'cloudAppControl:CAC-Social-ViewNoPost': R(['INFO_FLOW'], 'differentiator', 'Read social media, no posting.'),
  'cloudAppControl:CAC-LinkedIn-ReadOnly': R(['INFO_FLOW'], 'differentiator', 'LinkedIn read-only.'),
  'cloudAppControl:CAC-GenAI-NoUpload': R(['AI_GOV', 'DATA_LOSS'], 'differentiator', 'AI prompts allowed, file uploads blocked.'),
  'cloudAppControl:CAC-Slack-NoFileUpload': R(['INFO_FLOW', 'DATA_LOSS'], 'differentiator', 'Chat allowed, file uploads blocked.'),
  'cloudAppControl:CAC-Block-DoH': R(['DNS', 'LEAST_FUNCTION'], 'best_practice', 'DNS over HTTPS apps (off by default: DoH is inspected instead).'),
  'cloudAppControl:CAC-Block-FileShare': R(['INFO_FLOW', 'DATA_LOSS'], 'best_practice', 'Unsanctioned file sharing.'),
  'cloudAppControl:CAC-Restrict-IM': R(['INFO_FLOW', 'DATA_LOSS'], 'best_practice', 'File transfer in instant messaging.'),
  'cloudAppControl:CAC-Block-IM': R(['INFO_FLOW', 'LEAST_FUNCTION'], 'best_practice', 'Unsanctioned instant messaging.'),
  'cloudAppControl:CAC-Restrict-Social': R(['INFO_FLOW'], 'best_practice', 'Posting on social apps.'),
  'cloudAppControl:CAC-Block-Webmail': R(['INFO_FLOW', 'DATA_LOSS'], 'best_practice', 'Personal webmail.'),
  'cloudAppControl:CAC-NoUpload-Stream': R(['DATA_LOSS'], 'best_practice', 'Uploads to streaming apps.'),
  'cloudAppControl:CAC-Block-Streaming': R(['PRODUCTIVITY', 'LEAST_FUNCTION'], 'best_practice', 'Streaming media apps.'),
  'cloudAppControl:CAC-Restrict-Collab': R(['INFO_FLOW', 'LEAST_FUNCTION'], 'best_practice', 'Unsanctioned collaboration apps.'),
  'cloudAppControl:CAC-Restrict-AI-ML': R(['AI_GOV'], 'differentiator', 'Coaching page across AI/ML apps.'),
  // File Type Control
  'fileTypeControl:FTC-Block-Database-Upload': R(['DATA_LOSS'], 'best_practice', 'Database file uploads (mass exfiltration).'),
  'fileTypeControl:FTC-Block-Exe-DL': R(['MALWARE', 'LEAST_FUNCTION'], 'best_practice', 'Executable downloads.'),
  'fileTypeControl:FTC-Block-Scripts': R(['MALWARE', 'LEAST_FUNCTION'], 'best_practice', 'Script files.'),
  'fileTypeControl:FTC-Block-PW-Archives': R(['MALWARE', 'DATA_LOSS'], 'best_practice', 'Password-protected archives that cannot be inspected.'),
  // Cloud Firewall
  'firewallFiltering:FW-Geo-Block-Out': R(['BOUNDARY'], 'best_practice', 'Remote administration and file transfer to high-risk countries.'),
  'firewallFiltering:FW-Geo-Block-In': R(['BOUNDARY'], 'best_practice', 'Remote administration and file transfer from high-risk countries.'),
  'firewallFiltering:Block-QUIC': R(['INSPECT_TLS', 'LEAST_FUNCTION'], 'best_practice', 'Forces browsers to TCP so traffic can be inspected.'),
  'firewallFiltering:Allow-Web': R(['ALLOW_EXCEPTION'], 'operational', 'Allows web traffic above the default deny.'),
  'firewallFiltering:Allow-NTP': R(['ALLOW_EXCEPTION', 'TIME_SYNC'], 'operational', 'Allows time synchronization.'),
  'firewallFiltering:Allow-Collab': R(['ALLOW_EXCEPTION'], 'operational', 'Allows approved voice and video.'),
  'firewallFiltering:Allow-Enterprise': R(['ALLOW_EXCEPTION'], 'operational', 'Allows directory, authentication and management services.'),
  'firewallFiltering:Block-P2P': R(['LEAST_FUNCTION'], 'best_practice', 'P2P file sharing.'),
  'firewallFiltering:Block-Tunnels': R(['LEAST_FUNCTION', 'BOUNDARY'], 'best_practice', 'Tunnels and proxy evasion.'),
  'firewallFiltering:Default-Block-All': R(['ALLOW_EXCEPTION', 'BOUNDARY'], 'best_practice', 'Default deny.'),
  // DNS
  'dnsSecurity:DNS-Block-Critical-Tunnels': R(['DNS_TUNNEL', 'DATA_LOSS'], 'best_practice', 'Known malicious DNS tunnels.'),
  'dnsSecurity:DNS-Block-High-Tunnels': R(['DNS_TUNNEL', 'DATA_LOSS'], 'best_practice', 'All DNS tunnel categories.'),
  'dnsSecurity:DNS-DoH-Block-Risky': R(['DNS', 'THREAT_SITES'], 'best_practice', 'Risky lookups over DNS over HTTPS.'),
  'dnsSecurity:DNS-Trusted-Resolver': R(['DNS'], 'best_practice', 'All DNS answered by the Zscaler Trusted Resolver.'),
  // SSL Inspection
  'sslInspection:SSL-Bypass-Health': R(['PRIVACY_EXEMPT'], 'privacy', 'Personal health sites are not decrypted.'),
  'sslInspection:SSL-Bypass-Finance': R(['PRIVACY_EXEMPT'], 'privacy', 'Personal banking sites are not decrypted.'),
  'sslInspection:SSL-Excl-Fin-Hlth-Gov': R(['PRIVACY_EXEMPT'], 'privacy', 'Finance, health and government sites are not decrypted.'),
  'sslInspection:SSL-Inspect-Remaining': R(['INSPECT_TLS'], 'best_practice', 'Inspects the rest; blocks TLS 1.0 and 1.1.'),
  'sslInspection:SSL-Inspect-All': R(['INSPECT_TLS'], 'best_practice', 'Inspects everything below the predefined exemptions.'),
  'sslInspection:SSL-Inspect-Catch-All': R(['INSPECT_TLS'], 'best_practice', 'Inspects the rest; blocks TLS 1.0 and 1.1.'),
  'sslInspection:SSL-No-Inspection': R([], 'weakens', 'No TLS inspection: DLP, sandbox and file type controls cannot see encrypted traffic.'),
  // Advanced Threat Protection settings
  'advancedThreatProtection:cmdCtlServerBlocked': R(['THREAT_SITES', 'MALWARE'], 'best_practice', ''),
  'advancedThreatProtection:cmdCtlTrafficBlocked': R(['THREAT_SITES', 'MALWARE'], 'best_practice', ''),
  'advancedThreatProtection:malwareSitesBlocked': R(['MALWARE', 'THREAT_SITES'], 'best_practice', ''),
  'advancedThreatProtection:activeXBlocked': R(['MOBILE_CODE'], 'best_practice', ''),
  'advancedThreatProtection:browserExploitsBlocked': R(['MOBILE_CODE', 'MALWARE'], 'best_practice', ''),
  'advancedThreatProtection:fileFormatVunerabilitesBlocked': R(['MALWARE'], 'best_practice', ''),
  'advancedThreatProtection:knownPhishingSitesBlocked': R(['THREAT_SITES'], 'best_practice', ''),
  'advancedThreatProtection:suspectedPhishingSitesBlocked': R(['THREAT_SITES'], 'best_practice', ''),
  'advancedThreatProtection:suspectAdwareSpywareSitesBlocked': R(['MALWARE', 'THREAT_SITES'], 'best_practice', ''),
  'advancedThreatProtection:webspamBlocked': R(['THREAT_SITES'], 'best_practice', ''),
  'advancedThreatProtection:cryptoMiningBlocked': R(['MALWARE', 'LEAST_FUNCTION'], 'best_practice', ''),
  'advancedThreatProtection:ircTunnellingBlocked': R(['LEAST_FUNCTION', 'BOUNDARY'], 'best_practice', ''),
  'advancedThreatProtection:anonymizerBlocked': R(['LEAST_FUNCTION', 'BOUNDARY'], 'best_practice', ''),
  'advancedThreatProtection:cookieStealingBlocked': R(['MALWARE', 'THREAT_SITES'], 'best_practice', ''),
  'advancedThreatProtection:potentialMaliciousRequestsBlocked': R(['MOBILE_CODE'], 'best_practice', ''),
  'advancedThreatProtection:bitTorrentBlocked': R(['LEAST_FUNCTION'], 'best_practice', ''),
  'advancedThreatProtection:torBlocked': R(['LEAST_FUNCTION', 'BOUNDARY'], 'best_practice', ''),
  'advancedThreatProtection:sshTunnellingBlocked': R(['LEAST_FUNCTION', 'BOUNDARY'], 'best_practice', ''),
  // v2.8 DLP rules with their own reasons
  'dlp:DLP-Source-Code': R(['DATA_LOSS', 'DATA_MONITOR'], 'differentiator', 'Program source leaving the organization (AI apps, paste sites, personal repositories); monitor by default.'),
  'dlp:DLP-PHI-Bulk': R(['DATA_LOSS'], 'best_practice', 'A bulk export of patient identifiers in one transfer.'),
  'dlp:DLP-PHI-Sensitive': R(['DATA_LOSS'], 'best_practice', 'Specially protected conditions (42 CFR Part 2, psychotherapy notes, HIV, genetic) with a patient identifier.'),
  'dlp:DLP-PHI-Narrative': R(['DATA_LOSS'], 'best_practice', 'Clinical notes with a patient identifier.'),
  'saasDlp:': R(['DATA_LOSS', 'DATA_MONITOR'], 'differentiator', 'Data at rest in sanctioned SaaS apps, scanned out of band by the SaaS Security API; incidents are reported.'),
  'emailDlp:': R(['DATA_LOSS', 'DATA_MONITOR'], 'differentiator', 'Outbound email from the corporate mail service, inspected by Zscaler Email DLP; incidents are logged.'),
  // Endpoint DLP
  'endpointDlp:EDLP-USB': R(['MEDIA'], 'best_practice', 'USB and removable storage.'),
  'endpointDlp:EDLP-Cloud': R(['MEDIA', 'DATA_LOSS'], 'best_practice', 'Personal cloud storage from the endpoint.'),
  'endpointDlp:EDLP-Print': R(['MEDIA'], 'best_practice', 'Printing.')
};
// Families with one entry for every member
const FAMILY = [
  [/^sandbox:/, R(['SANDBOX', 'MALWARE'], 'best_practice', 'Unknown files of this type are detonated before delivery.')],
  [/^dlp:DLP-Mon-/, R(['DATA_MONITOR'], 'differentiator', 'Monitor mode: incidents are logged, nothing is blocked.')],
  [/^dlp:DLP-/, R(['DATA_LOSS'], 'best_practice', 'Blocks the profile\'s sensitive data leaving the organization.')],
  [/^aiPromptCapture:/, R(['DATA_MONITOR', 'AI_GOV'], 'differentiator', 'Captures prompts sent to this AI app for review.')],
  [/^ucaas:/, R([], 'operational', 'Zscaler one-click setting that keeps this voice and video service working through inspection.')]
];
// ZPA policies the wizard creates (for the mapping report)
const ZPA_RULES = {
  accessRule: R(['REMOTE_ACCESS'], 'best_practice', 'Users reach only the published apps; no network access.'),
  timeoutRule: R(['SESSION'], 'best_practice', 'Re-authentication and idle timeout for private apps.'),
  inspectionRule: R(['APP_PROTECT'], 'differentiator', 'OWASP inspection of private web apps (AppProtection).'),
  isolationRule: R(['ISOLATION', 'DATA_LOSS'], 'differentiator', 'Private apps opened in isolation: no download, copy or print.')
};

function ruleSpec(key) {
  if (RULES[key]) return RULES[key];
  if (/^saasDlp:/.test(key)) return RULES['saasDlp:'];
  if (/^emailDlp:/.test(key)) return RULES['emailDlp:'];
  for (const [re, spec] of FAMILY) if (re.test(key)) return spec;
  return null;
}

/** Controls of `fw` for a rule key; DLP block rules use the profile's own per-rule controls. */
function mapRule(fw, key) {
  const spec = ruleSpec(key);
  const catalog = Object.fromEntries((fw.controls || []).map(c => [c.id, c.name]));
  if (!spec) return { objectives: [], controls: [], reason: { code: 'best_practice', label: REASONS.best_practice, text: 'Not yet tagged.' }, unknown: true };
  const ids = [];
  const push = (id) => { if (id && !ids.includes(id)) ids.push(id); };
  const m = /^dlp:DLP-(?!Mon-)(.+)$/.exec(key);
  const br = m && ((fw.dlp && fw.dlp.blockRules) || []).find(b => b.key === m[1]);
  if (br) (br.controls || []).forEach(push);
  for (const o of spec.o) for (const id of ((fw.objectives || {})[o] || [])) push(id);
  const out = { objectives: spec.o.map(o => ({ id: o, label: OBJECTIVES[o] })), controls: ids.map(id => ({ id, name: catalog[id] || id })), why: spec.t || '' };
  if (!ids.length) out.reason = { code: spec.r, label: REASONS[spec.r], text: spec.t || REASONS[spec.r] };
  return out;
}

function mapZpa(fw, kind) {
  const spec = ZPA_RULES[kind];
  if (!spec) return null;
  const catalog = Object.fromEntries((fw.controls || []).map(c => [c.id, c.name]));
  const ids = [...new Set(spec.o.flatMap(o => (fw.objectives || {})[o] || []))];
  const out = { objectives: spec.o.map(o => ({ id: o, label: OBJECTIVES[o] })), controls: ids.map(id => ({ id, name: catalog[id] || id })), why: spec.t };
  if (!ids.length) out.reason = { code: spec.r, label: REASONS[spec.r], text: spec.t };
  return out;
}

module.exports = { OBJECTIVES, REASONS, RULES, ZPA_RULES, ruleSpec, mapRule, mapZpa };
