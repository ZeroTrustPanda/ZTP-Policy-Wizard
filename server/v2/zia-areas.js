/**
 * Policy areas added in 2.0 (FWK-08): Sandbox Standard/Advanced (§1.4), inline DLP Monitor/Block (SCP-10/11, §2.2),
 * Endpoint DLP (SCP-12), AI Prompt Capture (§1.5) and ATP defaults (SCP-19).
 * Each generator returns plain "desired object" descriptions; the engine (zia-engine.js) turns them into API calls.
 */
const DICTS = require('../frameworks/dlp-dictionaries.json');

// ---------- Sandbox (§1.4) ----------
// File-type categories Zscaler Cloud Sandbox rules accept (seen on live tenants and in 1.9 builds).
const SANDBOX_SUPPORTED = new Set([
  'FTCATEGORY_WINDOWS_EXECUTABLES', 'FTCATEGORY_WINDOWS_LIBRARY', 'FTCATEGORY_MICROSOFT_INSTALLER', 'FTCATEGORY_APK',
  'FTCATEGORY_POWERSHELL', 'FTCATEGORY_BAT', 'FTCATEGORY_VISUAL_BASIC_SCRIPT', 'FTCATEGORY_WINDOWS_SCRIPT_FILES', 'FTCATEGORY_HTA',
  'FTCATEGORY_PYTHON', 'FTCATEGORY_JAVA_APPLET', 'FTCATEGORY_FLASH', 'FTCATEGORY_ISO', 'FTCATEGORY_DMG',
  'FTCATEGORY_ZIP', 'FTCATEGORY_RAR', 'FTCATEGORY_P7Z', 'FTCATEGORY_TAR', 'FTCATEGORY_BZIP2', 'FTCATEGORY_SCZIP',
  'FTCATEGORY_MS_WORD', 'FTCATEGORY_MS_EXCEL', 'FTCATEGORY_MS_POWERPOINT', 'FTCATEGORY_MS_RTF', 'FTCATEGORY_PDF_DOCUMENT'
]);
const SANDBOX_PROTOCOLS = ['FOHTTP_RULE', 'FTP_RULE', 'HTTPS_RULE', 'HTTP_RULE'];
const SANDBOX_CATEGORIES = ['ADWARE_BLOCK', 'BOTMAL_BLOCK', 'ANONYP2P_BLOCK', 'RANSOMWARE_BLOCK', 'OFFSEC_TOOLS_BLOCK', 'SUSPICIOUS_BLOCK'];

// Draft risk tiers (OQ-7: user to confirm). Types the sandbox does not support are dropped and listed (SCP-43).
const SANDBOX_ADVANCED_GROUPS = [
  { key: 'Executables', label: 'Executables and installers (exe, dll, msi, scr, apk)', tier: 'high',
    types: ['FTCATEGORY_WINDOWS_EXECUTABLES', 'FTCATEGORY_WINDOWS_LIBRARY', 'FTCATEGORY_MICROSOFT_INSTALLER', 'FTCATEGORY_APK'] },
  { key: 'Scripts', label: 'Scripts (ps1, bat/cmd, vbs, wsf, hta, py, standalone js)', tier: 'high',
    types: ['FTCATEGORY_POWERSHELL', 'FTCATEGORY_BAT', 'FTCATEGORY_VISUAL_BASIC_SCRIPT', 'FTCATEGORY_WINDOWS_SCRIPT_FILES', 'FTCATEGORY_HTA', 'FTCATEGORY_PYTHON', 'FTCATEGORY_JAVASCRIPT'] },
  { key: 'Java-Flash', label: 'Java and Flash (jar, swf)', tier: 'high', types: ['FTCATEGORY_JAVA_APPLET', 'FTCATEGORY_FLASH'] },
  { key: 'DiskImg-Lnk', label: 'Disk images and shortcuts (iso, img, dmg, lnk)', tier: 'high', types: ['FTCATEGORY_ISO', 'FTCATEGORY_DMG', 'FTCATEGORY_IMG', 'FTCATEGORY_LNK'] },
  { key: 'Archives', label: 'Archives (zip, rar, 7z, tar, gz, bz2)', tier: 'high',
    types: ['FTCATEGORY_ZIP', 'FTCATEGORY_RAR', 'FTCATEGORY_P7Z', 'FTCATEGORY_TAR', 'FTCATEGORY_GZIP', 'FTCATEGORY_BZIP2', 'FTCATEGORY_SCZIP'] },
  { key: 'Office', label: 'Office documents (Word, Excel, PowerPoint — the categories include macro-capable docm/xlsm/pptm and legacy doc/xls/ppt)', tier: 'high',
    types: ['FTCATEGORY_MS_WORD', 'FTCATEGORY_MS_EXCEL', 'FTCATEGORY_MS_POWERPOINT'],
    note: 'Zscaler file-type categories do not separate macro-enabled from macro-free Office files, so all Word / Excel / PowerPoint files follow the high-risk action.' },
  { key: 'PDF', label: 'PDF', tier: 'high', types: ['FTCATEGORY_PDF_DOCUMENT'] },
  { key: 'LowRisk', label: 'Lower-risk documents (rtf, txt, csv, images)', tier: 'low',
    types: ['FTCATEGORY_MS_RTF', 'FTCATEGORY_TEXT', 'FTCATEGORY_CSV', 'FTCATEGORY_BITMAP', 'FTCATEGORY_JPEG', 'FTCATEGORY_PNG', 'FTCATEGORY_GIF'] }
];

function sandboxRules(prefix, mode) {
  const dropped = [];
  const rule = (suffix, label, types, firstTimeOperation, mlActionEnabled, note) => {
    const keep = types.filter(t => SANDBOX_SUPPORTED.has(t));
    const gone = types.filter(t => !SANDBOX_SUPPORTED.has(t));
    if (gone.length) dropped.push(`${prefix}-SBX-${suffix}: not supported by Cloud Sandbox, left out: ${gone.map(t => t.replace('FTCATEGORY_', '')).join(', ')}`);
    if (!keep.length) return null;
    return {
      name: `${prefix}-SBX-${suffix}`, actionKey: `sandbox:SBX-${suffix}`, state: 'ENABLED',
      description: `${label}. First-time action: ${firstTimeOperation === 'QUARANTINE' ? 'Quarantine' : 'Allow and Scan'}${mlActionEnabled ? '; AI Instant Verdict on' : ''}.${note ? ' ' + note : ''}`,
      fileTypes: keep, protocols: SANDBOX_PROTOCOLS, baPolicyCategories: SANDBOX_CATEGORIES, baRuleAction: 'BLOCK',
      firstTimeEnable: true, firstTimeOperation, mlActionEnabled, sandboxMode: mode
    };
  };
  let rules;
  if (mode === 'standard') {
    rules = [rule('Std-Exe-Dll', 'Standard: Windows executables (.exe) and libraries (.dll)', ['FTCATEGORY_WINDOWS_EXECUTABLES', 'FTCATEGORY_WINDOWS_LIBRARY'], 'ALLOW_SCAN', false)];
  } else {
    rules = SANDBOX_ADVANCED_GROUPS.map(g => rule(`Adv-${g.key}`, g.label, g.types, g.tier === 'high' ? 'QUARANTINE' : 'ALLOW_SCAN', true, g.note));
  }
  return { rules: rules.filter(Boolean), notes: dropped };
}

// ---------- Advanced Threat Protection (SCP-19) ----------
const MALWARE_TO_ATP = {
  commandAndControlServers: 'cmdCtlServerBlocked', commandAndControlTraffic: 'cmdCtlTrafficBlocked',
  maliciousContent: 'malwareSitesBlocked', vulnerableActiveX: 'activeXBlocked', browserExploits: 'browserExploitsBlocked',
  fileFormatVulnerabilities: 'fileFormatVunerabilitesBlocked', knownPhishingSites: 'knownPhishingSitesBlocked',
  suspectedPhishingSites: 'suspectedPhishingSitesBlocked', spywareCallback: 'suspectAdwareSpywareSitesBlocked',
  webSpam: 'webspamBlocked', cryptoMining: 'cryptoMiningBlocked', ircTunneling: 'ircTunnellingBlocked',
  anonymizers: 'anonymizerBlocked', cookieStealing: 'cookieStealingBlocked', potentiallyMaliciousRequests: 'potentialMaliciousRequestsBlocked',
  bitTorrent: 'bitTorrentBlocked', tor: 'torBlocked', sshTunneling: 'sshTunnellingBlocked'
};
const ATP_LABELS = {
  cmdCtlServerBlocked: 'Block connections to known Command & Control servers', cmdCtlTrafficBlocked: 'Block botnet Command & Control traffic to unknown servers',
  malwareSitesBlocked: 'Block known malicious / compromised sites and content', activeXBlocked: 'Block vulnerable ActiveX controls',
  browserExploitsBlocked: 'Block known browser exploits', fileFormatVunerabilitesBlocked: 'Block file format vulnerabilities (Office / PDF)',
  knownPhishingSitesBlocked: 'Block known phishing sites', suspectedPhishingSitesBlocked: 'Block suspected phishing sites (heuristics)',
  suspectAdwareSpywareSitesBlocked: 'Block spyware callback traffic', webspamBlocked: 'Block web spam', cryptoMiningBlocked: 'Block cryptomining',
  ircTunnellingBlocked: 'Block IRC tunnelling', anonymizerBlocked: 'Block anonymizers', cookieStealingBlocked: 'Block cookie stealing',
  potentialMaliciousRequestsBlocked: 'Block cross-site scripting (XSS) requests', bitTorrentBlocked: 'Block BitTorrent (P2P)',
  torBlocked: 'Block Tor (P2P anonymizer)', sshTunnellingBlocked: 'Block SSH tunnelling'
};
function atpSettings(malwarePolicy) {
  const s = (malwarePolicy && malwarePolicy.settings) || {};
  const out = [];
  for (const [k, field] of Object.entries(MALWARE_TO_ATP)) {
    // Baselines that don't mention a setting default to Block (ATP defaults, SCP-19)
    const value = s[k] === undefined ? true : s[k] === 'BLOCK';
    out.push({ key: field, label: ATP_LABELS[field], value });
  }
  return out;
}

// ---------- AI Prompt Capture (§1.5, fixed list SCP-50) ----------
const AI_PROMPT_APPS = [
  { key: 'enableChatGptPrompt', label: 'ChatGPT', group: 'genai' },
  { key: 'enableMicrosoftCoPilotPrompt', label: 'Microsoft Copilot', group: 'genai' },
  { key: 'enableGeminiPrompt', label: 'Gemini', group: 'genai' },
  { key: 'enablePerPlexityPrompt', label: 'Perplexity', group: 'genai' },
  { key: 'enablePOEPrompt', label: 'Poe', group: 'genai' },
  { key: 'enableMetaPrompt', label: 'Meta AI', group: 'genai' },
  { key: 'enableWriterPrompt', label: 'WRITER', group: 'genai' },
  { key: 'enableDeepSeekPrompt', label: 'DeepSeek', group: 'genai' },
  { key: 'enableGrokPrompt', label: 'Grok AI', group: 'genai' },
  { key: 'enableClaudePrompt', label: 'Claude', group: 'genai' },
  { key: 'enableMistralAIPrompt', label: 'Mistral', group: 'genai' },
  { key: 'enableGrammarlyPrompt', label: 'Grammarly', group: 'genai' },
  { key: 'enableQuillbotAIPrompt', label: 'QuillBot', group: 'genai' },
  { key: 'enableGoogleAIPrompt', label: 'Google AI', group: 'genai' },
  { key: 'enableUcaasZoom', label: 'Zoom', group: 'ucaas' },
  { key: 'enableUcaasLogMeIn', label: 'GoTo', group: 'ucaas' },
  { key: 'enableUcaasRingCentral', label: 'RingCentral', group: 'ucaas' },
  { key: 'enableUcaasWebex', label: 'Webex', group: 'ucaas' },
  { key: 'enableUcaasTalkdesk', label: 'Talkdesk', group: 'ucaas' }
];

// ---------- DLP (SCP-10/11, §2.2, FWK-20/21/22) ----------
function dlpMonitorRules(prefix, framework) {
  return (framework.dlp.monitorEngines || []).map(engine => ({
    name: `${prefix}-DLP-Mon-${engine}`, actionKey: `dlp:DLP-Mon-${engine}`, state: 'ENABLED', action: 'ALLOW', allowOnly: true,
    engineRef: { predefined: engine },
    description: `Monitor mode: ${framework.name} — Zscaler predefined ${engine} DLP engine. Allow only; incidents are logged.`,
    severity: 'RULE_SEVERITY_MEDIUM'
  }));
}

/** Block mode: dictionaries (custom ones created, predefined reused) → one engine per rule → rule that blocks by default. */
function dlpBlockObjects(prefix, framework) {
  const dictionaries = new Map();
  const engines = [];
  const rules = [];
  for (const br of framework.dlp.blockRules || []) {
    const refs = [];
    for (const d of br.dictionaries) {
      const [kind, key] = d.split(':');
      if (kind === 'custom') {
        const def = DICTS.custom[key];
        if (!def) continue;
        const name = `${prefix}-Dict-${key}`;
        if (!dictionaries.has(name)) dictionaries.set(name, { ...def, label: def.name, key, name });
        refs.push({ custom: name });
      } else refs.push({ predefined: key });
    }
    const engineName = `${prefix}-Eng-${br.key}`;
    engines.push({ name: engineName, dictRefs: refs, description: `Block mode: ${framework.name} — ${br.label}. Created by the Zscaler Policy Wizard.` });
    rules.push({
      name: `${prefix}-DLP-${br.key}`, actionKey: `dlp:DLP-${br.key}`, state: 'ENABLED', action: 'BLOCK', defaultAction: 'BLOCK',
      engineRef: { custom: engineName },
      description: `Block mode: ${framework.name} — ${br.label}. Dictionaries: ${br.dictionaries.map(x => x.split(':')[1]).join(', ')}.`,
      severity: 'RULE_SEVERITY_HIGH', controls: br.controls || []
    });
  }
  return { dictionaries: [...dictionaries.values()], engines, rules };
}

const ENDPOINT_CHANNELS = [
  { key: 'REMOVABLE_DRIVE_TRANSFER', suffix: 'USB', label: 'USB / removable storage' },
  { key: 'PERSONAL_CLOUD_STORAGE', suffix: 'Cloud', label: 'Personal cloud storage' },
  { key: 'PRINTING', suffix: 'Print', label: 'Printing' }
];
function endpointDlpRules(prefix, framework) {
  return ENDPOINT_CHANNELS.filter(c => (framework.dlp.endpointChannels || []).includes(c.key)).map(c => ({
    name: `${prefix}-EDLP-${c.suffix}`, actionKey: `endpointDlp:EDLP-${c.suffix}`, state: 'ENABLED', action: 'ALLOW', allowOnly: true,
    channel: c.key, engineRefs: (framework.dlp.monitorEngines || []).map(e => ({ predefined: e })),
    description: `Endpoint DLP (Monitor) — ${c.label} — ${framework.name}. Windows and macOS.`, severity: 'RULE_SEVERITY_MEDIUM'
  }));
}

module.exports = {
  SANDBOX_SUPPORTED, SANDBOX_PROTOCOLS, SANDBOX_ADVANCED_GROUPS, sandboxRules,
  MALWARE_TO_ATP, ATP_LABELS, atpSettings, AI_PROMPT_APPS,
  dlpMonitorRules, dlpBlockObjects, endpointDlpRules, ENDPOINT_CHANNELS
};
