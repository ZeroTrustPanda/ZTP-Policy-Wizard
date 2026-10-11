/**
 * ZCC App Profile templates (v1.6.0) — Windows and macOS
 *
 * Windows BEST_PRACTICE = the "PerfectPolicy" app profile on the ZTH tenant (ID 230119).
 * macOS   BEST_PRACTICE = the "MAC" app profile on the ZTH tenant (ID 66609).
 * Captured 2026-10-09. Each setting is one thing the reference profile enables beyond a
 * plain portal-default profile. The `apply` mappings were proven by creating a clone
 * through the public API and diffing it against the reference profile.
 *
 * Every setting has:
 *   key          stable id used by the UI and API
 *   label        short name shown in the wizard
 *   category     grouping in the customize / review screens
 *   description  what it does, in plain language
 *   value        human-readable value that will be written
 *   portalDefault  what a profile created with portal defaults has instead
 *   impact       'info' | 'caution' (shown as a warning chip)
 *   apply(body)  mutates the portal-shaped create body
 *   verify(p)    checks a profile read back from GET /application-profiles/{id}
 *   manual       true = the public API does not accept this field; shown as a portal step
 *   appIds       (bypass settings) app service IDs the dry run checks exist in the tenant
 */

const DOMAIN_PROFILE_CONFIG = '{"trusted":0,"vpnTrusted":1,"offTrusted":1,"splitVpnTrusted":1}';

// IP-based app bypass definitions (IDs from GET /webAppService/listByCompany)
const BYPASS_APPS = [
  { id: 3, name: 'Microsoft Teams' },
  { id: 5, name: 'Zoom Meetings' },
  { id: 7, name: 'Microsoft SharePoint' },
  { id: 9, name: 'Microsoft Exchange' },
  { id: 11, name: 'Microsoft 365' },
  { id: 13, name: 'Windows 365 & Azure Virtual Desktop' }
];

const jsonEq = (a, b) => {
  try { return JSON.stringify(typeof a === 'string' ? JSON.parse(a) : a) === JSON.stringify(typeof b === 'string' ? JSON.parse(b) : b); }
  catch (e) { return a === b; }
};
const num = (v) => Number(v);

const WINDOWS_BEST_PRACTICE_SETTINGS = [
  {
    key: 'installSslCert',
    label: 'Install Zscaler SSL Certificate',
    category: 'Security',
    description: 'Client Connector installs the Zscaler root certificate in the Windows certificate store, so SSL inspection works without a separate certificate rollout.',
    value: 'On', portalDefault: 'Off', impact: 'info',
    apply: (b) => { b.windowsPolicy.install_ssl_certs = 1; b.install_ssl_certs = 1; },
    verify: (p) => num(p.install_ssl_certs) === 1
  },
  {
    key: 'wfpDriver',
    label: 'Install Windows Filtering Platform (WFP) Driver',
    category: 'Security',
    description: 'Installs the WFP driver used for packet-level features such as process-based bypasses, flow logging and local packet capture.',
    value: 'On', portalDefault: 'Off', impact: 'info',
    apply: (b) => { b.windowsPolicy.wfpDriver = 1; b.wfpDriver = 1; },
    verify: (p) => num(p.wfpDriver) === 1
  },
  {
    key: 'enableCli',
    label: 'Enable Zscaler CLI',
    category: 'Security',
    description: 'Allows the Client Connector command-line interface on endpoints for troubleshooting. Disable-without-password options stay at their defaults.',
    value: 'On', portalDefault: 'Off', impact: 'info',
    apply: (b) => { b.policyExtension.generateCliPasswordContract.enableCli = true; },
    verify: (p) => p.policyExtension?.generateCliPasswordContract?.enableCli === true
  },
  {
    key: 'prioritizeIPv4',
    label: 'Prioritize IPv4 over IPv6',
    category: 'Network',
    description: 'Client Connector prefers IPv4 when a destination is reachable over both IPv4 and IPv6.',
    value: 'On', portalDefault: 'Off', impact: 'info',
    apply: (b) => { b.windowsPolicy.prioritizeIPv4 = 1; b.prioritizeIPv4 = 1; },
    verify: (p) => num(p.prioritizeIPv4) === 1
  },
  {
    key: 'parallelIpv4Ipv6',
    label: 'Disable Parallel IPv4 and IPv6: explicit value',
    category: 'Network',
    description: 'Sets "Disable Parallel IPv4 and IPv6" to 0, as in PerfectPolicy, instead of -1 ("Default").',
    value: '0', portalDefault: '-1 (Default)', impact: 'info',
    apply: (b) => { b.disableParallelIpv4AndIPv6 = 0; b.disableParallelIpv4andIpv6 = '0'; b.windowsPolicy.disableParallelIpv4andIpv6 = '0'; },
    verify: (p) => num(p.disableParallelIpv4AndIPv6) === 0
  },
  {
    key: 'domainProfileDetection',
    label: 'Trigger Domain Profile Detection',
    category: 'Network',
    description: 'Triggers Windows domain network profile detection on VPN-trusted, off-trusted and split-VPN networks (not on trusted networks).',
    value: 'On: VPN-trusted, off-trusted, split-VPN', portalDefault: 'Off', impact: 'info',
    apply: (b) => {
      b.windowsPolicy.triggerDomainProfleDetection = 1; b.triggerDomainProfleDetection = 1;
      b.windowsPolicy.domainProfileDetectionConfig = DOMAIN_PROFILE_CONFIG;
    },
    verify: (p) => num(p.triggerDomainProfleDetection) === 1 && jsonEq(p.domainProfileDetectionConfig, DOMAIN_PROFILE_CONFIG)
  },
  {
    key: 'dnsIncludeAll',
    label: 'Domain Inclusions: all domains (*)',
    category: 'Network',
    description: 'Z-Tunnel 2.0 domain inclusion list set to "*", so DNS for all domains is handled by Client Connector.',
    value: '*', portalDefault: '(empty)', impact: 'info',
    apply: (b) => { b.policyExtension.packetTunnelDnsIncludeList = '*'; b.packetTunnelDnsIncludeList = ['*']; },
    verify: (p) => p.policyExtension?.packetTunnelDnsIncludeList === '*'
  },
  {
    key: 'appBypass',
    label: 'Bypass IP-based Applications',
    category: 'Network',
    description: 'Traffic to the published IP ranges of these apps bypasses the tunnel and goes direct: ' + BYPASS_APPS.map(a => a.name).join(', ') + '.',
    value: BYPASS_APPS.map(a => a.name).join(', '), portalDefault: 'None', impact: 'caution',
    appIds: BYPASS_APPS.map(a => a.id),
    apply: (b) => { b.appServiceIds = BYPASS_APPS.map(a => a.id); },
    verify: (p) => {
      const got = (p.appServiceIds || []).map(String).sort();
      const want = BYPASS_APPS.map(a => String(a.id)).sort();
      return JSON.stringify(got) === JSON.stringify(want);
    }
  },
  {
    key: 'notificationFramework',
    label: 'Use Zscaler Notification Framework',
    category: 'User Experience',
    description: 'Enables the Zscaler Notification Framework for Client Connector notifications.',
    value: 'On', portalDefault: 'Off', impact: 'info',
    apply: (b) => { b.policyExtension.useZscalerNotificationFramework = '1'; },
    verify: (p) => String(p.policyExtension?.useZscalerNotificationFramework) === '1'
  },
  {
    key: 'switchFocus',
    label: 'Switch Focus to Notification',
    category: 'User Experience',
    description: 'Brings Client Connector notifications to the front so users see them.',
    value: 'On', portalDefault: 'Off', impact: 'info',
    apply: (b) => { b.policyExtension.switchFocusToNotification = '1'; },
    verify: (p) => String(p.policyExtension?.switchFocusToNotification) === '1'
  },
  {
    key: 'zpaReauthNotice',
    label: 'ZPA Reauthentication Advance Notice (30 min)',
    category: 'User Experience',
    description: 'Warns users 30 minutes before their ZPA authentication expires so they can re-authenticate before access drops.',
    value: 'On, 30 minutes', portalDefault: 'Off', impact: 'info',
    apply: (b) => { b.policyExtension.advanceZpaReauth = true; b.policyExtension.advanceZpaReauthTime = 30; },
    verify: (p) => p.policyExtension?.advanceZpaReauth === true && num(p.policyExtension?.advanceZpaReauthTime) === 30
  },
  {
    key: 'allUsers',
    label: 'Apply to All Users',
    category: 'Assignment',
    description: 'The profile matches every user (no group or user scoping). Combined with "Enable profile", it takes effect for anyone who reaches this rule order.',
    value: 'All users', portalDefault: 'No users/groups', impact: 'caution',
    apply: (b) => { b.groupAll = 1; },
    verify: (p) => num(p.groupAll) === 1
  }
];

// ========================
// macOS — reference profile "MAC" (ID 66609)
// ========================
const MAC_BYPASS_APPS = BYPASS_APPS.filter(a => [3, 5, 13].includes(a.id));
const MAC_PAC_URL = 'https://pac.zscaler.net/zscaler.net/recommended.pac';
const sameIds = (got, want) => JSON.stringify((got || []).map(String).sort()) === JSON.stringify(want.map(String).sort());

const MAC_BEST_PRACTICE_SETTINGS = [
  {
    key: 'installSslCert',
    label: 'Install Zscaler SSL Certificate',
    category: 'Security',
    description: 'Client Connector installs the Zscaler root certificate in the macOS keychain, so SSL inspection works without a separate certificate rollout.',
    value: 'On', portalDefault: 'Off', impact: 'info',
    apply: (b) => { b.macPolicy.install_ssl_certs = 1; b.install_ssl_certs = 1; },
    verify: (p) => num(p.install_ssl_certs) === 1
  },
  {
    key: 'blockPrivateRelay',
    label: 'Block iCloud Private Relay',
    category: 'Security',
    description: 'Blocks Apple iCloud Private Relay, which would otherwise carry Safari traffic around the Zscaler tunnel.',
    value: 'On', portalDefault: 'Off', impact: 'info',
    apply: (b) => { b.policyExtension.blockPrivateRelay = '1'; b.blockPrivateRelay = '1'; },
    verify: (p) => String(p.policyExtension?.blockPrivateRelay) === '1'
  },
  {
    key: 'failCloseTunnelExit',
    label: 'Fail-close on tunnel process exit: Off',
    category: 'Security',
    description: 'Does not lock down traffic when the Client Connector tunnel process exits (MAC value). The portal default locks traffic down.',
    value: 'Off (no lockdown)', portalDefault: 'On (lockdown)', impact: 'caution',
    apply: (b) => { b.policyExtension.zccFailCloseSettingsLockdownOnTunnelProcessExit = '0'; b.zccFailCloseSettingsLockdownOnTunnelProcessExit = 0; },
    verify: (p) => num(p.policyExtension?.zccFailCloseSettingsLockdownOnTunnelProcessExit) === 0
  },
  {
    key: 'pacUrl',
    label: 'App Profile PAC URL: Zscaler recommended',
    category: 'Network',
    description: 'Uses the Zscaler-hosted recommended PAC file for this app profile.',
    value: MAC_PAC_URL, portalDefault: '(none)', impact: 'info',
    apply: (b) => { b.pac_url = MAC_PAC_URL; },
    verify: (p) => p.pac_url === MAC_PAC_URL
  },
  {
    key: 'dnsIncludeAll',
    label: 'Domain Inclusions: all domains (*)',
    category: 'Network',
    description: 'Z-Tunnel 2.0 domain inclusion list set to "*", so DNS for all domains is handled by Client Connector.',
    value: '*', portalDefault: '(empty)', impact: 'info',
    apply: (b) => { b.policyExtension.packetTunnelDnsIncludeList = '*'; b.packetTunnelDnsIncludeList = ['*']; },
    verify: (p) => p.policyExtension?.packetTunnelDnsIncludeList === '*'
  },
  {
    key: 'prioritizeDnsExclusionsOff',
    label: 'Prioritize DNS Exclusions: Off',
    category: 'Network',
    description: 'DNS exclusions do not take priority over inclusions (MAC value). The portal default prioritizes exclusions.',
    value: 'Off', portalDefault: 'On', impact: 'info',
    apply: (b) => { b.policyExtension.prioritizeDnsExclusions = 0; b.prioritizeDnsExclusions = '0'; },
    verify: (p) => num(p.policyExtension?.prioritizeDnsExclusions) === 0
  },
  {
    key: 'flowBasedTunnel',
    label: 'Enable Flow-Based Tunnel',
    category: 'Network',
    description: 'Turns on the flow-based tunnel option, as in the MAC reference profile.',
    value: 'On', portalDefault: 'Off', impact: 'info',
    apply: (b) => { b.policyExtension.enableFlowBasedTunnel = '1'; },
    verify: (p) => num(p.policyExtension?.enableFlowBasedTunnel) === 1
  },
  {
    key: 'reconnectOnWake',
    label: 'Reconnect Tunnel on System Wakeup',
    category: 'Network',
    description: 'Re-establishes the tunnel as soon as the Mac wakes from sleep.',
    value: 'On', portalDefault: 'Off', impact: 'info',
    apply: (b) => { b.policyExtension.reconnectTunOnWakeup = '1'; },
    verify: (p) => num(p.policyExtension?.reconnectTunOnWakeup) === 1
  },
  {
    key: 'appBypass',
    label: 'Bypass IP-based Applications',
    category: 'Network',
    description: 'Traffic to the published IP ranges of these apps bypasses the tunnel and goes direct: ' + MAC_BYPASS_APPS.map(a => a.name).join(', ') + '.',
    value: MAC_BYPASS_APPS.map(a => a.name).join(', '), portalDefault: 'None', impact: 'caution',
    appIds: MAC_BYPASS_APPS.map(a => a.id),
    apply: (b) => { b.appServiceIds = MAC_BYPASS_APPS.map(a => a.id); },
    verify: (p) => sameIds(p.appServiceIds, MAC_BYPASS_APPS.map(a => a.id))
  },
  {
    key: 'notificationFramework',
    label: 'Use Zscaler Notification Framework',
    category: 'User Experience',
    description: 'Enables the Zscaler Notification Framework for Client Connector notifications.',
    value: 'On', portalDefault: 'Off', impact: 'info',
    apply: (b) => { b.policyExtension.useZscalerNotificationFramework = '1'; },
    verify: (p) => String(p.policyExtension?.useZscalerNotificationFramework) === '1'
  },
  {
    key: 'switchFocus',
    label: 'Switch Focus to Notification',
    category: 'User Experience',
    description: 'Brings Client Connector notifications to the front so users see them.',
    value: 'On', portalDefault: 'Off', impact: 'info',
    apply: (b) => { b.policyExtension.switchFocusToNotification = '1'; },
    verify: (p) => String(p.policyExtension?.switchFocusToNotification) === '1'
  },
  {
    key: 'notificationTemplate',
    label: 'Notification Template (ID 2221)',
    category: 'User Experience',
    description: 'Uses the tenant notification template 2221 (as MAC does) instead of the legacy notification settings. Template IDs are tenant-specific.',
    value: 'Template 2221', portalDefault: 'Legacy Notification Settings', impact: 'info',
    apply: (b) => { b.notificationTemplateId = 2221; b.notificationTemplateSelected = [{ label: '2221', value: 2221 }]; },
    verify: (p) => num(p.notificationTemplateContract?.id ?? p.notificationTemplateId) === 2221
  },
  {
    key: 'reactivateZia',
    label: 'Re-enable Internet Security After 60 Minutes',
    category: 'User Experience',
    description: 'If a user turns off Internet Security, Client Connector turns it back on after 60 minutes.',
    value: '60 minutes', portalDefault: 'Never (0)', impact: 'info',
    apply: (b) => { b.reactivateWebSecurityMinutes = '60'; },
    verify: (p) => num(p.reactivateWebSecurityMinutes) === 60
  },
  {
    key: 'modernUi',
    label: 'Client Connector UI: Modern UI Experience',
    category: 'User Experience',
    description: 'MAC uses the Modern UI. The public API ignores this field on create, update and PATCH (verified 2026-10-09), so set it in the Mobile Admin portal after creation.',
    value: 'Modern UI Experience', portalDefault: 'Follow Global Setting', impact: 'info', manual: true,
    apply: (b) => {
      // Sent anyway in case the API starts honouring it; verification treats it as a manual step.
      b.policyExtension.switchToModernUI = 1;
      b.switchToModernUISelected = [{ disabled: false, label: 'Modern UI Experience', selected: false, value: '1' }];
    },
    verify: () => true
  },
  {
    key: 'localPacketCapture',
    label: 'Allow Local Packet Capture',
    category: 'Troubleshooting',
    description: 'Lets users or support start a local packet capture from Client Connector.',
    value: 'On', portalDefault: 'Off', impact: 'info',
    apply: (b) => { b.policyExtension.enableLocalPacketCapture = '1'; b.enableLocalPacketCapture = '1'; b.policyExtension.enableLocalPacketCaptureV2 = 1; },
    verify: (p) => String(p.policyExtension?.enableLocalPacketCapture) === '1'
  },
  {
    key: 'packetCaptureExtrasOff',
    label: 'Automatic Packet Capture Extras: Off',
    category: 'Troubleshooting',
    description: 'Turns off automatic packet capture for critical and other sections and the extra capture disk space (MAC values).',
    value: 'Off', portalDefault: 'On (512 MB extra space)', impact: 'info',
    apply: (b) => {
      for (const k of ['enableAPCforCriticalSections', 'enableAPCforOtherSections', 'enablePCAdditionalSpace']) { b.policyExtension[k] = '0'; b[k] = '0'; }
      b.policyExtension.pcAdditionalSpace = '0'; b.pcAdditionalSpace = [];
    },
    verify: (p) => ['enableAPCforCriticalSections', 'enableAPCforOtherSections', 'enablePCAdditionalSpace', 'pcAdditionalSpace']
      .every(k => num(p.policyExtension?.[k]) === 0)
  },
  {
    key: 'allUsers',
    label: 'Apply to All Users',
    category: 'Assignment',
    description: 'The profile matches every user (no group or user scoping). Combined with "Enable profile", it takes effect for anyone who reaches this rule order.',
    value: 'All users', portalDefault: 'No users/groups', impact: 'caution',
    apply: (b) => { b.groupAll = 1; },
    verify: (p) => num(p.groupAll) === 1
  }
];

// ========================
// Platforms and templates
// ========================
const PLATFORMS = {
  windows: { id: 'windows', label: 'Windows', icon: '🪟', deviceType: 3, policyKey: 'windowsPolicy', bodyFile: './zcc-windows-profile-template.json' },
  macos:   { id: 'macos',   label: 'macOS',   icon: '🍎', deviceType: 4, policyKey: 'macPolicy',     bodyFile: './zcc-mac-profile-template.json' }
};

const TEMPLATES = {
  windows: {
    BEST_PRACTICE: {
      id: 'BEST_PRACTICE', name: 'ZTP Best Practice (PerfectPolicy)', icon: '⭐',
      description: 'Everything enabled in the PerfectPolicy reference profile: SSL cert + WFP driver, Microsoft 365/Teams/Zoom/AVD IP bypass, domain profile detection, notification framework, ZPA reauth notice, CLI, applies to all users.',
      source: 'PerfectPolicy (ZTH tenant, ID 230119)',
      recommendedForwardingProfile: null,
      settings: WINDOWS_BEST_PRACTICE_SETTINGS
    },
    PORTAL_DEFAULT: {
      id: 'PORTAL_DEFAULT', name: 'Portal Default (blank)', icon: '📄',
      description: 'Exactly what the Mobile Admin portal creates when you click Add Windows Policy and save without changes. Use as a clean starting point.',
      source: 'Mobile Admin portal defaults (captured 2026-10-09)',
      recommendedForwardingProfile: null,
      settings: []
    }
  },
  macos: {
    BEST_PRACTICE: {
      id: 'BEST_PRACTICE', name: 'ZTP Best Practice (MAC)', icon: '⭐',
      description: 'Everything enabled in the MAC reference profile: SSL cert, iCloud Private Relay block, recommended PAC, Teams/Zoom/AVD IP bypass, flow-based tunnel, reconnect on wake, notification framework, local packet capture, applies to all users.',
      source: 'MAC (ZTH tenant, ID 66609)',
      recommendedForwardingProfile: { id: 39325, name: 'MAC' },
      // Same values as the portal default, but MAC stores them as strings; keeps the clone byte-identical.
      baseApply: (b) => { b.policyExtension.deleteDHCPOption121Routes = '{"trusted":"1","offTrusted":"1","vpnTrusted":"1","splitVpnTrusted":"1"}'; },
      settings: MAC_BEST_PRACTICE_SETTINGS
    },
    PORTAL_DEFAULT: {
      id: 'PORTAL_DEFAULT', name: 'Portal Default (blank)', icon: '📄',
      description: 'Exactly what the Mobile Admin portal creates when you click Add macOS Policy and save without changes. Use as a clean starting point.',
      source: 'Mobile Admin portal defaults (captured 2026-10-09)',
      recommendedForwardingProfile: null,
      settings: []
    }
  }
};

function getPlatform(platform) {
  const p = PLATFORMS[platform || 'windows'];
  if (!p) throw new Error(`Unsupported platform: ${platform}`);
  return p;
}

/** Catalog for the UI: templates and their settings, without functions. */
function getTemplateCatalog(platform = 'windows') {
  getPlatform(platform);
  return Object.values(TEMPLATES[platform]).map(t => ({
    id: t.id, name: t.name, icon: t.icon, description: t.description, source: t.source,
    recommendedForwardingProfile: t.recommendedForwardingProfile,
    settings: t.settings.map(({ apply, verify, ...meta }) => meta)
  }));
}

function getTemplate(platform, templateId) {
  getPlatform(platform);
  const t = TEMPLATES[platform][templateId || 'BEST_PRACTICE'];
  if (!t) throw new Error(`Unknown ${platform} app profile template: ${templateId}`);
  return t;
}

/** Settings from the template that the user left enabled. */
function selectedSettings(platform, templateId, enabledKeys) {
  const t = getTemplate(platform, templateId);
  if (!Array.isArray(enabledKeys)) return t.settings; // default: everything in the template
  const set = new Set(enabledKeys);
  return t.settings.filter(s => set.has(s.key));
}

module.exports = {
  PLATFORMS,
  TEMPLATES,
  BYPASS_APPS,
  getPlatform,
  getTemplateCatalog,
  getTemplate,
  selectedSettings,
  // v1.6.0 Windows-only aliases
  getWindowsTemplateCatalog: () => getTemplateCatalog('windows')
};
