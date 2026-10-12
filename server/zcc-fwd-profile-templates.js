/**
 * ZCC Forwarding Profile templates (v1.7.0)
 *
 * BEST_PRACTICE = the "Windows" forwarding profile on the ZTH tenant (ID 36531), captured 2026-10-11.
 * Each setting is one thing that profile does differently from a forwarding profile the
 * Mobile Admin portal creates with defaults. Proven by creating a clone through the public
 * API (POST /webForwardingProfile/edit with id "-1") and diffing it against 36531: zero differences.
 *
 * Network types in forwardingProfileActions / forwardingProfileZpaActions:
 *   0 = On-Trusted, 1 = VPN-Trusted, 2 = Off-Trusted, 3 = Split VPN-Trusted
 * ZIA actionType: 0 = None, 1 = Tunnel, 2 = Tunnel with Local Proxy (portal default), 3 = Enforce Proxy
 * ZPA actionType: 0 = None, 1 = Tunnel
 *
 * Setting shape matches zcc-app-profile-templates.js: key, label, category, description,
 * value, portalDefault, impact, apply(body), verify(storedProfile).
 */

const NETWORKS = [
  { type: 0, label: 'On-Trusted' },
  { type: 1, label: 'VPN-Trusted' },
  { type: 2, label: 'Off-Trusted' },
  { type: 3, label: 'Split VPN-Trusted' }
];
const num = (v) => Number(v);
const zia = (b) => b.forwardingProfileActions || [];
const zpa = (b) => b.forwardingProfileZpaActions || [];
const all = (list, fn) => list.length === NETWORKS.length && list.every(fn);

const WINDOWS_FWD_SETTINGS = [
  {
    key: 'ziaTunnel',
    label: 'ZIA action: Tunnel on every network',
    category: 'ZIA Forwarding',
    description: 'Client Connector tunnels internet traffic to ZIA (Z-Tunnel 2.0 packet tunnel) on On-Trusted, VPN-Trusted, Off-Trusted and Split VPN-Trusted networks.',
    value: 'Tunnel (all 4 network types)', portalDefault: 'Tunnel with Local Proxy', impact: 'info',
    apply: (b) => zia(b).forEach(a => { a.actionType = 1; a.enablePacketTunnel = 1; }),
    verify: (p) => all(zia(p), a => num(a.actionType) === 1 && num(a.enablePacketTunnel) === 1)
  },
  {
    key: 'redirectWebTraffic',
    label: 'Redirect Web Traffic to Client Connector Listening Proxy',
    category: 'ZIA Forwarding',
    description: 'Web traffic that apps send to a proxy is redirected into Client Connector, so proxy-aware apps are still inspected.',
    value: 'On (all networks)', portalDefault: 'Off', impact: 'info',
    apply: (b) => zia(b).forEach(a => { a.redirectWebTraffic = 1; }),
    verify: (p) => all(zia(p), a => num(a.redirectWebTraffic) === 1)
  },
  {
    key: 'tunnel2ForProxied',
    label: 'Use Z-Tunnel 2.0 for Proxied Web Traffic',
    category: 'ZIA Forwarding',
    description: 'Proxied web traffic is sent through the Z-Tunnel 2.0 tunnel instead of Z-Tunnel 1.0.',
    value: 'On (all networks)', portalDefault: 'Off', impact: 'info',
    apply: (b) => zia(b).forEach(a => { a.useTunnel2ForProxiedWebTraffic = 1; }),
    verify: (p) => all(zia(p), a => num(a.useTunnel2ForProxiedWebTraffic) === 1)
  },
  {
    key: 'dropIpv6',
    label: 'Drop IPv6 Traffic',
    category: 'ZIA Forwarding',
    description: 'Drops IPv6 traffic, including on IPv6-only networks, so it cannot bypass the tunnel. Can break IPv6-only destinations.',
    value: 'On, including IPv6-only networks', portalDefault: 'Off', impact: 'caution',
    apply: (b) => zia(b).forEach(a => { a.dropIpv6Traffic = 1; a.dropIpv6TrafficInIpv6Network = 1; }),
    verify: (p) => all(zia(p), a => num(a.dropIpv6Traffic) === 1 && num(a.dropIpv6TrafficInIpv6Network) === 1)
  },
  {
    key: 'latencyBasedZen',
    label: 'Latency-Based ZEN Selection',
    category: 'ZIA Forwarding',
    description: 'Client Connector probes nearby Zscaler service edges (every 60 s, 5 samples) and moves to a faster one when latency rises.',
    value: 'On (60 s interval, 5 samples, threshold 2)', portalDefault: 'Off', impact: 'info',
    apply: (b) => zia(b).forEach(a => { a.latencyBasedZenEnablement = 1; }),
    verify: (p) => all(zia(p), a => num(a.latencyBasedZenEnablement) === 1)
  },
  {
    key: 'noSystemPac',
    label: 'System Proxy: no automatic configuration script',
    category: 'ZIA Forwarding',
    description: 'Client Connector does not push a PAC script into the system proxy settings. With Tunnel mode the tunnel carries the traffic, so the PAC is not needed.',
    value: 'Enforce, PAC off', portalDefault: 'Enforce, "Use automatic configuration script" on', impact: 'info',
    apply: (b) => zia(b).forEach(a => { a.systemProxy = 0; a.systemProxyData.enablePAC = 0; }),
    verify: (p) => all(zia(p), a => num(a.systemProxy) === 0 && num(a.systemProxyData?.enablePAC) === 0)
  },
  {
    key: 'zpaVpnTrusted',
    label: 'ZPA: Tunnel on VPN-Trusted networks',
    category: 'ZPA Forwarding',
    description: 'Private-app traffic still goes through ZPA when the device is on a trusted VPN. The portal default sends nothing to ZPA on VPN-Trusted networks.',
    value: 'Tunnel', portalDefault: 'None', impact: 'info',
    apply: (b) => zpa(b).filter(a => num(a.networkType) === 1).forEach(a => { a.actionType = 1; a.isSameAsOnTrustedNetwork = false; }),
    verify: (p) => zpa(p).some(a => num(a.networkType) === 1 && num(a.actionType) === 1)
  },
  {
    key: 'zpaLatencyServer',
    label: 'ZPA Latency-Based Server Selection',
    category: 'ZPA Forwarding',
    description: 'Client Connector picks the ZPA service edge with the lowest latency (including for Microtenants) instead of the closest by geography.',
    value: 'On (all networks)', portalDefault: 'Off', impact: 'info',
    apply: (b) => zpa(b).forEach(a => { a.latencyBasedServerEnablement = 1; a.latencyBasedServerMTEnablement = 1; }),
    verify: (p) => all(zpa(p), a => num(a.latencyBasedServerEnablement) === 1 && num(a.latencyBasedServerMTEnablement) === 1)
  }
];

const FWD_TEMPLATES = {
  BEST_PRACTICE: {
    id: 'BEST_PRACTICE', name: 'Zscaler POV Best Practice', icon: '⭐',
    description: 'Forwarding settings from the Zscaler POV best practice guide: tunnel to ZIA on every network, listening-proxy redirect, Z-Tunnel 2.0 for proxied traffic, drop IPv6, latency-based ZEN, no system PAC, ZPA on VPN-Trusted networks, ZPA latency-based server selection.',
    source: 'Zscaler POV best practice guide',
    // The reference profile also has "Predefined Trusted Networks" ticked with none selected (no effect).
    baseApply: (b) => { b.predefinedTrustedNetworks = true; },
    settings: WINDOWS_FWD_SETTINGS
  },
  PORTAL_DEFAULT: {
    id: 'PORTAL_DEFAULT', name: 'Portal Default (blank)', icon: '📄',
    description: 'Exactly what the Mobile Admin portal creates when you click Add Forwarding Profile and save without changes: Tunnel with Local Proxy for ZIA, ZPA tunnel except on VPN-Trusted networks.',
    source: 'Mobile Admin portal defaults (captured 2026-10-11)',
    settings: []
  }
};

const BODY = require('./zcc-fwd-profile-template.json');

function getFwdTemplate(templateId) {
  const t = FWD_TEMPLATES[templateId || 'BEST_PRACTICE'];
  if (!t) throw new Error(`Unknown forwarding profile template: ${templateId}`);
  return t;
}

function getFwdTemplateCatalog() {
  return Object.values(FWD_TEMPLATES).map(t => ({
    id: t.id, name: t.name, icon: t.icon, description: t.description, source: t.source,
    settings: t.settings.map(({ apply, verify, ...meta }) => meta)
  }));
}

function selectedFwdSettings(templateId, enabledKeys) {
  const t = getFwdTemplate(templateId);
  if (!Array.isArray(enabledKeys)) return t.settings;
  const set = new Set(enabledKeys);
  return t.settings.filter(s => set.has(s.key));
}

/** Full portal-shaped create body (id "-1" = create). Returns { body, applied }. */
function buildForwardingProfileBody({ name, templateId = 'BEST_PRACTICE', enabledSettings = null }) {
  if (!name || !String(name).trim()) throw new Error('Forwarding profile name is required');
  const body = JSON.parse(JSON.stringify(BODY));
  body.id = '-1';
  body.name = String(name).trim();
  const tpl = getFwdTemplate(templateId);
  if (tpl.baseApply) tpl.baseApply(body);
  const applied = selectedFwdSettings(templateId, enabledSettings);
  for (const s of applied) s.apply(body);
  return { body, applied };
}

module.exports = { NETWORKS, FWD_TEMPLATES, getFwdTemplate, getFwdTemplateCatalog, selectedFwdSettings, buildForwardingProfileBody };
