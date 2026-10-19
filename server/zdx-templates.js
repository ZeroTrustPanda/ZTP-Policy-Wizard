/**
 * ZDX probe templates (v1.8.0)
 *
 * Zscaler POV Best Practice = the probes the Zscaler POV best practice guide turns on first:
 *   - Microsoft Login (Zscaler predefined app, login.microsoftonline.com): Web + CloudPath probes
 *   - zscaler.com (custom app): Web + CloudPath probes
 *
 * Probe bodies mirror what the ZDX portal stores (captured from the ZTH tenant 2026-10-12) and
 * were proven by create -> read back -> delete through the public API.
 */

const PROBE_FREQUENCIES = [300, 600, 900, 1800];          // seconds; ZDX portal default is 5 minutes
const CLOUDPATH_PROTOCOLS = ['ADAPTIVE', 'ICMP', 'TCP', 'UDP'];

const ALL_TARGETS = () => ({
  onUsers: [], excludedUsers: [], onGroups: [], excludedGroups: [], onLocations: [], excludedLocations: [],
  onLocationGroups: [], excludedLocationGroups: [], onGeolocations: [], excludedGeolocations: [],
  onDevices: [], excludedDevices: [], onDepartments: [], excludedDepartments: [], onOsTypes: [], excludedOsTypes: []
}); // empty include/exclude lists = all users

// Friendly text for the predefined apps ZDX supports. Anything not listed still works, using ZDX's own name.
const PREDEFINED_INFO = {
  MICROSOFT_LOGIN: { label: 'Microsoft Login', description: 'Microsoft 365 / Entra ID sign-in page (login.microsoftonline.com). Shows whether users can reach Microsoft authentication quickly.' },
  OUTLOOK: { label: 'Outlook Online', description: 'Outlook on the web (outlook.office365.com).' },
  MICROSOFT_TEAMS: { label: 'Microsoft Teams Web App', description: 'Teams front door (teams.microsoft.com).' },
  SHAREPOINT: { label: 'SharePoint Online', description: 'Your SharePoint tenant (<prefix>.sharepoint.com).' },
  ONEDRIVE: { label: 'OneDrive for Business', description: 'Your OneDrive tenant (<prefix>.sharepoint.com).' },
  ZOOM: { label: 'Zoom', description: 'Your Zoom account (<prefix>.zoom.us).' },
  OKTA: { label: 'Okta', description: 'Your Okta org (<prefix>.okta.com).' },
  BOX: { label: 'Box', description: 'Box web app (app.box.com).' },
  SALESFORCE_CLASSIC: { label: 'Salesforce Classic', description: 'Your Salesforce org (<prefix>.my.salesforce.com).' },
  SALESFORCE_LIGHTENING: { label: 'Salesforce Lightning', description: 'Your Salesforce org (<prefix>.lightning.force.com).' },
  SERVICENOW: { label: 'ServiceNow', description: 'Your ServiceNow instance (<prefix>.service-now.com).' },
  WEBEX: { label: 'Webex', description: 'Your Webex site (<prefix>.webex.com).' }
};

const TEMPLATES = {
  POV_BEST_PRACTICE: {
    id: 'POV_BEST_PRACTICE', name: 'Zscaler POV Best Practice', icon: '⭐',
    description: 'The probes the Zscaler POV best practice guide starts with: Microsoft Login (Zscaler predefined app) and zscaler.com (custom app), plus the UCaaS apps Microsoft Teams, Zoom and Webex for call-quality monitoring. Each has a Web probe and a CloudPath probe, for all users. Zoom and Webex need the customer\'s account prefix (left out when blank).',
    source: 'Zscaler POV best practice guide',
    predefined: [{ provider: 'MICROSOFT_LOGIN', web: true, cloudpath: true }, { provider: 'MICROSOFT_TEAMS', web: true, cloudpath: true },
      { provider: 'ZOOM', web: true, cloudpath: true }, { provider: 'WEBEX', web: true, cloudpath: true }],
    custom: [{ name: 'zscaler.com', url: 'https://zscaler.com/', web: true, cloudpath: true, frequency: 300, protocol: 'ADAPTIVE' }]
  },
  BLANK: {
    id: 'BLANK', name: 'Start empty', icon: '📄',
    description: 'No apps selected. Pick predefined apps and add your own custom apps (for example an internal EHR or PACS URL) in the next steps.',
    source: 'Build your own',
    predefined: [],
    custom: []
  }
};

function getTemplate(id) {
  const t = TEMPLATES[id || 'POV_BEST_PRACTICE'];
  if (!t) throw new Error(`Unknown ZDX template: ${id}`);
  return t;
}

function getTemplateCatalog() {
  return Object.values(TEMPLATES).map(t => JSON.parse(JSON.stringify(t)));
}

/** Host part of a URL, or null if it isn't a valid http(s) URL. */
function hostOf(url) {
  try {
    const u = new URL(String(url).trim());
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;
    return u.hostname || null;
  } catch (e) { return null; }
}

/** Probe names are limited to 64 characters by ZDX. */
function probeName(appName, kind) {
  const suffix = kind === 'web' ? ' Web Probe' : ' CloudPath Probe';
  return String(appName).trim().substring(0, 64 - suffix.length) + suffix;
}

function buildWebMonitor({ appName, url, frequency = 300, klass = 'CUSTOM' }) {
  return {
    name: probeName(appName, 'web'), type: 'WEB', active: true, class: klass,
    timeoutSeconds: 60, expiresAtTimestamp: 0, frequencyInSeconds: Number(frequency) || 300,
    url: String(url).trim(), requestMethods: ['GET'], requestHeaders: [], retries: 1, requestTimeoutSeconds: 60,
    followRedirects: true, maxRedirects: 5, responseCodes: ['200-299', '304'], responseHeaders: [],
    ...ALL_TARGETS()
  };
}

function buildCloudPathMonitor({ appName, host, frequency = 300, protocol = 'ADAPTIVE', followWebId = null, klass = 'CUSTOM' }) {
  const body = {
    name: probeName(appName, 'cloudpath'), type: 'TRACERT', active: true, class: klass,
    timeoutSeconds: 60, expiresAtTimestamp: 0, frequencyInSeconds: Number(frequency) || 300,
    host: String(host).trim(), protocol: CLOUDPATH_PROTOCOLS.includes(protocol) ? protocol : 'ADAPTIVE',
    requestTimeoutSeconds: 60, maxPacketCount: 5, packetIntervalMs: 1000, packetTimeoutMs: 1000,
    udpPort: 33434, tcpPort: 443, reverseLookupEnabled: true,
    ...ALL_TARGETS()
  };
  if (body.protocol === 'ADAPTIVE' || body.protocol === 'TCP') body.tcpType = 'RESILIENT_TCP';
  if (followWebId) body.followWebMonitor = { id: Number(followWebId) };
  return body;
}

module.exports = {
  PROBE_FREQUENCIES, CLOUDPATH_PROTOCOLS, PREDEFINED_INFO, TEMPLATES,
  getTemplate, getTemplateCatalog, hostOf, probeName, buildWebMonitor, buildCloudPathMonitor
};
