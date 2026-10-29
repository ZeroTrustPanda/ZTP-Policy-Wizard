/**
 * v2.2 / 2.3: customer intake. One form at the start of the call fills in every module:
 *   ZIA (baseline + scope), Client Connector (VPN gateways, DNS lists), ZPA (wildcard or one segment per app),
 *   ZDX (custom web apps). Presets give a starting point by vertical; every value stays editable.
 * Destinations in presets use {domain}, replaced with the customer's internal domain.
 */
'use strict';

// v2.3: every preset starts with the same cross-vertical private apps, led by a wildcard for the internal domain
// (ZPA picks the most specific segment, so the named apps below still get their own segment and policy).
const ALL_PORTS = '1-52; 54-65535; udp:1-52; udp:54-65535';
const COMMON_APPS = [
  { name: 'All internal apps', destinations: ['*.{domain}'], ports: ALL_PORTS, common: true },
  { name: 'Active Directory', destinations: ['dc01.{domain}', 'dc02.{domain}'], ports: '88; 135; 389; 445; 464; 636; 3268; 3269; 49152-65535; udp:88; udp:123; udp:389; udp:464', common: true },
  { name: 'File shares', destinations: ['files.{domain}'], ports: '445', common: true },
  { name: 'Intranet', destinations: ['intranet.{domain}'], ports: '80; 443', common: true, zdx: 'https://intranet.{domain}/' },
  { name: 'Remote desktop jump host', destinations: ['jumpbox.{domain}'], ports: '3389', common: true }
];
// ZDX: Outlook joins the template's Microsoft Login / Teams / Zoom / Webex for every segment; each segment adds its own SaaS
const COMMON_ZDX_PREDEFINED = ['OUTLOOK'];

const PRESETS = {
  HEALTHCARE: {
    id: 'HEALTHCARE', name: 'Healthcare', icon: '🏥', baseline: 'HIPAA',
    description: 'Hospital or health system: HIPAA baseline; EHR, single sign-on and imaging as ZPA segments; clinical reference apps in ZDX.',
    apps: [
      { name: 'Epic Hyperspace', destinations: ['epic.{domain}', 'epicweb.{domain}'], ports: '443; 80', zdx: 'https://epicweb.{domain}/' },
      { name: 'Epic Interconnect', destinations: ['interconnect.{domain}'], ports: '443' },
      { name: 'Imprivata OneSign', destinations: ['imprivata.{domain}'], ports: '443; 80' },
      { name: 'PACS', destinations: ['pacs.{domain}'], ports: '104; 11112; 443' },
      { name: 'Cerner Millennium', destinations: ['cerner.{domain}'], ports: '443; 3389' }
    ],
    zdxApps: [
      { name: 'UpToDate', url: 'https://www.uptodate.com/' },
      { name: 'Epic UserWeb', url: 'https://userweb.epic.com/' },
      { name: 'Doximity', url: 'https://www.doximity.com/' }
    ],
    notes: ['Keep Imprivata and the EHR thick client on ZPA, not bypassed, so single sign-on and access policy can be shown.',
      'Confirm the real EHR, PACS, Imprivata and domain controller host names with the customer; the preset names are placeholders built from the internal domain.']
  },
  GENERAL: {
    id: 'GENERAL', name: 'General enterprise', icon: '🏢', baseline: 'BALANCED',
    description: 'Any organization: Balanced baseline; common internal apps on ZPA; common SaaS apps in ZDX.',
    apps: [],
    zdxApps: [
      { name: 'Salesforce', url: 'https://login.salesforce.com/' },
      { name: 'Workday', url: 'https://www.myworkday.com/' },
      { name: 'DocuSign', url: 'https://app.docusign.com/' }
    ],
    notes: ['Replace the example host names with the customer\'s real servers.']
  },
  FINANCE: {
    id: 'FINANCE', name: 'Financial services', icon: '🏦', baseline: 'PCI',
    description: 'Bank, insurer or payments: PCI DSS baseline; core banking and trading apps on ZPA; market data and HR SaaS in ZDX.',
    apps: [
      { name: 'Core banking', destinations: ['core.{domain}'], ports: '443' },
      { name: 'Trading platform', destinations: ['trade.{domain}'], ports: '443; 8443' }
    ],
    zdxApps: [
      { name: 'Bloomberg', url: 'https://www.bloomberg.com/' },
      { name: 'Workday', url: 'https://www.myworkday.com/' },
      { name: 'DocuSign', url: 'https://app.docusign.com/' }
    ],
    notes: ['Check which baseline the customer audits against (PCI DSS, SOX).']
  },
  FEDERAL: {
    id: 'FEDERAL', name: 'Federal and public sector', icon: '🏛️', baseline: 'FEDRAMP_MOD',
    description: 'Federal, state or local agency, or a contractor that serves one: FedRAMP Moderate baseline (pick CMMC, Zero Trust, IRS 1075, CJIS or GovRAMP instead); case management and HR apps on ZPA; login.gov and USAJOBS in ZDX.',
    apps: [
      { name: 'Case management', destinations: ['cases.{domain}'], ports: '443' },
      { name: 'Financial management', destinations: ['finance.{domain}'], ports: '443' },
      { name: 'HR and time and attendance', destinations: ['hr.{domain}'], ports: '443' }
    ],
    zdxApps: [
      { name: 'Login.gov', url: 'https://secure.login.gov/' },
      { name: 'USAJOBS', url: 'https://www.usajobs.gov/' },
      { name: 'SAM.gov', url: 'https://sam.gov/' }
    ],
    notes: ['Confirm the authorization the customer works to (FedRAMP Moderate or High, CMMC Level 2, IRS Pub 1075, CJIS, GovRAMP) and pick that compliance profile.',
      'Federal civilian agencies on a GovCloud tenant use the GovCloud Edition of the wizard.']
  },
  EDUCATION: {
    id: 'EDUCATION', name: 'Education', icon: '🎓', baseline: 'BALANCED',
    description: 'School district, college or university: Balanced baseline; student information system on ZPA; learning platforms in ZDX.',
    apps: [
      { name: 'Student information system', destinations: ['sis.{domain}'], ports: '443' }
    ],
    zdxApps: [
      { name: 'Canvas', url: 'https://canvas.instructure.com/' },
      { name: 'Google Classroom', url: 'https://classroom.google.com/' },
      { name: 'PowerSchool', url: 'https://www.powerschool.com/' }
    ],
    notes: ['Check whether CIPA / FERPA content filtering is required for students.']
  },
  BLANK: { id: 'BLANK', name: 'Start empty', icon: '📄', baseline: 'BALANCED', description: 'Only the wildcard for the internal domain; add apps yourself.', apps: [], zdxApps: [], notes: [], commonOnly: ['All internal apps'] }
};

const DOMAIN_RE = /^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$/;

/** Fill a preset for one customer domain (returns copies). */
function preset(id, domain) {
  const p = PRESETS[id] || PRESETS.BLANK;
  const d = String(domain || '').trim().toLowerCase();
  const sub = (v) => String(v).replace(/\{domain\}/g, d || 'example.org');
  const common = p.commonOnly ? COMMON_APPS.filter(a => p.commonOnly.includes(a.name)) : COMMON_APPS;
  const apps = [...common, ...p.apps].map(a => ({ name: a.name, destinations: a.destinations.map(sub), ports: a.ports, zdx: a.zdx ? sub(a.zdx) : null, common: !!a.common }));
  const zdxApps = [...apps.filter(a => a.zdx).map(a => ({ name: a.name, url: a.zdx })), ...(p.zdxApps || []).map(z => ({ name: z.name, url: sub(z.url) }))];
  return {
    ...p, apps, zdxApps, zdxPredefined: p.id === 'BLANK' ? [] : COMMON_ZDX_PREDEFINED.slice(),
    notes: p.notes.slice()
  };
}

/** Suggest a prefix from the customer name: letters and digits, up to 12, upper case. */
function suggestPrefix(name) {
  const s = String(name || '').replace(/[^A-Za-z0-9 ]/g, ' ').trim();
  if (!s) return '';
  const words = s.split(/\s+/);
  const initials = words.length > 1 ? words.map(w => w[0]).join('') : words[0];
  return (initials.length >= 3 ? initials : words.join('')).toUpperCase().slice(0, 12);
}

function validateIntake(i) {
  const errors = [];
  if (i.domain && !DOMAIN_RE.test(String(i.domain).trim())) errors.push(`"${i.domain}" is not a valid domain (for example hospital.org).`);
  for (const d of i.internalDomains || []) if (!DOMAIN_RE.test(String(d).replace(/^\*\./, ''))) errors.push(`Internal domain "${d}" is not valid.`);
  return errors;
}

function catalog() {
  return Object.values(PRESETS).map(p => ({ id: p.id, name: p.name, icon: p.icon, baseline: p.baseline, description: p.description, appCount: (p.commonOnly ? p.commonOnly.length : COMMON_APPS.length) + p.apps.length, zdxCount: (p.zdxApps || []).length }));
}

module.exports = { PRESETS, COMMON_APPS, preset, catalog, suggestPrefix, validateIntake };
