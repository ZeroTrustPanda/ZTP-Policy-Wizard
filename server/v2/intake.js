/**
 * v2.2: customer intake. One form at the start of the call fills in every module:
 *   ZIA (baseline + scope), Client Connector (VPN gateways, DNS lists), ZPA (wildcard or one segment per app),
 *   ZDX (custom web apps). Presets give a starting point by vertical; every value stays editable.
 * Destinations in presets use {domain}, replaced with the customer's internal domain.
 */
'use strict';

const PRESETS = {
  HEALTHCARE: {
    id: 'HEALTHCARE', name: 'Healthcare', icon: '🏥', baseline: 'HIPAA',
    description: 'Hospital or health system: HIPAA baseline, EHR, single sign-on, imaging and clinical apps as ZPA segments, EHR web access monitored in ZDX.',
    apps: [
      { name: 'Epic Hyperspace', destinations: ['epic.{domain}', 'epicweb.{domain}'], ports: '443; 80', zdx: 'https://epicweb.{domain}/' },
      { name: 'Epic Interconnect', destinations: ['interconnect.{domain}'], ports: '443' },
      { name: 'Imprivata OneSign', destinations: ['imprivata.{domain}'], ports: '443; 80' },
      { name: 'PACS', destinations: ['pacs.{domain}'], ports: '104; 11112; 443' },
      { name: 'Cerner Millennium', destinations: ['cerner.{domain}'], ports: '443; 3389' },
      { name: 'Intranet', destinations: ['*.{domain}'], ports: '80; 443' }
    ],
    notes: ['Keep Imprivata and the EHR thick client on ZPA, not bypassed, so single sign-on and access policy can be shown.',
      'Confirm the real EHR, PACS and Imprivata host names with the customer; the preset names are placeholders built from the internal domain.']
  },
  GENERAL: {
    id: 'GENERAL', name: 'General enterprise', icon: '🏢', baseline: 'BALANCED',
    description: 'Any organization: Balanced baseline, intranet and file shares on ZPA, intranet monitored in ZDX.',
    apps: [
      { name: 'Intranet', destinations: ['intranet.{domain}'], ports: '80; 443', zdx: 'https://intranet.{domain}/' },
      { name: 'File shares', destinations: ['files.{domain}'], ports: '445' },
      { name: 'Remote desktop', destinations: ['rdp.{domain}'], ports: '3389' }
    ],
    notes: ['Replace the example host names with the customer\'s real servers.']
  },
  FINANCE: {
    id: 'FINANCE', name: 'Financial services', icon: '🏦', baseline: 'PCI',
    description: 'Bank, insurer or payments: PCI DSS baseline, core banking and trading apps on ZPA.',
    apps: [
      { name: 'Core banking', destinations: ['core.{domain}'], ports: '443' },
      { name: 'Trading platform', destinations: ['trade.{domain}'], ports: '443; 8443' },
      { name: 'Intranet', destinations: ['intranet.{domain}'], ports: '80; 443', zdx: 'https://intranet.{domain}/' }
    ],
    notes: ['Check which baseline the customer audits against (PCI DSS, SOX).']
  },
  BLANK: { id: 'BLANK', name: 'Start empty', icon: '📄', baseline: 'BALANCED', description: 'No preset applications.', apps: [], notes: [] }
};

const DOMAIN_RE = /^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$/;

/** Fill a preset for one customer domain (returns copies). */
function preset(id, domain) {
  const p = PRESETS[id] || PRESETS.BLANK;
  const d = String(domain || '').trim().toLowerCase();
  const sub = (v) => String(v).replace(/\{domain\}/g, d || 'example.org');
  return {
    ...p,
    apps: p.apps.map(a => ({ name: a.name, destinations: a.destinations.map(sub), ports: a.ports, zdx: a.zdx ? sub(a.zdx) : null })),
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
  return Object.values(PRESETS).map(p => ({ id: p.id, name: p.name, icon: p.icon, baseline: p.baseline, description: p.description, appCount: p.apps.length }));
}

module.exports = { PRESETS, preset, catalog, suggestPrefix, validateIntake };
