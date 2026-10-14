/**
 * Portable frameworks (v1.9.0).
 *
 * A framework file carries everything needed to rebuild the same policy in another tenant:
 *   {
 *     format: 'ztp-zia-framework', formatVersion: 1, appVersion, name, description, savedAt,
 *     kind: 'built-in' | 'captured',
 *     config: { tier, complianceFramework, prefix, enable* flags, actionSettings,
 *               disabledRules, cbiProfileName, sslCertificateName },
 *     baseTemplate: { metadata, policies, customCategories }   // only for captured frameworks
 *   }
 * Nothing tenant-specific is kept: isolation profiles and certificates are stored by
 * name and matched again in the new tenant; user / group / location scoping is not carried over.
 *
 * captureFromTenant() reads the tenant's own policies (URL filtering with its custom categories,
 * Cloud Firewall, SSL Inspection, Sandbox, DNS Control and File Type Control)
 * (OneAPI or legacy API) and turns them into a framework that can be applied elsewhere.
 */
const FORMAT = 'ztp-zia-framework';
const FORMAT_VERSION = 1;
const CONFIG_KEYS = ['tier', 'complianceFramework', 'prefix', 'enableUrlFiltering', 'enableFirewall', 'enableSslInspection',
  'enableMalwareProtection', 'enableAdvancedSettings', 'enableSandbox', 'enableDnsSecurity', 'enableFileTypeControl',
  'enableCloudAppControl', 'enableDlp', 'actionSettings', 'disabledRules', 'cbiProfileName', 'sslCertificateName'];
// Frameworks only in the GovCloud Edition (legacy API build)
const GOVCLOUD_ONLY = new Set(['DOW_STANDARD']);

const list = (r) => (Array.isArray(r) ? r : (r && (r.list || r.items)) || []);
const SCOPE_FIELDS = ['locations', 'locationGroups', 'groups', 'departments', 'users', 'devices', 'deviceGroups', 'labels', 'timeWindows', 'workloadGroups'];

function pickConfig(cfg = {}) {
  const out = {};
  for (const k of CONFIG_KEYS) if (cfg[k] !== undefined) out[k] = cfg[k];
  return out;
}

/** Build the file contents (the browser saves it). */
function buildFrameworkFile({ name, description, config, baseTemplate, appVersion }) {
  const cfg = pickConfig(config);
  if (config && config.cbiProfile && config.cbiProfile.name) cfg.cbiProfileName = config.cbiProfile.name;
  if (config && config.sslCertificate && config.sslCertificate.name) cfg.sslCertificateName = config.sslCertificate.name;
  return {
    format: FORMAT, formatVersion: FORMAT_VERSION, appVersion, savedAt: new Date().toISOString(),
    name: String(name || 'ZIA framework').substring(0, 120), description: description || '',
    kind: baseTemplate ? 'captured' : 'built-in',
    config: cfg,
    ...(baseTemplate ? { baseTemplate } : {})
  };
}

/** Check an uploaded file and return the wizard config to load. */
function readFrameworkFile(f) {
  if (!f || typeof f !== 'object') throw new Error('Not a framework file (expected JSON).');
  if (f.format !== FORMAT) throw new Error(`Not a ZTP ZIA framework file (format "${f.format || 'missing'}").`);
  if (!(f.formatVersion >= 1 && f.formatVersion <= FORMAT_VERSION)) throw new Error(`Framework file version ${f.formatVersion} is newer than this app understands.`);
  const config = pickConfig(f.config || {});
  if (config.complianceFramework && GOVCLOUD_ONLY.has(config.complianceFramework)) {
    throw new Error(`This framework uses ${config.complianceFramework}, which is only in the Zscaler Policy Wizard GovCloud Edition.`);
  }
  if (f.config && f.config.cbiProfileName) config.cbiProfileName = f.config.cbiProfileName;
  if (f.kind === 'captured' || f.baseTemplate) {
    if (!f.baseTemplate || typeof f.baseTemplate.policies !== 'object') throw new Error('Captured framework has no policies.');
    config.baseTemplate = f.baseTemplate;
  } else if (!config.complianceFramework && !config.tier) {
    throw new Error('Framework file has neither a built-in framework nor captured policies.');
  }
  const counts = config.baseTemplate
    ? Object.fromEntries(Object.entries(config.baseTemplate.policies).map(([k, v]) => [k, Array.isArray(v) ? v.length : 1]))
    : null;
  return { name: f.name, description: f.description || '', kind: f.kind || 'built-in', savedAt: f.savedAt, appVersion: f.appVersion, config, counts };
}

// ---------------- capture ----------------
function scopeNote(r) {
  const used = SCOPE_FIELDS.filter(k => Array.isArray(r[k]) && r[k].length);
  return used.length ? `${r.name}: ${used.join(', ')} scoping not carried over (applies to everyone in the new tenant)` : null;
}

async function captureFromTenant(client, { name, host } = {}) {
  const policies = {}, notes = [], skipped = [];
  const safe = async (label, fn) => { try { return list(await fn()); } catch (e) { notes.push(`${label}: could not read (${e.message})`); return null; } };
  const note = (n) => { if (n) notes.push(n); };
  const user = (r) => !r.defaultRule && !r.predefined;

  // URL filtering + the custom categories it uses
  const urlRules = await safe('URL Filtering', () => client.getUrlFilteringRules());
  const customCategories = [];
  if (urlRules) {
    const custom = await safe('Custom URL categories', () => client.getUrlCategories(true)) || [];
    const byId = Object.fromEntries(custom.map(c => [c.id, c]));
    policies.urlFiltering = urlRules.filter(user).sort((a, b) => (a.order || 0) - (b.order || 0)).map(r => {
      note(scopeNote(r));
      const cats = r.urlCategories || [];
      for (const id of cats) if (byId[id] && !customCategories.some(c => c.id === id)) {
        const c = byId[id];
        customCategories.push({ id, configuredName: c.configuredName, superCategory: c.superCategory || 'USER_DEFINED',
          urls: c.urls || [], dbCategorizedUrls: c.dbCategorizedUrls || [], keywords: c.keywords || [], keywordsRetainingParentCategory: c.keywordsRetainingParentCategory || [],
          description: c.description || '' });
      }
      return { name: r.name, order: r.order, state: r.state || 'ENABLED', action: r.action, urlCategories: cats, protocols: r.protocols || ['ANY_RULE'],
        description: r.description || '', ...(r.action === 'ISOLATE' && r.cbiProfile ? { cbiProfile: { name: r.cbiProfile.name } } : {}) };
    });
  }

  const fw = await safe('Cloud Firewall', () => client.getFirewallRules());
  if (fw) policies.firewallFiltering = fw.filter(user).map(r => {
    note(scopeNote(r));
    if ((r.nwServices || []).length || (r.nwServiceGroups || []).length || (r.srcIpGroups || []).length || (r.destIpGroups || []).length) {
      notes.push(`${r.name}: network services / IP groups are tenant objects and are not carried over`);
    }
    return { name: r.name, order: r.order, state: r.state || 'ENABLED', action: r.action, description: r.description || '',
      ...(r.nwApplications ? { nwApplications: r.nwApplications } : {}), ...(r.destIpCategories ? { destIpCategories: r.destIpCategories } : {}),
      ...(r.destCountries ? { destCountries: r.destCountries } : {}) };
  });

  const ssl = await safe('SSL Inspection', () => client.getSslInspectionRules());
  if (ssl) policies.sslInspection = ssl.filter(user).map(r => {
    note(scopeNote(r));
    const d = r.action && r.action.decryptSubActions;
    return { name: r.name, order: r.order, state: r.state || 'ENABLED', action: r.action && r.action.type === 'DECRYPT' ? 'DECRYPT' : 'DO_NOT_DECRYPT',
      description: r.description || '', ...(Array.isArray(r.urlCategories) && r.urlCategories.length ? { urlCategories: r.urlCategories.map(c => (typeof c === 'string' ? c : c.id || c.name)).filter(Boolean) } : {}),
      ...(d ? { minClientTLS: d.minClientTLSVersion, minServerTLS: d.minServerTLSVersion } : {}) };
  });

  const sb = await safe('Sandbox', () => client.getSandboxRules());
  if (sb) policies.sandbox = sb.filter(user).map(r => {
    note(scopeNote(r));
    return { name: r.name, order: r.order, state: r.state || 'ENABLED', baRuleAction: r.baRuleAction, baPolicyCategories: r.baPolicyCategories || [],
      fileTypes: r.fileTypes || ['ANY'], protocols: r.protocols || ['ANY_RULE'], firstTimeEnable: !!r.firstTimeEnable,
      firstTimeOperation: r.firstTimeOperation, mlActionEnabled: !!r.mlActionEnabled, description: r.description || '' };
  });

  const dns = await safe('DNS Control', () => client.getDnsControlRules());
  if (dns) policies.dnsSecurity = dns.filter(user).map(r => {
    note(scopeNote(r));
    return { name: r.name, order: r.order, state: r.state || 'ENABLED', action: r.action, rank: r.rank || 7, protocols: r.protocols || ['ANY_RULE'],
      ...(r.applications ? { applications: r.applications } : {}), description: r.description || '' };
  });

  const ftc = await safe('File Type Control', () => client.getFileTypeRules());
  if (ftc) policies.fileTypeControl = ftc.filter(user).map(r => {
    note(scopeNote(r));
    return { name: r.name, order: r.order, state: r.state || 'ENABLED', filteringAction: r.filteringAction, fileTypes: r.fileTypes || [],
      operation: r.operation || 'UPLOAD_DOWNLOAD', protocols: r.protocols || ['ANY_RULE'],
      ...(r.passwordProtected !== undefined ? { passwordProtected: r.passwordProtected } : {}), description: r.description || '' };
  });

  for (const [k, v] of Object.entries(policies)) if (Array.isArray(v) && !v.length) delete policies[k];
  skipped.push('Cloud App Control and Data Loss Prevention are not captured: their rules point at tenant-specific apps, engines and dictionaries.');
  skipped.push('Malware Protection, Advanced Threat Protection and IPS settings are not captured (this version does not apply them).');

  const baseTemplate = {
    metadata: { name: name || `Captured from ${host || 'tenant'}`, source: `tenant capture (${host || 'tenant'})`, tier: 'CUSTOM', capturedAt: new Date().toISOString() },
    policies, customCategories
  };
  return { baseTemplate, notes, skipped };
}

module.exports = { buildFrameworkFile, readFrameworkFile, captureFromTenant, FORMAT, FORMAT_VERSION };
