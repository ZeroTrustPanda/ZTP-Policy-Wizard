/**
 * Match a policy set to the connected tenant before dry run / apply (v1.9.0). Never changes the tenant.
 *  - Isolation profile: URL Isolate rules and Sandbox "Quarantine & Isolate" use the profile chosen on the
 *    Customize step (or named in a framework file), else the tenant's default profile. Profiles can only be
 *    created in the Isolation portal; the ZIA API reads them.
 *  - Isolate rules also need browser types (user agents): copied from an Isolate rule the tenant already has.
 *  - Cloud Firewall: deprecated or unknown network applications are dropped (ZIA refuses them); a rule left
 *    with none is skipped, because a firewall rule with no applications would match all traffic.
 *  - URL categories the tenant doesn't have are left out (an unknown category fails the whole rule).
 * Returns { template, info, warnings, errors }.
 */
const list = (r) => (Array.isArray(r) ? r : (r && (r.list || r.items)) || []);
const ISOLATE_USER_AGENTS = ['OPERA', 'FIREFOX', 'MSIE', 'MSEDGE', 'CHROME', 'SAFARI', 'MSCHREDGE'];

async function resolveForTenant(client, templateIn, { cbiProfile = null } = {}) {
  const template = JSON.parse(JSON.stringify(templateIn));
  const warnings = [], errors = [];
  const info = { cbi: null, firewallApps: null };
  const policies = template.policies || {};

  // ---- URL categories: drop ones this tenant doesn't have (one unknown category fails the whole rule)
  const urlRules = policies.urlFiltering || [];
  if (urlRules.length) {
    let cats = null;
    try { cats = list(await client.getUrlCategories()); } catch (e) { /* send as written */ }
    if (cats && cats.length) {
      const known = new Set(cats.map(c => c.id));
      for (const c of (template.customCategories || [])) known.add(c.id);
      for (const r of urlRules) if (r.customCategoryName) known.add(r.customCategoryName);
      known.add('ANY');
      policies.urlFiltering = urlRules.filter(r => {
        if (!Array.isArray(r.urlCategories)) return true;
        const gone = r.urlCategories.filter(c => !known.has(c));
        if (!gone.length) return true;
        r.urlCategories = r.urlCategories.filter(c => known.has(c));
        warnings.push(`${r.name}: categories not in this tenant, left out: ${gone.join(', ')}`);
        if (!r.urlCategories.length) { warnings.push(`${r.name}: no categories left — rule skipped.`); return false; }
        return true;
      });
      if (!policies.urlFiltering.length) delete policies.urlFiltering;
    }
  }

  // ---- Isolation profile
  const isoRules = (policies.urlFiltering || []).filter(r => r.action === 'ISOLATE');
  const sbIso = (policies.sandbox || []).filter(r => r.firstTimeOperation === 'QUARANTINE_ISOLATE');
  if (isoRules.length || sbIso.length) {
    let profiles = [];
    try { profiles = list(await client.getCbiProfiles()); }
    catch (e) { warnings.push(`Could not read Cloud Browser Isolation profiles (${e.message}).`); }
    const named = [...isoRules, ...sbIso].map(r => r.cbiProfile).find(p => p && (p.id || p.name));
    const want = (cbiProfile && (cbiProfile.id || cbiProfile.name)) ? cbiProfile : named || null;
    let chosen = null;
    if (want) chosen = profiles.find(p => String(p.id) === String(want.id)) || profiles.find(p => p.name === want.name) || null;
    if (!chosen && profiles.length) {
      chosen = profiles.find(p => p.defaultProfile) || profiles[0];
      warnings.push(want ? `Isolation profile "${want.name}" is not in this tenant — using "${chosen.name}".`
        : `No isolation profile chosen — using "${chosen.name}"${chosen.defaultProfile ? ' (the default profile)' : ''}.`);
    }
    info.cbi = { available: profiles.map(p => ({ id: p.id, name: p.name, url: p.url, defaultProfile: !!p.defaultProfile })) };
    if (chosen) {
      const cbi = { id: chosen.id, name: chosen.name, url: chosen.url, ...(chosen.profileSeq !== undefined ? { profileSeq: chosen.profileSeq } : {}) };
      for (const r of [...isoRules, ...sbIso]) r.cbiProfile = cbi;
      Object.assign(info.cbi, cbi, { defaultProfile: !!chosen.defaultProfile });
    } else {
      if (isoRules.length) errors.push(`This tenant has no Cloud Browser Isolation profile, so ${isoRules.map(r => r.name).join(', ')} cannot Isolate. Create a profile in the Isolation portal, or set those rules back to Block / Allow.`);
      for (const r of sbIso) { r.firstTimeOperation = 'QUARANTINE'; delete r.cbiProfile; warnings.push(`${r.name}: no isolation profile in this tenant — first-time action falls back to Quarantine.`); }
    }
    if (isoRules.length) {
      let agents = null;
      try {
        const existing = list(await client.getUrlFilteringRules()).find(r => r.action === 'ISOLATE' && Array.isArray(r.userAgentTypes) && r.userAgentTypes.length);
        if (existing) agents = existing.userAgentTypes.slice();
      } catch (e) { /* default list */ }
      for (const r of isoRules) if (!r.userAgentTypes || !r.userAgentTypes.length) r.userAgentTypes = agents || ISOLATE_USER_AGENTS.slice();
    }
  }

  // ---- Cloud Firewall network applications
  const fw = policies.firewallFiltering || [];
  if (fw.some(r => Array.isArray(r.nwApplications) && r.nwApplications.length)) {
    let apps = null;
    try { apps = list(await client.getNetworkApplications()); }
    catch (e) { warnings.push(`Could not read the tenant's network applications (${e.message}); firewall rules are sent as written.`); }
    if (apps && apps.length) {
      const ok = new Set(apps.filter(a => !a.deprecated).map(a => a.id));
      const dep = new Set(apps.filter(a => a.deprecated).map(a => a.id));
      info.firewallApps = { checked: apps.length, deprecated: dep.size };
      policies.firewallFiltering = fw.filter(r => {
        if (!Array.isArray(r.nwApplications) || !r.nwApplications.length) return true;
        const keep = r.nwApplications.filter(a => ok.has(a));
        const gone = r.nwApplications.filter(a => !ok.has(a));
        if (gone.length) warnings.push(`${r.name}: left out ${gone.map(a => `${a}${dep.has(a) ? ' (deprecated)' : ' (not in this tenant)'}`).join(', ')}`);
        r.nwApplications = keep;
        if (!keep.length) { warnings.push(`${r.name}: none of its network applications are usable in this tenant — rule skipped.`); return false; }
        return true;
      });
      if (!policies.firewallFiltering.length) delete policies.firewallFiltering;
    }
  }
  return { template, info, warnings, errors };
}

module.exports = { resolveForTenant, ISOLATE_USER_AGENTS };
