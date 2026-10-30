/**
 * v2.8: shadow and conflict check for the ZIA dry run.
 * ZIA evaluates each of these policies top down and stops at the first rule that matches, and the wizard adds its rules
 * below the customer's. A customer rule higher in the list that matches the same traffic therefore decides first, and the
 * POV rule never fires for that traffic.
 *
 * The check only reports what it is certain of (the approach follows Zscaler Made Easy, see About):
 *   - a customer rule scoped to users, groups, departments, locations, devices, times or anything else this check does not
 *     understand is never reported as shadowing; it is only counted
 *   - every criterion of the customer rule must be "all" or a superset of the POV rule's, field by field
 * Findings: shadowed (a different action decides all of the POV rule's traffic), partial (it decides some categories or apps),
 * duplicate (an existing rule already does the same thing, so the POV rule is redundant).
 */
'use strict';

const ANY = (v) => v === undefined || v === null || (Array.isArray(v) && (!v.length || v.includes('ANY') || v.includes('ANY_RULE')));
const ids = (v) => (Array.isArray(v) ? v : []).map(x => (x && typeof x === 'object') ? String(x.id !== undefined ? x.id : x.name) : String(x));

// Fields that narrow who or what a rule applies to and that this check does not evaluate: any of them set → not certain.
const SCOPE_FIELDS = ['users', 'groups', 'departments', 'locations', 'locationGroups', 'timeWindows', 'devices', 'deviceGroups', 'deviceTrustLevels',
  'workloadGroups', 'sourceIpGroups', 'srcIps', 'srcIpGroups', 'srcIpv6Groups', 'userRiskScoreLevels', 'userAgentTypes', 'platforms', 'overrideUsers',
  'overrideGroups', 'cloudAppInstances', 'tenancyProfileIds', 'proxyGateways', 'zpaAppSegments', 'destIpGroups', 'destIpv6Groups', 'destAddresses',
  'excludeSrcCountries', 'sourceCountries', 'appServiceGroups', 'appServices', 'nwServiceGroups', 'nwApplicationGroups', 'deviceTrustLevel',
  'browserEunTemplateId', 'sizeQuota', 'timeQuota', 'enforceTimeValidity', 'cbiProfile', 'labels'];
const scopedBy = (r) => SCOPE_FIELDS.filter(k => k !== 'labels' && k !== 'cbiProfile' && k !== 'browserEunTemplateId' && (Array.isArray(r[k]) ? r[k].length : (k === 'enforceTimeValidity' ? !!r[k] : (r[k] && typeof r[k] === 'object' && Object.keys(r[k]).length && k !== 'cbiProfile'))));

/** Does `big` (the customer's value) cover all of `small` (the POV rule's)? null = can't tell. */
function covers(big, small) {
  if (ANY(big)) return true;
  if (ANY(small)) return false;
  const b = new Set(ids(big));
  return ids(small).every(x => b.has(x));
}
function overlap(big, small) {
  if (ANY(big)) return ids(small);
  if (ANY(small)) return ids(big);
  const b = new Set(ids(big));
  return ids(small).filter(x => b.has(x));
}

const actionOf = (r, type) => {
  if (type === 'sslInspection') return (r.action && r.action.type) || '';
  if (type === 'cloudAppControl') return (r.actions || []).slice().sort().join('+');
  if (type === 'fileTypeControl') return r.filteringAction || '';
  return r.action || '';
};
const pretty = (a) => String(a || '').replace(/_/g, ' ').toLowerCase();
/** What a rule does to the traffic, coarsely: two rules with the same outcome (BLOCK_DROP and BLOCK_ICMP, say) are duplicates, not a conflict. */
function outcome(action) {
  const parts = String(action || '').split('+').filter(Boolean);
  if (!parts.length) return '';
  const cls = (a) => /^(BLOCK|DENY|DROP)|BLOCK_|_DROP$/.test(a) ? 'block' : /^ALLOW|^DECRYPT$|^INSPECT/.test(a) ? 'allow' : /CAUTION/.test(a) ? 'caution' : /ISOLATE/.test(a) ? 'isolate' : /DO_NOT_DECRYPT/.test(a) ? 'exempt' : a;
  const set = [...new Set(parts.map(cls))].sort();
  return set.length === 1 ? set[0] : parts.slice().sort().join('+');
}

// Per policy: the list it lives in, and which criteria fields decide whether a rule matches.
// Keyed by the engine's category label (the ledger's "category").
const POLICIES = {
  'URL Filtering': { type: 'urlFiltering', main: 'urlCategories', fields: ['urlCategories', 'protocols', 'requestMethods'] },
  'Cloud Firewall': { type: 'firewallFiltering', main: null, fields: ['nwApplications', 'nwServices', 'destCountries', 'destIpCategories', 'protocols', 'destPorts'] },
  'DNS Security': { type: 'dnsSecurity', main: null, fields: ['protocols', 'destIpCategories', 'resCategories', 'applications', 'destCountries'] },
  'File Type Control': { type: 'fileTypeControl', main: 'fileTypes', fields: ['fileTypes', 'protocols', 'urlCategories', 'operation'] },
  'Cloud App Control': { type: 'cloudAppControl', main: 'applications', fields: ['applications'] },
  'SSL Inspection': { type: 'sslInspection', main: 'urlCategories', fields: ['urlCategories', 'cloudApplications'] }
};

function fieldCovers(field, big, small) {
  if (field === 'operation') return !big || big === 'UPLOAD_DOWNLOAD' || big === small;
  if (field === 'requestMethods') return ANY(big) || covers(big, small);
  return covers(big, small);
}

/**
 * planned: [{ category, listPath, body }] — every rule the apply will create or keep (the engine's dry-run record).
 * lists: { listPath: [existing objects] } as the dry run read them.
 * isOurs(rule): true for objects the wizard made (prefix or provenance tag).
 */
function analyze(planned, lists, isOurs) {
  const findings = [];
  let scopedSkipped = 0, checked = 0;
  const managed = new Set();
  for (const pl of planned || []) {
    const def = POLICIES[pl.category];
    if (!def) continue;
    const p = pl.body || {};
    const type = def.type, label = pl.category;
    const all = (lists[pl.listPath] || []).filter(x => x && !x.defaultRule && x.state !== 'DISABLED');
    if (!all.length) continue;
    checked++;
    const mine = all.find(x => x.name === p.name);
    const myOrder = mine ? mine.order : Infinity;   // a new POV rule is added below the existing ones
    const myAction = actionOf(p, type);
    const above = all.filter(x => x.name !== p.name && !isOurs(x) && (x.order || 0) < myOrder).sort((a, b) => a.order - b.order);
    let partial = null;
    for (const e of above) {
      // Zscaler-managed one-click rules match on criteria the API does not show; the wizard places its rules after them on purpose
      if (e.predefined) { managed.add(e.name); continue; }
      if (scopedBy(e).length) { if (def.fields.some(f => ANY(e[f]) || overlap(e[f], p[f]).length)) scopedSkipped++; continue; }
      // every non-main criterion must cover the POV rule completely
      const others = def.fields.filter(f => f !== def.main);
      if (!others.every(f => fieldCovers(f, e[f], p[f]))) continue;
      const ea = actionOf(e, type);
      if (!def.main || fieldCovers(def.main, e[def.main], p[def.main])) {
        const same = ea === myAction || outcome(ea) === outcome(myAction);
        findings.push({ type, policy: label, rule: p.name, kind: same ? 'duplicate' : 'shadowed', severity: same ? 'info' : 'high',
          by: { name: e.name, order: e.order, action: ea, predefined: !!e.predefined },
          reason: same
            ? `"${e.name}" (order ${e.order}) already ${ea === myAction ? 'does the same' : `has the same effect`} (${pretty(ea)}) higher in the list, so "${p.name}" is redundant.`
            : `"${e.name}" (order ${e.order}, ${pretty(ea)}) matches everything "${p.name}" matches and sits above it, so the POV rule never fires.`,
          fix: same ? 'Nothing to change; the POV result will come from the existing rule. Mention it in the readout.'
            : `Move "${p.name}" above "${e.name}" in the ZIA portal, or narrow "${e.name}", before running this test.` });
        partial = null;
        break;
      }
      // the main criterion overlaps only in part (some categories, apps or file types)
      const ov = overlap(e[def.main], p[def.main]);
      if (ov.length && ea !== myAction && outcome(ea) !== outcome(myAction) && !partial) {
        const what = def.main === 'urlCategories' ? 'categories' : def.main === 'applications' ? 'apps' : 'file types';
        partial = { type, policy: label, rule: p.name, kind: 'partial', severity: 'medium', by: { name: e.name, order: e.order, action: ea, predefined: !!e.predefined }, overlap: ov.slice(0, 12),
          reason: `"${e.name}" (order ${e.order}, ${pretty(ea)}) decides ${ov.length} of this rule's ${what} first: ${ov.slice(0, 6).join(', ')}${ov.length > 6 ? '…' : ''}.`,
          fix: `Test with ${what} not in "${e.name}", or move "${p.name}" above it.` };
      }
    }
    if (partial) findings.push(partial);
  }
  const order = { high: 0, medium: 1, info: 2 };
  findings.sort((a, b) => order[a.severity] - order[b.severity]);
  return {
    findings, checked, scopedSkipped,
    summary: findings.length
      ? `${findings.filter(f => f.kind === 'shadowed').length} POV rule(s) shadowed, ${findings.filter(f => f.kind === 'partial').length} partly decided by a customer rule above, ${findings.filter(f => f.kind === 'duplicate').length} redundant.`
      : (checked ? 'No customer rule above the POV rules decides their traffic first.' : 'No existing rules to compare.'),
    note: [scopedSkipped ? `${scopedSkipped} customer rule(s) above are scoped to particular users, groups, locations or devices and may decide first for them; they are not reported.` : '',
      managed.size ? `Zscaler-managed rules above (${[...managed].slice(0, 4).join(', ')}${managed.size > 4 ? '…' : ''}) are not compared: they match on criteria the API does not show.` : ''].filter(Boolean).join(' ') || null
  };
}

module.exports = { analyze, covers, scopedBy, outcome, POLICIES };
