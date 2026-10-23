/**
 * v2.6: what the API client is allowed to do, per product, against what the wizard needs.
 *  - Which products the client can use at all: the OneAPI token's "service-info" claim lists each product with its role
 *    (seen live on ZTH: ZIA "API Role", ZPA "API Full Access", ZCC "Super Admin", ZDX "ZDX Super Admin", ZGUARD "Administrator",
 *    ZINSIGHTS "ZINSIGHTS Reader", ZIAM "Super Admin"). A product that is missing there has no API access.
 *  - ZIA: the role's featurePermissions (READ_WRITE / READ_ONLY / NONE) from GET /adminRoles?includeApiRoles=true.
 *  - ZPA: the role's classPermissionGroups (FULL / VIEW_ONLY / NONE), found by the role name in the token.
 *  - Client Connector: GET getAdminRoles, by role name (2 = full, 1 = view only, 0 = none).
 *  - ZDX, AI Guard, Z-Insights: presence and role name only (ZDX's role API answers 500 on ZTH).
 * Nothing secret is read or returned: claim names, product names, role names and permission names only.
 */
'use strict';
const list = (r) => (Array.isArray(r) ? r : (r && (r.list || r.items || r.records)) || []);

const PRODUCTS = {
  ZIA: { label: 'Internet Access (ZIA)', feature: 'zia' },
  ZPA: { label: 'Private Access (ZPA)', feature: 'zpa' },
  ZCC: { label: 'Client Connector (ZCC)', feature: 'zcc' },
  ZDX: { label: 'Digital Experience (ZDX)', feature: 'zdx' },
  ZGUARD: { label: 'AI Guard', feature: 'aiguard' },
  ZINSIGHTS: { label: 'Z-Insights (Prove it totals)', feature: null, optional: true }
};

/** ZIA feature permission → what the wizard uses it for. */
const ZIA_NEEDS = [
  { perm: 'URL_FILTERING_CONTROL', for: 'URL Filtering rules' },
  { perm: 'CUSTOM_URL_CAT', for: 'custom URL categories (presets, AI Guard allow)' },
  { perm: 'CLOUD_APP_CONTROL', for: 'Cloud App Control rules' },
  { perm: 'SSL_POLICY', for: 'SSL Inspection rules' },
  { perm: 'FIREWALL_CONTROL', for: 'Firewall and geo-block rules, QUIC block' },
  { perm: 'IP_FQDN_GROUPS', for: 'IP / FQDN destination groups (AI Guard)' },
  { perm: 'DNS_CONTROL', for: 'DNS Control rules (DoH, Trusted Resolver, tunnels)' },
  { perm: 'FILE_TYPE_CONTROL', for: 'File Type Control rules' },
  { perm: 'ADVANCED_THREAT_PROTECTION', for: 'Advanced Threat Protection settings' },
  { perm: 'MALWARE_PROTECTION', for: 'malware protection settings' },
  { perm: 'CLOUD_SANDBOX', for: 'Cloud Sandbox rules' },
  { perm: 'DLP_DICTIONARIES_ENGINES', for: 'DLP dictionaries and engines' },
  { perm: 'INLINE_DLP', for: 'web DLP rules' },
  { perm: 'END_POINT_DLP', for: 'Endpoint DLP rules', optional: true },
  { perm: 'ADVANCED_SETTINGS', for: 'AI prompt capture, Microsoft 365 / UCaaS one-click settings' },
  { perm: 'BROWSER_ISOLATION', for: 'Isolate rules (isolation profiles)' },
  { perm: 'FORWARDING_CONTROL', for: 'AI Guard forwarding rule', product: 'aiguard' },
  { perm: 'PROXY_GATEWAY', for: 'AI Guard proxy and gateway', product: 'aiguard' }
];
/** ZPA object classes the wizard writes (matched on the role's friendly class names). */
const ZPA_NEEDS = [
  { re: /^Application$|Application Segment/i, for: 'application segments' },
  { re: /Segment Group|ApplicationGroup/i, for: 'segment groups' },
  { re: /Server Group/i, for: 'server groups' },
  { re: /Connector Group|AssistantGroup/i, for: 'App Connector groups' },
  { re: /Provisioning/i, for: 'provisioning keys' },
  { re: /Policy|Policies/i, for: 'access / timeout / inspection / isolation policies' },
  { re: /Inspection/i, for: 'AppProtection (inspection) profiles', optional: true },
  { re: /Isolation|Browser Isolation/i, for: 'isolation profiles', optional: true },
  { re: /Privileged|PRA/i, for: 'Privileged Remote Access', optional: true }
];
/** Client Connector role fields the wizard uses. */
const ZCC_NEEDS = [
  { key: 'windowsProfile', for: 'Windows app profiles' }, { key: 'macProfile', for: 'macOS app profiles' },
  { key: 'forwardingProfile', for: 'forwarding profiles' }, { key: 'appBypass', for: 'bypass apps' },
  { key: 'enrolledDevicesGroup', for: 'devices and one-time passwords', optional: true }, { key: 'deviceOverview', for: 'device list', optional: true }
];

/** Products and role names from the token (no secrets: names only). */
function tokenInfo(accessToken) {
  try {
    const p = JSON.parse(Buffer.from(String(accessToken).split('.')[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
    const si = Array.isArray(p['service-info']) ? p['service-info'] : [];
    const out = {};
    for (const s of si) out[s.prd] = { role: s.ext && s.ext.rnm || null, roleId: s.ext && s.ext.rid ? String(s.ext.rid) : null, tenant: s.tnt || null };
    return { ok: true, products: out };
  } catch (e) { return { ok: false, products: {} }; }
}

/**
 * client: the signed-in ZIA client (OneAPI); zpa: ZPA client or null; zccClient: ZCC client or null;
 * wants: { zia, zpa, zcc, zdx, aiguard } = what this POV uses (missing = assume all).
 * Returns { products: [ { product, label, access, role, status, missing: [...], readOnly: [...], fix, detail } ], checks }.
 */
async function permissions({ client, zpa, zccClient, wants }) {
  const w = wants || { zia: true, zpa: true, zcc: true, zdx: true, aiguard: false };
  const t = client && client.authMode === 'oneapi' ? tokenInfo(client.accessToken) : { ok: false, products: {} };
  const rows = [];
  const needed = (p) => p === 'ZIA' ? (w.zia !== false || w.aiguard) : p === 'ZPA' ? w.zpa !== false : p === 'ZCC' ? w.zcc !== false : p === 'ZDX' ? w.zdx !== false : p === 'ZGUARD' ? !!w.aiguard : false;
  for (const [prd, meta] of Object.entries(PRODUCTS)) {
    const have = t.products[prd];
    const row = { product: prd, label: meta.label, needed: needed(prd), access: !!have, role: have ? have.role : null, missing: [], readOnly: [], status: 'pass', detail: '', fix: null };
    if (!t.ok) { row.status = 'info'; row.detail = 'Signed in without a OneAPI token, so API permissions were not checked.'; rows.push(row); continue; }
    if (!have) {
      row.status = row.needed ? 'fail' : 'info';
      row.detail = row.needed ? `This API client has no ${meta.label} access, and this POV uses it.` : `No ${meta.label} access (not used by this POV).`;
      row.fix = `In ZIdentity › Integration › API Clients, edit the client and add a ${prd === 'ZGUARD' ? 'AI Guard' : prd} role (full access for the POV).`;
      rows.push(row); continue;
    }
    try {
      if (prd === 'ZIA') {
        const r = list(await client.apiCall('GET', '/api/v1/adminRoles?includeApiRoles=true')).find(x => String(x.id) === String(have.roleId) || x.name === have.role);
        const fp = (r && r.featurePermissions) || null;
        if (!fp) row.detail = `Role "${have.role}": its permissions could not be read, so they were not checked.`;
        else {
          for (const n of ZIA_NEEDS) {
            if (n.product === 'aiguard' && !w.aiguard) continue;
            const v = fp[n.perm];
            if (v === 'READ_WRITE') continue;
            (v === 'READ_ONLY' ? row.readOnly : row.missing).push({ perm: n.perm, for: n.for, optional: !!n.optional });
          }
        }
      } else if (prd === 'ZPA' && zpa) {
        const roles = list(await zpa.apiCall('GET', `${await zpa.base()}/roles`));
        const r = roles.find(x => x.name === have.role || String(x.id) === String(have.roleId));
        if (!r) row.detail = /full access|super/i.test(have.role || '') ? `Role "${have.role}" (a full-access role).` : `Role "${have.role}": not listed in ZPA roles, so its permissions were not checked.`;
        else {
          const cls = (r.classPermissionGroups || []).flatMap(g => g.classPermissions || []).map(c => ({ name: (c.classType && c.classType.friendlyName) || '', type: c.permission && c.permission.type }));
          for (const n of ZPA_NEEDS) {
            const hit = cls.filter(c => n.re.test(c.name));
            if (!hit.length) continue;
            if (hit.every(c => c.type === 'FULL')) continue;
            (hit.some(c => c.type === 'VIEW_ONLY') ? row.readOnly : row.missing).push({ perm: [...new Set(hit.map(c => c.name))].join(', '), for: n.for, optional: !!n.optional });
          }
        }
      } else if (prd === 'ZCC' && zccClient) {
        const roles = list(await zccClient.apiCall('GET', '/zcc/papi/public/v1/getAdminRoles'));
        const r = roles.find(x => x.roleName === have.role || String(x.id) === String(have.roleId));
        if (!r) row.detail = `Role "${have.role}": not listed in Client Connector roles, so its permissions were not checked.`;
        else for (const n of ZCC_NEEDS) {
          const v = String(r[n.key]);
          if (v === '2') continue;
          (v === '1' ? row.readOnly : row.missing).push({ perm: n.key, for: n.for, optional: !!n.optional });
        }
      }
    } catch (e) { row.detail = `Could not read the ${prd} role: ${String(e.message).slice(0, 160)}`; }
    const hard = [...row.missing, ...row.readOnly].filter(x => !x.optional);
    if (!row.detail) row.detail = `Role "${have.role}".`;
    if (hard.length) {
      row.status = row.needed ? 'warn' : 'info';
      row.detail += ` Missing or read-only: ${hard.map(x => `${x.perm} (${x.for})`).join('; ')}.`;
      row.fix = prd === 'ZIA' ? `In ZIA › Administration › Role Management, give "${have.role}" Full (read/write) for: ${hard.map(x => x.perm).join(', ')}.`
        : prd === 'ZPA' ? `In ZPA › Administration › Role Management, give "${have.role}" Full access to: ${hard.map(x => x.perm).join(', ')}.`
        : `In Client Connector › Administration › Role Management, give "${have.role}" Full access to: ${hard.map(x => x.perm).join(', ')}.`;
    } else if ([...row.missing, ...row.readOnly].length) {
      row.detail += ` Optional features without write access: ${[...row.missing, ...row.readOnly].map(x => x.for).join('; ')}.`;
    } else row.detail += prd === 'ZIA' || prd === 'ZPA' || prd === 'ZCC' ? ' Everything the wizard writes is allowed.' : '';
    rows.push(row);
  }
  const checks = rows.map(r => ({ area: 'API access', name: r.label, status: r.status, detail: r.detail, ...(r.fix ? { fix: r.fix } : {}) }));
  return { tokenRead: t.ok, products: rows, checks };
}

module.exports = { permissions, tokenInfo, ZIA_NEEDS, ZPA_NEEDS, ZCC_NEEDS, PRODUCTS };
