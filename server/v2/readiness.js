/**
 * v2.2: tenant readiness check, run right after sign-in (read-only).
 * Each check: { area, name, status: 'pass'|'warn'|'fail'|'info', detail, fix? }.
 * One failing area never stops the others; the Client Connector check costs one ZCC call (rate-limited API).
 */
'use strict';
const { licenceChecks } = require('./licences');
const list = (r) => (Array.isArray(r) ? r : (r && (r.list || r.items)) || []);

async function safe(checks, area, name, fn) {
  try { const r = await fn(); if (r) checks.push({ area, name, ...r }); }
  catch (e) { checks.push({ area, name, status: e.rateLimitedUntil ? 'info' : 'warn', detail: e.rateLimitedUntil ? `Skipped: ${e.message}` : `Could not check: ${String(e.message).slice(0, 200)}` }); }
}

async function readiness({ client, zccClient, zdxClient, zpa, licensing }) {
  const checks = [];
  let licenceSummary = null;
  // ---------- ZIA ----------
  await safe(checks, 'ZIA', 'Pending changes', async () => {
    const st = await client.apiCall('GET', '/api/v1/status');
    const pending = st && /PENDING/i.test(st.status || '');
    return { status: pending ? 'warn' : 'pass', detail: pending ? 'Changes are waiting for activation in ZIA. The wizard activates its own changes, which also activates these.' : 'No pending changes.' };
  });
  await safe(checks, 'ZIA', 'SSL rule order', async () => {
    const rules = list(await client.apiCall('GET', '/api/v1/sslInspectionRules')).filter(r => !r.defaultRule).sort((a, b) => a.order - b.order);
    const ex = rules.find(r => r.predefined && /Recommended Exemptions/i.test(r.name));
    const catchAll = rules.filter(r => !r.predefined && r.state !== 'DISABLED' && r.action && r.action.type === 'DECRYPT' && !(r.urlCategories || []).length && !(r.cloudApplications || []).length);
    const above = ex ? catchAll.filter(r => r.order < ex.order) : [];
    if (above.length) return { status: 'warn', detail: `${above.map(r => `"${r.name}" (order ${r.order})`).join(', ')} inspects all traffic above "Zscaler Recommended Exemptions" (order ${ex.order}), so those exemptions never apply.`, fix: 'Move the rule below the exemptions. Rules the wizard owns are moved automatically on the next run.' };
    return { status: 'pass', detail: ex ? `Inspect-all rules sit below "Zscaler Recommended Exemptions" (order ${ex.order}).` : 'No predefined exemption rule found.' };
  });
  await safe(checks, 'ZIA', 'Isolation profile (Cloud Browser Isolation)', async () => {
    const p = list(await client.apiCall('GET', '/api/v1/browserIsolation/profiles'));
    return p.length ? { status: 'pass', detail: `${p.length} profile(s): ${p.map(x => x.name).join(', ')}` }
      : { status: 'warn', detail: 'No isolation profile. Isolate rules fall back to Caution.', fix: 'Add Cloud Browser Isolation to the tenant to show isolation.' };
  });
  await safe(checks, 'ZIA', 'Zscaler Trusted Resolver', async () => {
    const g = list(await client.apiCall('GET', '/api/v1/dnsGateways')).find(x => x.natZtrGateway);
    return g ? { status: 'pass', detail: `${g.name} is available for the DNS resolver rule.` } : { status: 'warn', detail: 'No Trusted Resolver DNS gateway; the resolver rule is skipped.' };
  });
  await safe(checks, 'ZIA', 'Users and groups (identity)', async () => {
    const groups = list(await client.apiCall('GET', '/api/v1/groups?pageSize=100'));
    return groups.length ? { status: 'pass', detail: `${groups.length >= 100 ? '100+' : groups.length} group(s) synced from the identity provider.` }
      : { status: 'warn', detail: 'No user groups yet.', fix: 'Connect the identity provider (SAML/SCIM) in ZIdentity so users can sign in to Client Connector.' };
  });
  // ---------- Licensing (v2.3: whole tenant, compared with a fully licensed POV tenant) ----------
  {
    let raw = null, zpaCustomer = null;
    try { raw = await client.apiCall('GET', '/api/v1/subscriptions'); } catch (e) { raw = null; }
    if (zpa) { try { zpaCustomer = await zpa.apiCall('GET', await zpa.base()); } catch (e) { zpaCustomer = null; } }
    const lic = licenceChecks(raw, { zpaCustomer });
    checks.push(...lic.checks);
    licenceSummary = lic.summary;
  }

  // ---------- ZPA ----------
  if (zpa) {
    await safe(checks, 'ZPA', 'App Connectors', async () => {
      const c = await zpa.listAll('/connector');
      const up = c.filter(x => /ZPN_STATUS_AUTHENTICATED/i.test(x.controlChannelStatus || '') || /AUTHENTICATED|UP/i.test(x.runtimeStatus || ''));
      if (!c.length) return { status: 'warn', detail: 'No App Connectors enrolled yet.', fix: 'Deploy an App Connector with the provisioning key the ZPA step creates.' };
      return { status: up.length ? 'pass' : 'warn', detail: `${up.length} of ${c.length} App Connector(s) online.` };
    });
    await safe(checks, 'ZPA', 'Privileged Remote Access portal', async () => {
      const p = await zpa.listAll('/praPortal');
      return p.length ? { status: 'pass', detail: `Portal: ${p.map(x => `${x.name} (${x.domain})`).join(', ')}` }
        : { status: 'info', detail: 'No PRA portal. PRA consoles are a manual step until one exists (domain + certificate).' };
    });
    await safe(checks, 'ZPA', 'Web certificates (Browser Access)', async () => {
      const certs = await zpa.listAll('/certificate');
      const now = Date.now() / 1000;
      const valid = certs.filter(c => !c.validToInEpochSec || Number(c.validToInEpochSec) > now);
      return valid.length ? { status: 'pass', detail: `${valid.length} valid certificate(s): ${valid.map(c => c.name).join(', ')}` }
        : { status: 'info', detail: 'No valid web certificate. Browser Access needs one (upload it in the ZPA portal).' };
    });
    await safe(checks, 'ZPA', 'Isolation for ZPA', async () => {
      const p = await zpa.listAll('/isolation/profiles');
      return p.length ? { status: 'pass', detail: `${p.length} ZPA isolation profile(s).` } : { status: 'info', detail: 'No ZPA isolation profile; the isolation policy is skipped.' };
    });
  }

  // ---------- Client Connector ----------
  if (zccClient) await safe(checks, 'ZCC', 'Enrolled devices', async () => {
    const d = list(await zccClient.apiCall('GET', '/zcc/papi/public/v1/getDevices?page=1&pageSize=500'));
    const reg = d.filter(x => /Registered/i.test(x.registrationState || ''));
    return reg.length ? { status: 'pass', detail: `${reg.length >= 500 ? '500+' : reg.length} registered device(s).` }
      : { status: 'info', detail: 'No registered devices yet.', fix: 'Use Devices & Install to build the install command for the first test machine.' };
  });

  // ---------- ZDX ----------
  if (zdxClient) await safe(checks, 'ZDX', 'ZDX reachable', async () => {
    const apps = list(await zdxClient.apiCall('GET', '/config/applications'));
    return { status: 'pass', detail: `${apps.length} configured app(s).` };
  });

  const counts = checks.reduce((c, x) => { c[x.status] = (c[x.status] || 0) + 1; return c; }, {});
  return { checks, counts, licences: licenceSummary, at: new Date().toISOString() };
}

module.exports = { readiness };
