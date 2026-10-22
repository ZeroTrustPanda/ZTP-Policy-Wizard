/**
 * v2.5 routes: AI Guard (ZIA proxy chaining to AI Guard, AI app inspection, prompt capture, zguard API check).
 *   GET  /api/v2/aiguard/context   read-only checks + app catalogue + root certificates / gateways in ZIA
 *   POST /api/v2/aiguard/plan      dry run (planId)
 *   POST /api/v2/aiguard/apply     apply after a dry run of the same input; snapshot for restore; activates ZIA
 */
'use strict';
const crypto = require('crypto');
const ag = require('./aiguard');
const snapshots = require('./snapshots');

function register(app, requireAuth, { v2, rememberPlan, checkPlan, countActions }) {
  const PREFIX_RE = /^[A-Za-z0-9_-]{1,20}$/;
  function input(body, session) {
    const b = body || {};
    const prefix = String(b.prefix || v2(session).prefix || '').trim();
    if (!PREFIX_RE.test(prefix)) throw Object.assign(new Error('Set the prefix first (customer intake).'), { status: 400 });
    const c = b.cert || {};
    const cert = c.mode === 'existing' ? { mode: 'existing', id: c.id } : c.mode === 'upload' ? { mode: 'upload', pem: String(c.pem || '') } : {};
    return { prefix, apps: Array.isArray(b.apps) ? b.apps.filter(id => ag.AI_APPS.some(a => a.id === id)) : [], extraDomains: Array.isArray(b.extraDomains) ? b.extraDomains.slice(0, 50) : [],
      includeCloudMicrosoft: !!b.includeCloudMicrosoft, cert, blockQuic: b.blockQuic !== false, sslInspect: b.sslInspect !== false, promptCapture: b.promptCapture !== false };
  }
  // the plan id covers the certificate by hash (the PEM itself is never logged or stored)
  const planKey = (i) => ({ ...i, cert: i.cert.mode === 'upload' ? { mode: 'upload', sha: crypto.createHash('sha256').update(i.cert.pem.trim()).digest('hex') } : i.cert });
  const forRecord = (i) => ({ ...i, cert: i.cert.mode === 'upload' ? { mode: 'upload' } : i.cert });

  app.get('/api/v2/aiguard/context', requireAuth, async (req, res) => {
    try {
      const ctx = await ag.context(req.session.client);
      res.json({ ...ctx, apps: ag.AI_APPS.map(a => ({ id: a.id, name: a.name, domains: a.domains, prompt: !!a.prompt, default: !!a.default })), cloudMicrosoft: ag.CLOUD_MICROSOFT,
        proxy: ag.AI_GUARD_PROXY, names: ag.names(v2(req.session).prefix || 'PREFIX') });
    } catch (e) { res.status(502).json({ error: e.message }); }
  });

  app.post('/api/v2/aiguard/plan', requireAuth, async (req, res) => {
    try {
      const i = input(req.body, req.session);
      const run = await ag.runAiGuard(req.session.client, i, { dryRun: true });
      const planId = rememberPlan(req.session, 'aiguard', planKey(i));
      req.session.logger.log('V2_AIGUARD_DRY_RUN', { counts: countActions(run.ledger), apps: i.apps, domains: run.domains.length });
      res.json({ planId, ledger: run.ledger, counts: countActions(run.ledger), warnings: run.warnings, followUps: run.followUps, gatewayMissing: run.gatewayMissing, names: run.names, domains: run.domains });
    } catch (e) { res.status(e.status || 502).json({ error: e.message }); }
  });

  app.post('/api/v2/aiguard/apply', requireAuth, async (req, res) => {
    try {
      const i = input(req.body, req.session);
      const bad = checkPlan(req.session, 'aiguard', planKey(i), req.body.planId);
      if (bad) return res.status(409).json({ error: bad });
      const run = await ag.runAiGuard(req.session.client, i, { dryRun: false, logger: req.session.logger });
      const snapshot = snapshots.save({ product: 'zia', prefix: i.prefix, undo: run.undo, tenant: req.session.client.vanityDomain || req.session.client.baseUrl });
      const st = v2(req.session); st.runs.aiguard = st.runs.aiguard || [];
      st.runs.aiguard.push({ at: new Date().toISOString(), ledger: run.ledger, warnings: run.warnings, followUps: run.followUps, input: forRecord(i), snapshot, activated: run.activated });
      req.session.logger.log('V2_AIGUARD_APPLY', { counts: countActions(run.ledger), activated: run.activated });
      res.json({ ledger: run.ledger, counts: countActions(run.ledger), warnings: run.warnings, followUps: run.followUps, activated: run.activated, gatewayMissing: run.gatewayMissing, snapshot });
    } catch (e) { res.status(e.status || 502).json({ error: e.message }); }
  });
}

module.exports = { register };
