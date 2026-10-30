/**
 * v2.4 routes: Active POVs and saved templates.
 *
 *   GET    /api/v2/povs                     list (summaries), newest activity first
 *   POST   /api/v2/povs                     create for the signed-in tenant and open it in this session
 *   GET    /api/v2/povs/active              the POV open in this session (or null)
 *   GET    /api/v2/povs/:id                 full POV (plan, resume point, runs, tests, criteria, timeline, notes, follow-ups)
 *   PUT    /api/v2/povs/:id                 edit status / criteria / timeline / notes / follow-ups / resume point
 *   POST   /api/v2/povs/:id/open            open in this session; refused when signed in to a different tenant
 *   POST   /api/v2/povs/close               close the open POV in this session
 *   DELETE /api/v2/povs/:id                 archive (moved to povs/_archive)
 *   GET    /api/v2/povs/:id/export          one-file export (no secrets)
 *   POST   /api/v2/povs/import              import an exported POV
 *   GET|POST /api/v2/pov-templates, GET|DELETE /api/v2/pov-templates/:id
 *
 * Listing and reading POVs works before signing in when the wizard runs on this computer (loopback), so you can see
 * where you left off and which tenant to sign in to. Everything else needs a session.
 */
'use strict';
const povs = require('./povs');
const tests = require('./pov-tests');

function register(app, requireAuth, { v2 }) {
  const isLocal = (req) => /^(::1|127\.0\.0\.1|::ffff:127\.0\.0\.1)$/.test(String(req.socket && req.socket.remoteAddress || ''));
  // on this computer a signed-out (or expired) browser can still see its POVs; a valid session is attached when there is one
  const localOrAuth = (req, res, next) => {
    if (!isLocal(req)) return requireAuth(req, res, next);
    if (!req.headers['x-session-id']) return next();
    const soft = { status: () => ({ json: () => next() }) };
    return requireAuth(req, soft, next);
  };
  const sessionTenant = (s) => ({ vanity: s.client.vanityDomain, cloud: s.client.cloud || 'production' });
  const fail = (res, e) => res.status(e.status || 500).json({ error: e.message, ...(e.extra || {}) });

  // Every change made while a POV is open is copied into that POV once the request has finished.
  app.use((req, res, next) => {
    if (req.method !== 'GET') res.on('finish', () => {
      try { const st = req.session && req.session.v2; if (st && st.povId && res.statusCode < 500) povs.syncFromSession(st.povId, st); } catch (e) { /* the POV file is best effort */ }
    });
    next();
  });

  app.get('/api/v2/povs', localOrAuth, (req, res) => res.json({ povs: povs.listAll(tests.runbook), dir: povs.DIR }));

  app.get('/api/v2/povs/active', requireAuth, (req, res) => {
    const st = v2(req.session);
    if (!st.povId) return res.json({ pov: null, tenant: sessionTenant(req.session) });
    try { res.json({ pov: povs.load(st.povId), tenant: sessionTenant(req.session) }); } catch (e) { st.povId = null; res.json({ pov: null, tenant: sessionTenant(req.session) }); }
  });

  app.post('/api/v2/povs', requireAuth, (req, res) => {
    try {
      const b = req.body || {};
      const p = povs.create({ customerName: b.customerName, prefix: b.prefix, tenant: sessionTenant(req.session), guide: b.guide || null, templateId: b.templateId || null });
      const st = v2(req.session);
      Object.assign(st, { povId: p.id, runs: povs.emptyRuns(), testResults: {}, posture: null, lastShadow: null, coverageSummary: null, prefix: p.prefix || st.prefix });
      req.session.logger.log('POV_CREATE', { id: p.id, customer: p.customerName });
      res.json({ pov: p });
    } catch (e) { fail(res, e); }
  });

  app.post('/api/v2/povs/close', requireAuth, (req, res) => {
    const st = v2(req.session);
    Object.assign(st, { povId: null, runs: povs.emptyRuns(), testResults: {}, posture: null, lastShadow: null, coverageSummary: null });
    res.json({ closed: true });
  });

  app.post('/api/v2/povs/import', requireAuth, (req, res) => {
    try { const p = povs.importPov(req.body); res.json({ pov: povs.summary(p, tests.runbook) }); } catch (e) { fail(res, e); }
  });

  app.get('/api/v2/povs/:id', localOrAuth, (req, res) => {
    try {
      const p = povs.load(req.params.id);
      res.json({ pov: p, summary: povs.summary(p, tests.runbook), tests: tests.runbook(p.runs || {}, p.testResults || {}) });
    } catch (e) { fail(res, e); }
  });

  app.put('/api/v2/povs/:id', localOrAuth, (req, res) => {
    try {
      const b = { ...(req.body || {}) };
      // the resume point is only written by the session that has this POV open
      const st = req.session && req.session.v2;
      if (b.guide !== undefined && !(st && st.povId === req.params.id)) delete b.guide;
      const p = povs.update(req.params.id, b);
      res.json({ pov: p, summary: povs.summary(p, tests.runbook) });
    } catch (e) { fail(res, e); }
  });

  app.post('/api/v2/povs/:id/open', requireAuth, (req, res) => {
    try {
      const p = povs.load(req.params.id);
      const have = sessionTenant(req.session);
      if (povs.tenantKey(p.tenant) && povs.tenantKey(p.tenant) !== povs.tenantKey(have)) {
        return res.status(409).json({ error: `This POV belongs to ${p.tenant.vanity} (${p.tenant.cloud}), but you are signed in to ${have.vanity} (${have.cloud}). Sign in to the POV's tenant to open it; nothing was changed.`, povTenant: p.tenant, sessionTenant: have });
      }
      if (!povs.tenantKey(p.tenant)) { p.tenant = have; povs.save(p); }   // imported without a tenant: bind it now
      const st = v2(req.session);
      const runs = { ...povs.emptyRuns(), ...(p.runs || {}) };
      Object.assign(st, { povId: p.id, runs, testResults: p.testResults || {}, intake: p.intake || null, prefix: p.prefix || st.prefix, posture: p.posture || null, lastShadow: p.shadow || null, coverageSummary: p.coverage || null });
      req.session.logger.log('POV_OPEN', { id: p.id, customer: p.customerName });
      res.json({ pov: p });
    } catch (e) { fail(res, e); }
  });

  app.delete('/api/v2/povs/:id', localOrAuth, (req, res) => {
    try {
      const st = req.session && req.session.v2;
      if (st && st.povId === req.params.id) Object.assign(st, { povId: null, runs: povs.emptyRuns(), testResults: {}, posture: null, lastShadow: null, coverageSummary: null });
      res.json(povs.archive(req.params.id));
    } catch (e) { fail(res, e); }
  });

  app.get('/api/v2/povs/:id/export', localOrAuth, (req, res) => {
    try { res.json(povs.exportPov(req.params.id)); } catch (e) { fail(res, e); }
  });

  // ---------- templates ----------
  app.get('/api/v2/pov-templates', localOrAuth, (req, res) => res.json({ templates: povs.listTemplates() }));
  app.get('/api/v2/pov-templates/:id', localOrAuth, (req, res) => { try { res.json({ template: povs.loadTemplate(req.params.id) }); } catch (e) { fail(res, e); } });
  app.post('/api/v2/pov-templates', localOrAuth, (req, res) => { try { res.json({ template: povs.saveTemplate(req.body || {}) }); } catch (e) { fail(res, e); } });
  app.delete('/api/v2/pov-templates/:id', localOrAuth, (req, res) => { try { res.json(povs.deleteTemplate(req.params.id)); } catch (e) { fail(res, e); } });
}

module.exports = { register };
