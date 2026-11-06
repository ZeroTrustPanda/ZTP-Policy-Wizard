/**
 * v2.9 routes: custom block and caution pages (ZIA End User Notifications) and the company logo.
 *   GET  /api/v2/eun            current settings (message fields shortened) and the theme defaults
 *   POST /api/v2/eun/preview    { theme, page: 'block'|'caution' } → HTML stand-in of the page, for the preview frame
 *   POST /api/v2/eun/plan       dry run (planId)
 *   POST /api/v2/eun/apply      apply after a dry run of the same theme; Undo snapshot; activates ZIA
 * The pages are tenant-wide: they show for every user and every block or caution rule, not only the POV rules.
 */
'use strict';
const eun = require('./eun');
const snapshots = require('./snapshots');

function register(app, requireAuth, { v2, rememberPlan, checkPlan, countActions }) {
  const short = (v) => (typeof v === 'string' && v.length > 300 ? `${v.slice(0, 300)}… (${v.length} characters)` : v);

  app.get('/api/v2/eun', requireAuth, async (req, res) => {
    try {
      const cur = await eun.readCurrent(req.session.client);
      res.json({ current: Object.fromEntries(Object.entries(cur).map(([k, v]) => [k, short(v)])), defaults: eun.DEFAULTS, fonts: Object.keys(eun.FONTS), logoMax: eun.LOGO_MAX });
    } catch (e) { res.status(502).json({ error: `Could not read the end user notification settings: ${e.message}`, defaults: eun.DEFAULTS, fonts: Object.keys(eun.FONTS), logoMax: eun.LOGO_MAX }); }
  });

  app.post('/api/v2/eun/preview', requireAuth, (req, res) => {
    try {
      const t = eun.normalizeTheme((req.body || {}).theme);
      const page = req.body.page === 'caution' ? 'caution' : 'block';
      res.json({ html: eun.preview(t, page), size: eun.message(t, page).length, logo: t.logo ? eun.checkLogo(t.logo) : null });
    } catch (e) { res.status(e.status || 500).json({ error: e.message }); }
  });

  app.post('/api/v2/eun/plan', requireAuth, async (req, res) => {
    try {
      const t = eun.normalizeTheme((req.body || {}).theme);
      const run = await eun.run(req.session.client, t, { dryRun: true });
      const planId = rememberPlan(req.session, 'eun', t);
      req.session.logger.log('V2_EUN_DRY_RUN', { counts: countActions(run.ledger), sizes: run.sizes });
      res.json({ planId, ledger: run.ledger, counts: countActions(run.ledger), warnings: run.warnings, sizes: run.sizes });
    } catch (e) { res.status(e.status || 502).json({ error: e.message }); }
  });

  app.post('/api/v2/eun/apply', requireAuth, async (req, res) => {
    try {
      const t = eun.normalizeTheme((req.body || {}).theme);
      const bad = checkPlan(req.session, 'eun', t, req.body.planId);
      if (bad) return res.status(409).json({ error: bad });
      const run = await eun.run(req.session.client, t, { dryRun: false, logger: req.session.logger });
      const st = v2(req.session);
      const snapshot = snapshots.save({ product: 'zia', prefix: st.prefix || 'eun', undo: run.undo, tenant: req.session.client.vanityDomain || req.session.client.baseUrl });
      st.runs.eun = st.runs.eun || [];
      st.runs.eun.push({ at: new Date().toISOString(), ledger: run.ledger, warnings: run.warnings, snapshot, activated: run.activated, sizes: run.sizes, logoDropped: run.logoDropped });
      req.session.logger.log('V2_EUN_APPLY', { counts: countActions(run.ledger), activated: run.activated, logoDropped: run.logoDropped });
      res.json({ ledger: run.ledger, counts: countActions(run.ledger), warnings: run.warnings, activated: run.activated, snapshot, sizes: run.sizes, logoDropped: run.logoDropped });
    } catch (e) { res.status(e.status || 502).json({ error: e.message }); }
  });
}

module.exports = { register };
