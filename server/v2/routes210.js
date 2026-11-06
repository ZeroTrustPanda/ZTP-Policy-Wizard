/**
 * v2.10 routes.
 *   GET /api/v2/zpa/locations  App Connector Group locations to pick from (a custom city can be entered too)
 *   GET /api/v2/zia/cac-apps   the apps with per-app Cloud App Control rules, their default actions and the actions this
 *                              tenant offers for each (read with /webApplicationRules/{type}/availableActions, cached per session)
 */
'use strict';
const { CAC_APPS } = require('../templates');

const VERB = /^(ALLOW|DENY|BLOCK|CAUTION|ISOLATE)_(.+)$/;
// When ZIA lists no actions for an app (seen on ZTH for CLAUDE_AI), the whole-app actions of its type are offered instead;
// ZTH accepted ALLOW_AI_ML_WEB_USE for such apps (2026-10-22).
const WHOLE_APP = {
  AI_ML: ['ALLOW_AI_ML_WEB_USE', 'CAUTION_AI_ML_WEB_USE', 'DENY_AI_ML_WEB_USE', 'ISOLATE_AI_ML_WEB_USE'],   // upload controls are not offered for these apps
  SOCIAL_NETWORKING: ['ALLOW_SOCIAL_NETWORKING_VIEW', 'CAUTION_SOCIAL_NETWORKING_VIEW', 'BLOCK_SOCIAL_NETWORKING_VIEW', 'ISOLATE_SOCIAL_NETWORKING_VIEW', 'ALLOW_SOCIAL_NETWORKING_POST', 'BLOCK_SOCIAL_NETWORKING_POST'],
  FILE_SHARE: ['ALLOW_FILE_SHARE_VIEW', 'DENY_FILE_SHARE_VIEW', 'ALLOW_FILE_SHARE_UPLOAD', 'DENY_FILE_SHARE_UPLOAD']
};
const list = (r) => (Array.isArray(r) ? r : (r && (r.list || r.items)) || []);

/** Group action names by operation: { op: 'UPLOAD', label: 'Upload', verbs: { DENY: 'DENY_AI_ML_UPLOAD', … } }. */
function operations(actions, type) {
  const ops = new Map();
  for (const a of actions) {
    const m = VERB.exec(a);
    if (!m || !m[2].startsWith(type + '_')) continue;   // conditional access and other non-verb actions are left out
    const op = m[2].slice(type.length + 1);
    if (!ops.has(op)) ops.set(op, { op, label: op.replace(/_/g, ' ').toLowerCase().replace(/^\w/, c => c.toUpperCase()), verbs: {} });
    ops.get(op).verbs[m[1]] = a;
  }
  const first = ['WEB_USE', 'VIEW', 'LOGIN', 'CHAT', 'POST', 'UPLOAD', 'DOWNLOAD', 'SHARE'];
  return [...ops.values()].sort((x, y) => ((first.indexOf(x.op) + 1) || 99) - ((first.indexOf(y.op) + 1) || 99) || x.op.localeCompare(y.op));
}

function register(app, requireAuth, { v2 }) {
  app.get('/api/v2/zpa/locations', requireAuth, (req, res) => res.json({ locations: require('./zpa').LOCATIONS.map(l => ({ id: l.id, label: l.label, countryCode: l.countryCode })), default: 'us-sjc' }));

  app.get('/api/v2/zia/cac-apps', requireAuth, async (req, res) => {
    const st = v2(req.session);
    if (st.cacApps && Date.now() - st.cacApps.at < 10 * 60 * 1000 && !req.query.refresh) return res.json(st.cacApps.data);
    const out = [];
    for (const a of CAC_APPS) {
      let offered = null, error = null;
      try { offered = list(await req.session.client.apiCall('POST', `/api/v1/webApplicationRules/${a.type}/availableActions`, { cloudApps: [a.app], type: a.type })).map(String); }
      catch (e) { error = e.message; }
      const fromTenant = !!(offered && offered.length);
      const actions = fromTenant ? offered : WHOLE_APP[a.type];
      // what the rule is created with by default on this tenant: the first set if ZIA offers all of it, else the fallback set
      const ok = (set) => set && set.length && set.every(x => actions.includes(x));
      const defaults = ok(a.actions) ? a.actions : ok(a.fallbackActions) ? a.fallbackActions : (a.actions || []).filter(x => actions.includes(x));
      out.push({ app: a.app, label: a.label, key: `cloudAppControl:${a.key}`, type: a.type, defaults, optional: !a.actions, fromTenant, error,
        operations: operations(actions, a.type) });
    }
    const data = { apps: out };
    st.cacApps = { at: Date.now(), data };
    res.json(data);
  });
}

module.exports = { register, operations };
