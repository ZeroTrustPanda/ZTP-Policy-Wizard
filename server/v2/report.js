/**
 * Post-run summary report (§9, RPT-01..05): Markdown plus a printable HTML page (print to PDF from the browser).
 * Built from what actually ran in this session (the ledgers), not from the plan.
 */
const COPY = require('./copy');
const { SCOPE_ITEMS } = require('./scope');

const esc = (s) => String(s === undefined || s === null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const ACTION_WORD = { MANUAL: 'Manual step', CREATE: 'Created', UPDATE: 'Updated', NO_CHANGE: 'Unchanged', FAILED: 'Failed', SKIPPED: 'Skipped', DELETED: 'Deleted' };

function collect(runs) {
  const rows = [];
  for (const product of ['zia', 'aiguard', 'zcc', 'zpa']) for (const run of (runs[product] || [])) for (const e of (run.ledger || [])) rows.push({ ...e, product: product === 'aiguard' ? 'AI Guard' : product.toUpperCase() });
  return rows;
}

/** runs: { zia:[{at, template, ledger, warnings, activated}], zcc:[{at, ledger, warnings}], zpa:[{at, ledger, warnings, secrets, names}] } */
function buildReport({ runs, prefix, tenant, licensing, endpointWarning, includeSecrets = true, tests = [], posture = null, shadow = null, coverage = null }) {
  const rows = collect(runs);
  const zia = (runs.zia || [])[runs.zia ? runs.zia.length - 1 : 0];
  const zpa = (runs.zpa || [])[runs.zpa ? runs.zpa.length - 1 : 0];
  const pk = includeSecrets && zpa && zpa.secrets && zpa.secrets.provisioningKey;
  // Tamper protection passwords set on ZCC app profiles in this session (latest per profile)
  const pw = new Map();
  if (includeSecrets) for (const r of runs.zcc || []) if (r.secrets && r.secrets.tamperPassword) pw.set(r.secrets.profile, r.secrets.tamperPassword);
  const key = pk || pw.size > 0;
  const warnings = [...new Set([...(runs.zia || []), ...(runs.aiguard || []), ...(runs.zcc || []), ...(runs.zpa || [])].flatMap(r => r.warnings || []).map(w => typeof w === 'string' ? w : w.text))];
  const followUps = [];
  if (runs.zpa && runs.zpa.length) followUps.push(...(zpa.followUps || [COPY.report.followUps.zpaLocation, COPY.report.followUps.zpaDeploy]));
  if (pw.size) followUps.push(COPY.report.followUps.otp);
  const ag = (runs.aiguard || []).slice(-1)[0];
  if (ag) followUps.push(...(ag.followUps || []));
  if (zia && zia.template && ['urlFiltering', 'sandbox'].some(k => (zia.template.policies[k] || []).some(r => r.action === 'ISOLATE' || r.firstTimeOperation === 'QUARANTINE_ISOLATE'))) followUps.push(COPY.report.followUps.isolationProfile);
  if (zia && zia.template && zia.template.metadata.scope.endpointDlp && endpointWarning) followUps.push(COPY.report.followUps.endpointDlp);
  if ((runs.zcc || []).some(r => (r.manualSteps || []).some(m => m.key === 'modernUi'))) followUps.push(COPY.report.followUps.modernUi);
  if (zia && zia.template && (zia.template.generationNotes || []).length) warnings.push(...zia.template.generationNotes);
  if (zia && zia.activated === false) followUps.push('Activate the pending ZIA changes in the ZIA admin portal (automatic activation failed).');
  // v2.8: what the API could not write, as portal steps
  for (const m of (zia && zia.manualSteps) || []) { const t = `${m.area}: ${m.step}`; if (!followUps.includes(t)) followUps.push(t); }
  const P = require('./posture');
  const cmp = posture ? P.compare(posture.start, posture.end) : null;
  const pScore = (r) => (r && r.score !== null && r.score !== undefined ? `${r.score} (${r.maturity})` : (r ? r.maturity : 'not taken'));

  const scopeOn = zia ? SCOPE_ITEMS.filter(i => zia.template.metadata.scope[i.key]).map(i => i.label) : [];
  const baseline = zia ? zia.template.metadata.baseline : null;
  const decisions = [];
  if (zia) {
    for (const [type, rules] of Object.entries(zia.template.policies)) {
      if (Array.isArray(rules)) for (const r of rules) {
        const act = type === 'cloudAppControl' ? (r.actions || []).join(', ') : type === 'fileTypeControl' ? r.filteringAction
          : type === 'sandbox' ? `First time: ${r.firstTimeOperation}${r.mlActionEnabled ? ', AI Instant Verdict' : ''}`
          : typeof r.action === 'object' ? r.action.type : r.action;
        decisions.push({ type, name: r.name, action: act || '', changed: !!(r.userChoice && r.actionChanged !== false) });
      } else if (rules && rules.settings) for (const s of rules.settings) decisions.push({ type, name: s.label, action: s.skip ? 'left as is' : (s.value ? 'On' : 'Off') });
    }
  }
  const counts = {};
  for (const r of rows) { counts[r.product] = counts[r.product] || {}; counts[r.product][r.action] = (counts[r.product][r.action] || 0) + 1; }
  const when = new Date().toISOString();

  // ---------- Markdown ----------
  const md = [];
  md.push(`# Zscaler POV configuration summary`, '');
  if (key) md.push(`> **${COPY.report.sensitive}**`, '');
  md.push(`Generated ${when}${tenant ? ` · Tenant: ${tenant}` : ''} · Prefix: \`${prefix}\``, '');
  if (baseline) md.push(`## Baseline`, '', `${baseline.name} (${baseline.type === 'tier' ? 'non-mapped security level' : 'compliance framework'}), framework definition ${baseline.version}, researched ${baseline.researchedAt}.`, '');
  if (zia) md.push(`## Scope`, '', ...scopeOn.map(s => `- ${s}`), '');
  md.push(`## Objects by product`, '');
  for (const [p, c] of Object.entries(counts)) md.push(`- **${p}**: ${Object.entries(c).map(([a, n]) => `${ACTION_WORD[a] || a} ${n}`).join(', ')}`);
  md.push('', '| Product | Type | Name | Result | Detail |', '|---|---|---|---|---|');
  for (const r of rows) md.push(`| ${r.product} | ${r.category} | ${r.name} | ${ACTION_WORD[r.action] || r.action} | ${(r.error || (r.changes ? 'Changed: ' + r.changes.join(', ') : '') || r.note || '').replace(/\|/g, '\\|')} |`);
  md.push('');
  if (decisions.length) {
    md.push('## Rule decisions (ZIA)', '', '| Area | Rule / setting | Action |', '|---|---|---|');
    for (const d of decisions) md.push(`| ${d.type} | ${d.name} | ${d.action} |`);
    md.push('');
  }
  if (posture && (posture.start || posture.end)) {
    md.push('## Security posture: start and end of the POV', '', `Start: **${pScore(posture.start)}** · End: **${pScore(posture.end)}**${cmp && cmp.delta !== null ? ` · Change: **${cmp.delta >= 0 ? '+' : ''}${cmp.delta} points**` : ''}`, '');
    if (cmp && cmp.improved.length) { md.push('Improved during the POV:', ''); for (const i of cmp.improved) md.push(`- ${i.area}: ${i.label}`); md.push(''); }
    const last = posture.end || posture.start;
    const open = (last.results || []).filter(r => r.status === 'fail' || r.status === 'review');
    if (open.length) {
      md.push('Still open (what was found, what it means, what to do, the outcome):', '', '| Area | Check | Finding |', '|---|---|---|');
      for (const r of open) md.push(`| ${r.area} | ${r.label} | ${[r.found, r.means, r.do, r.outcome].filter(Boolean).join(' ').replace(/\|/g, '\\|')} |`);
      md.push('');
    }
    md.push((last && last.method) || '', '');
  }
  if (shadow && shadow.findings) {
    md.push('## Customer rules that decide before the POV rules', '', shadow.summary || '', '');
    if (shadow.findings.length) { md.push('| POV rule | Decided by | Why | Fix |', '|---|---|---|---|'); for (const f of shadow.findings) md.push(`| ${f.rule} | ${f.by.name} (order ${f.by.order}) | ${f.reason.replace(/\|/g, '\\|')} | ${f.fix.replace(/\|/g, '\\|')} |`); md.push(''); }
    if (shadow.note) md.push(shadow.note, '');
  }
  if (coverage && coverage.headline) {
    md.push('## Inspection coverage', '', coverage.headline, '');
    for (const i of (coverage.items || []).slice(0, 12)) md.push(`- **${i.area}**: ${i.title}`);
    md.push('');
  }
  if (pk) md.push('## ZPA provisioning key', '', `**${COPY.report.sensitive}**`, '', '```', pk, '```', '', COPY.zpa.keyNote, '');
  if (pw.size) { md.push('## Client Connector tamper protection passwords', '', `**${COPY.report.sensitive}**`, ''); for (const [n, v] of pw) md.push(`- ${n}: \`${v}\``); md.push('', COPY.report.tamperNote, ''); }
  const RES = { pass: 'Pass', fail: 'Fail', skip: 'Skipped' };
  if (tests.length) {
    md.push('## POV tests', '', '| Product | Test | Result | Note |', '|---|---|---|---|');
    for (const t of tests) md.push(`| ${t.product} | ${t.title} | ${t.result ? RES[t.result.status] : 'Not run'} | ${((t.result && t.result.note) || '').replace(/\|/g, '\\|')} |`);
    md.push('');
  }
  if (warnings.length) { md.push('## Warnings', ''); for (const w of warnings) md.push(`- ${w}`); md.push(''); }
  if (licensing && licensing.items) {
    const lic = Object.entries(licensing.items).filter(([, v]) => v.licensed !== true);
    if (lic.length) { md.push('## Licensing', ''); for (const [k, v] of lic) md.push(`- ${(SCOPE_ITEMS.find(i => i.key === k) || {}).label || k}: ${v.reason}`); md.push(''); }
  }
  md.push('## Manual follow-ups', '');
  if (followUps.length) followUps.forEach((f, i) => md.push(`${i + 1}. ${f}`)); else md.push('None.');
  md.push('');
  if (zia && zia.template.metadata.sources) {
    md.push('## Framework sources', '');
    for (const s of zia.template.metadata.sources) md.push(`- [${s.title}](${s.url})`);
    md.push('');
  }
  const markdown = md.join('\n');

  // ---------- HTML (print-friendly) ----------
  const badge = (a) => `<span class="b b-${String(a).toLowerCase()}">${esc(ACTION_WORD[a] || a)}</span>`;
  const html = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Zscaler POV Summary${prefix ? ' — ' + esc(prefix) : ''}</title>
<style>
:root{--ink:#14202e;--muted:#5b6b7f;--line:#d9e1ea;--bg:#fff;--warn:#8a5a00;--warnbg:#fff4dc;--bad:#a1271b;--badbg:#fde7e4;--ok:#1d6b3a;--okbg:#e3f5ea;--accent:#0b5cad}
*{box-sizing:border-box}body{font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;color:var(--ink);background:var(--bg);margin:0;padding:32px 16px}
main{max-width:1000px;margin:0 auto}h1{font-size:24px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 8px;border-bottom:1px solid var(--line);padding-bottom:4px}
.meta{color:var(--muted)}.secret{background:var(--badbg);color:var(--bad);border:1px solid var(--bad);padding:10px 12px;border-radius:6px;font-weight:600;margin:12px 0}
table{width:100%;border-collapse:collapse;font-size:12.5px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:600}
.b{display:inline-block;padding:1px 7px;border-radius:10px;font-size:11.5px;font-weight:600}.b-create,.b-deleted{background:var(--okbg);color:var(--ok)}.b-update{background:#e4eefb;color:var(--accent)}
.b-no_change{background:#eef1f4;color:var(--muted)}.b-failed{background:var(--badbg);color:var(--bad)}.b-skipped{background:var(--warnbg);color:var(--warn)}
code.key{display:block;padding:10px;background:#f4f6f8;border:1px solid var(--line);border-radius:6px;word-break:break-all;font-size:12px}
ul,ol{padding-left:20px}.warn li{color:var(--warn)}@media print{body{padding:0}h2{break-after:avoid}tr{break-inside:avoid}}
</style></head><body><main>
<h1>Zscaler POV configuration summary</h1>
<div class="meta">Generated ${esc(when)}${tenant ? ' · Tenant: ' + esc(tenant) : ''} · Prefix: <code>${esc(prefix)}</code></div>
${key ? `<div class="secret">${esc(COPY.report.sensitive)}</div>` : ''}
${baseline ? `<h2>Baseline</h2><p>${esc(baseline.name)} (${baseline.type === 'tier' ? 'non-mapped security level' : 'compliance framework'}), framework definition ${esc(baseline.version)}, researched ${esc(baseline.researchedAt)}.</p>` : ''}
${zia ? `<h2>Scope</h2><ul>${scopeOn.map(s => `<li>${esc(s)}</li>`).join('')}</ul>` : ''}
<h2>Objects by product</h2>
<p>${Object.entries(counts).map(([p, c]) => `<strong>${esc(p)}</strong>: ${Object.entries(c).map(([a, n]) => `${esc(ACTION_WORD[a] || a)} ${n}`).join(', ')}`).join(' &nbsp;·&nbsp; ') || 'Nothing ran yet.'}</p>
<table><thead><tr><th>Product</th><th>Type</th><th>Name</th><th>Result</th><th>Detail</th></tr></thead><tbody>
${rows.map(r => `<tr><td>${esc(r.product)}</td><td>${esc(r.category)}</td><td>${esc(r.name)}</td><td>${badge(r.action)}</td><td>${esc(r.error || (r.changes ? 'Changed: ' + r.changes.join(', ') : '') || r.note || '')}</td></tr>`).join('')}
</tbody></table>
${decisions.length ? `<h2>Rule decisions (ZIA)</h2><table><thead><tr><th>Area</th><th>Rule / setting</th><th>Action</th></tr></thead><tbody>${decisions.map(d => `<tr><td>${esc(d.type)}</td><td>${esc(d.name)}</td><td>${esc(d.action)}</td></tr>`).join('')}</tbody></table>` : ''}
${pk ? `<h2>ZPA provisioning key</h2><div class="secret">${esc(COPY.report.sensitive)}</div><code class="key">${esc(pk)}</code><p>${esc(COPY.zpa.keyNote)}</p>` : ''}
${pw.size ? `<h2>Client Connector tamper protection passwords</h2><div class="secret">${esc(COPY.report.sensitive)}</div>${[...pw].map(([n, v]) => `<p>${esc(n)}</p><code class="key">${esc(v)}</code>`).join('')}<p>${esc(COPY.report.tamperNote)}</p>` : ''}
${tests.length ? `<h2>POV tests</h2><table><thead><tr><th>Product</th><th>Test</th><th>Result</th><th>Note</th></tr></thead><tbody>${tests.map(t => `<tr><td>${esc(t.product)}</td><td>${esc(t.title)}</td><td>${t.result ? badge(t.result.status === 'pass' ? 'CREATE' : t.result.status === 'fail' ? 'FAILED' : 'SKIPPED').replace(/>[^<]*</, `>${RES[t.result.status]}<`) : 'Not run'}</td><td>${esc((t.result && t.result.note) || '')}</td></tr>`).join('')}</tbody></table>` : ''}
${posture && (posture.start || posture.end) ? `<h2>Security posture: start and end of the POV</h2><p>Start: <strong>${esc(pScore(posture.start))}</strong> · End: <strong>${esc(pScore(posture.end))}</strong>${cmp && cmp.delta !== null ? ` · Change: <strong>${cmp.delta >= 0 ? '+' : ''}${cmp.delta} points</strong>` : ''}</p>${cmp && cmp.improved.length ? `<p>Improved during the POV:</p><ul>${cmp.improved.map(i => `<li>${esc(i.area)}: ${esc(i.label)}</li>`).join('')}</ul>` : ''}${(() => { const last = posture.end || posture.start; const open = (last.results || []).filter(r => r.status === 'fail' || r.status === 'review'); return open.length ? `<table><thead><tr><th>Area</th><th>Check</th><th>Finding</th></tr></thead><tbody>${open.map(r => `<tr><td>${esc(r.area)}</td><td>${esc(r.label)}</td><td>${esc([r.found, r.means, r.do, r.outcome].filter(Boolean).join(' '))}</td></tr>`).join('')}</tbody></table><p class="meta">${esc(last.method || '')}</p>` : ''; })()}` : ''}
${shadow && shadow.findings ? `<h2>Customer rules that decide before the POV rules</h2><p>${esc(shadow.summary || '')}</p>${shadow.findings.length ? `<table><thead><tr><th>POV rule</th><th>Decided by</th><th>Why</th><th>Fix</th></tr></thead><tbody>${shadow.findings.map(f => `<tr><td>${esc(f.rule)}</td><td>${esc(f.by.name)} (order ${esc(f.by.order)})</td><td>${esc(f.reason)}</td><td>${esc(f.fix)}</td></tr>`).join('')}</tbody></table>` : ''}${shadow.note ? `<p class="meta">${esc(shadow.note)}</p>` : ''}` : ''}
${coverage && coverage.headline ? `<h2>Inspection coverage</h2><p>${esc(coverage.headline)}</p><ul>${(coverage.items || []).slice(0, 12).map(i => `<li><strong>${esc(i.area)}</strong>: ${esc(i.title)}</li>`).join('')}</ul>` : ''}
${warnings.length ? `<h2>Warnings</h2><ul class="warn">${warnings.map(w => `<li>${esc(w)}</li>`).join('')}</ul>` : ''}
<h2>Manual follow-ups</h2>${followUps.length ? `<ol>${followUps.map(f => `<li>${esc(f)}</li>`).join('')}</ol>` : '<p>None.</p>'}
${zia && zia.template.metadata.sources ? `<h2>Framework sources</h2><ul>${zia.template.metadata.sources.map(s => `<li><a href="${esc(s.url)}">${esc(s.title)}</a></li>`).join('')}</ul>` : ''}
</main></body></html>`;
  return { markdown, html, containsSecret: !!key };
}

module.exports = { buildReport };
