/**
 * v2.9: custom block and caution pages (ZIA End User Notifications).
 *
 * ZIA builds the block and caution pages itself; what can be changed through the API is the message text of each page, and
 * that text may carry a <style> block (help.zscaler.com, "Customizing EUNs with CSS Styles"). The theme builder turns a few
 * choices (colours, font, heading, message, logo, support contact) into that <style> block plus the message, for the block
 * page (customText) and the caution page (cautionCustomText). Advanced users can add their own CSS on top.
 *
 * The page's own CSS classes (from the Zscaler article): bh box header, eu_h header text, eu_co content, "eu_co rsn" reason,
 * "eu_co ln" link, "eu_co fo" footer, "eu_co st" static text, s_img static image, btn button, m_tbl table width, uq_cd unique
 * code (left alone: Support needs it). Background class per page: red block, yl caution, gr AUP, or quarantine.
 *
 * The company logo (Administration › Organization) has no write API, so the logo is embedded in the message as a small
 * data: image instead, and the same compressed file is offered for upload in the portal. ZIA's limit there is 10 KB.
 *
 * Every write goes through a dry run (planId), keeps an Undo snapshot of the settings it replaced and activates afterwards.
 */
'use strict';

const LOGO_MAX = 10 * 1024;
const FONTS = {
  system: 'Segoe UI, -apple-system, Helvetica, Arial, sans-serif',
  arial: 'Arial, Helvetica, sans-serif',
  helvetica: 'Helvetica Neue, Helvetica, Arial, sans-serif',
  verdana: 'Verdana, Geneva, sans-serif',
  tahoma: 'Tahoma, Geneva, sans-serif',
  georgia: 'Georgia, Times New Roman, serif',
  mono: 'Consolas, Menlo, monospace'
};
const DEFAULTS = {
  primary: '#0b3b6f', accent: '#0b5cad', background: '#f4f6f9', text: '#1f2933', cautionColor: '#b7791f', font: 'system',
  blockHeading: 'This site is blocked', blockMessage: 'Access to this site is blocked by company policy.',
  cautionHeading: 'Proceed with caution', cautionMessage: 'This site may not be appropriate for work. Continue only if you need it for your job.',
  supportEmail: '', supportPhone: '', policyLink: '', showReason: true, showCompanyName: true, hideStaticText: false,
  width: 640, logo: null, rawCss: ''
};

const COLOR = /^#([0-9a-f]{3}|[0-9a-f]{6})$/i;
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const bad = (msg) => Object.assign(new Error(msg), { status: 400 });

/** A data: URL of a PNG, JPEG or GIF of at most 10 KB, checked by its first bytes. Returns { mime, bytes, width, height }. */
function checkLogo(dataUrl) {
  const m = /^data:image\/(png|jpeg|gif);base64,([A-Za-z0-9+/=]+)$/.exec(String(dataUrl || ''));
  if (!m) throw bad('The logo must be a PNG, JPEG or GIF image.');
  const buf = Buffer.from(m[2], 'base64');
  if (buf.length > LOGO_MAX) throw bad(`The logo is ${(buf.length / 1024).toFixed(1)} KB; ZIA allows 10 KB. Compress it first (the wizard does this when you choose a file).`);
  let kind = null, width = null, height = null;
  if (buf.length > 24 && buf.readUInt32BE(0) === 0x89504e47) { kind = 'png'; width = buf.readUInt32BE(16); height = buf.readUInt32BE(20); }
  else if (buf.length > 10 && buf.slice(0, 6).toString('latin1').match(/^GIF8[79]a$/)) { kind = 'gif'; width = buf.readUInt16LE(6); height = buf.readUInt16LE(8); }
  else if (buf.length > 4 && buf[0] === 0xff && buf[1] === 0xd8) {
    kind = 'jpeg';
    for (let i = 2; i + 9 < buf.length;) {
      if (buf[i] !== 0xff) { i++; continue; }
      const marker = buf[i + 1], len = buf.readUInt16BE(i + 2);
      if (marker >= 0xc0 && marker <= 0xcf && ![0xc4, 0xc8, 0xcc].includes(marker)) { height = buf.readUInt16BE(i + 5); width = buf.readUInt16BE(i + 7); break; }
      i += 2 + len;
    }
  }
  const declared = m[1] === 'jpeg' ? 'jpeg' : m[1];
  if (kind !== declared) throw bad('The logo file does not match its type. Use a PNG, JPEG or GIF.');
  return { mime: `image/${m[1]}`, bytes: buf.length, width, height };
}

/** Normalise the theme from the browser: unknown keys dropped, colours and lengths checked. */
function normalizeTheme(input) {
  const t = { ...DEFAULTS };
  const src = input && typeof input === 'object' ? input : {};
  for (const k of ['primary', 'accent', 'background', 'text', 'cautionColor']) {
    if (src[k] === undefined || src[k] === '') continue;
    if (!COLOR.test(String(src[k]))) throw bad(`${k}: use a colour like #0b3b6f.`);
    t[k] = String(src[k]).toLowerCase();
  }
  if (src.font !== undefined) { if (!FONTS[src.font]) throw bad('Unknown font.'); t.font = src.font; }
  for (const [k, max] of [['blockHeading', 120], ['blockMessage', 1200], ['cautionHeading', 120], ['cautionMessage', 1200], ['supportEmail', 120], ['supportPhone', 40], ['policyLink', 400]]) {
    if (src[k] === undefined) continue;
    const v = String(src[k]).trim();
    if (v.length > max) throw bad(`${k} is too long (at most ${max} characters).`);
    t[k] = v;
  }
  if (t.supportEmail && !/^[^\s@<>"]+@[^\s@<>"]+\.[^\s@<>"]+$/.test(t.supportEmail)) throw bad('Support email does not look like an email address.');
  if (t.supportPhone && !/^[0-9+().\s-]{3,40}$/.test(t.supportPhone)) throw bad('Support phone: digits, spaces, + ( ) . - only.');
  if (t.policyLink && !/^https:\/\/[^\s<>"']+$/.test(t.policyLink)) throw bad('Policy link must start with https://');
  for (const k of ['showReason', 'showCompanyName', 'hideStaticText']) if (src[k] !== undefined) t[k] = !!src[k];
  if (src.width !== undefined) { const w = Number(src.width); if (!(w >= 320 && w <= 790)) throw bad('Page width: 320 to 790 pixels.'); t.width = Math.round(w); }
  if (src.logo) { checkLogo(src.logo); t.logo = String(src.logo); } else t.logo = null;
  if (src.rawCss !== undefined) {
    const css = String(src.rawCss);
    if (css.length > 6000) throw bad('Extra CSS is too long (at most 6000 characters).');
    // CSS only: no markup, no way out of the <style> block, no script or remote loads
    if (/[<>]|\/\*\s*<|expression\s*\(|javascript:|@import|url\s*\(\s*['"]?\s*(?!data:image\/)/i.test(css)) throw bad('Extra CSS may not contain < >, @import, expression(), javascript: or url() to other sites.');
    t.rawCss = css;
  }
  return t;
}

function css(t, page) {
  const font = FONTS[t.font] || FONTS.system;
  const band = page === 'caution' ? t.cautionColor : t.primary;
  const bg = page === 'caution' ? '.yl' : '.red';
  const rules = [
    `${bg}{background-color:${t.background}}`,
    `.m_tbl{width:90%;max-width:${t.width}px}`,
    `.bh{background-color:${band};color:#fff;font-family:${font}}`,
    `.eu_h{color:#fff;font-family:${font}}`,
    `.eu_co{color:${t.text};font-family:${font}}`,
    `.eu_co.ln a,.eu_co a{color:${t.accent}}`,
    `.btn{background:${t.accent};border-color:${t.accent};color:#fff}`,
    `.ztp-hd{display:flex;align-items:center;gap:12px;margin:0 0 8px}`,
    `.ztp-hd img{max-height:56px;max-width:180px}`,
    `.ztp-hd h2{margin:0;font-size:20px;color:${band};font-family:${font}}`,
    `.ztp-sp{margin-top:10px;font-size:13px;color:${t.text}}`
  ];
  if (t.hideStaticText) rules.push('.eu_co.st{display:none}', '.s_img{display:none}');
  return rules.join('') + (t.rawCss ? t.rawCss.replace(/\s+/g, ' ').trim() : '');
}

function message(t, page, { withLogo = true } = {}) {
  const heading = page === 'caution' ? t.cautionHeading : t.blockHeading;
  const text = page === 'caution' ? t.cautionMessage : t.blockMessage;
  const support = [t.supportEmail && `<a href="mailto:${esc(t.supportEmail)}">${esc(t.supportEmail)}</a>`, t.supportPhone && esc(t.supportPhone)].filter(Boolean).join(' · ');
  return `<style>${css(t, page)}</style>` +
    `<div class="ztp-hd">${withLogo && t.logo ? `<img src="${t.logo}" alt="">` : ''}${heading ? `<h2>${esc(heading)}</h2>` : ''}</div>` +
    (text ? `<p>${esc(text).replace(/\n/g, '<br>')}</p>` : '') +
    (support ? `<div class="ztp-sp">Need help? ${support}</div>` : '') +
    (t.policyLink ? `<div class="ztp-sp"><a href="${esc(t.policyLink)}" target="_blank" rel="noopener">Acceptable use policy</a></div>` : '');
}

/** The settings the theme writes. Only fields the tenant returns are written; the rest are reported. */
function desired(t, current, { withLogo = true } = {}) {
  const want = {
    customText: message(t, 'block', { withLogo }),
    cautionCustomText: message(t, 'caution', { withLogo }),
    displayReason: !!t.showReason,
    displayCompanyName: !!t.showCompanyName,
    // the portal logo (Administration › Organization) shows on the page too: turn it off when the theme embeds its own
    displayCompanyLogo: !t.logo,
    supportEmail: t.supportEmail || undefined,
    supportPhone: t.supportPhone || undefined,
    orgPolicyLink: t.policyLink || undefined
  };
  const values = {}, missing = [];
  for (const [k, v] of Object.entries(want)) {
    if (v === undefined) continue;
    if (current && Object.prototype.hasOwnProperty.call(current, k)) values[k] = v; else missing.push(k);
  }
  return { values, missing };
}

/** A stand-in for ZIA's page, with its class names, for the preview in the wizard (ZIA's own preview does not show CSS). */
function preview(t, page) {
  const bg = page === 'caution' ? 'yl' : 'red';
  const title = page === 'caution' ? 'Caution' : 'Website blocked';
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><style>
body{margin:0;font-family:Arial,sans-serif}.red{background:#b40000}.yl{background:#e8a200}.page{min-height:100vh;padding:24px 0}
.m_tbl{margin:0 auto;background:#fff;border-collapse:collapse;width:90%;max-width:790px;box-shadow:0 2px 10px rgba(0,0,0,.15)}
.bh{background:#444;padding:12px 16px}.eu_h{color:#fff;font-size:18px;font-weight:bold}.eu_co{padding:12px 16px;font-size:14px;color:#333}
.rsn{color:#555}.st{color:#777;font-size:12px}.fo{border-top:1px solid #ddd;font-size:11px;color:#888}.uq_cd{font-family:monospace}
.btn{display:inline-block;padding:6px 14px;background:#555;color:#fff;border:1px solid #555;border-radius:3px;text-decoration:none}
</style></head><body><div class="page ${bg}"><table class="m_tbl"><tr><td class="bh"><span class="eu_h">${title}</span></td></tr>
<tr><td class="eu_co">${message(t, page)}</td></tr>
${t.showReason ? `<tr><td class="eu_co rsn">${page === 'caution' ? 'The site example.com is in the category: Newly registered domains.' : 'Sorry, you don’t have permission to visit this site. It is in the category: Gambling.'}</td></tr>` : ''}
${page === 'caution' ? '<tr><td class="eu_co"><a class="btn" href="#">Continue</a></td></tr>' : ''}
<tr><td class="eu_co st">If you believe you should have access, contact your IT department.</td></tr>
<tr><td class="eu_co fo">${t.showCompanyName ? 'Your organization · ' : ''}<span class="uq_cd">Reference: 7f3a…</span></td></tr></table></div></body></html>`;
}

/** The current notification settings, for the form and the dry run. Long text fields are shortened. */
async function readCurrent(client) {
  const cur = await client.apiCall('GET', '/api/v1/eun');
  return cur || {};
}

/**
 * Dry run or apply. Uses the ZIA engine's settings writer, so Undo and activation work as for every other ZIA change.
 * If ZIA refuses the message with the embedded logo (field too long), it is written again without the logo and the
 * portal logo is switched on instead.
 */
async function run(client, theme, { dryRun, logger }) {
  const { ZiaEngine } = require('./zia-engine');
  const t = normalizeTheme(theme);
  const eng = new ZiaEngine(client, { dryRun, logger });
  let current;
  try { current = await readCurrent(client); }
  catch (e) { throw Object.assign(new Error(`Could not read the end user notification settings: ${e.message}`), { status: 502 }); }
  const { values, missing } = desired(t, current);
  const warnings = [];
  if (current.notificationType && current.notificationType !== 'DEFAULT') warnings.push(`This tenant sends users to its own notification page (${current.notificationType}${current.redirectUrl ? `: ${current.redirectUrl}` : ''}). The message and style are saved but only show if the notification type is set back to Default.`);
  if (missing.length) warnings.push(`Not offered by this tenant's API, left out: ${missing.join(', ')}.`);
  const sizes = { block: values.customText ? values.customText.length : 0, caution: values.cautionCustomText ? values.cautionCustomText.length : 0, logo: t.logo ? checkLogo(t.logo).bytes : 0 };
  let logoDropped = false;
  await eng.upsertSettings({ category: 'End User Notifications', name: 'Block and caution pages', path: '/api/v1/eun', values,
    putFilter: async (merged) => {
      try { await client.apiCall('PUT', '/api/v1/eun', merged); return {}; }
      catch (e) {
        if (!t.logo || !/length|too long|exceed|size|INVALID_INPUT|400/i.test(String(e.message))) throw e;
        const slim = desired(t, current, { withLogo: false }).values;
        await client.apiCall('PUT', '/api/v1/eun', { ...merged, ...slim, displayCompanyLogo: true });
        logoDropped = true;
        return { notes: ['ZIA did not accept the logo inside the page text, so the pages were saved without it and the portal company logo is shown instead. Upload the compressed logo in Administration › Organization.'] };
      }
    } });
  const activated = await eng.activate();
  return { ledger: eng.ledger, warnings: [...warnings, ...eng.warnings], undo: eng.undo, activated, sizes, logoDropped, theme: t };
}

module.exports = { normalizeTheme, checkLogo, desired, message, preview, run, readCurrent, DEFAULTS, FONTS, LOGO_MAX };
