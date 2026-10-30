/**
 * v2.8: a small Word (.docx) writer with no dependencies, for the POV report and the compliance pack.
 * Input is a list of blocks: { h: 1|2|3, text } · { p: text, bold? , color? } · { bullets: [text] } · { numbers: [text] }
 * · { table: { head: [..], rows: [[..]], widths?: [pct..] } } · { note: text } (a shaded callout).
 * Markdown from the existing report converts with fromMarkdown(). Inline **bold** and `code` are kept.
 */
'use strict';
const zlib = require('zlib');

// ---------- zip (deflate, no data descriptors) ----------
const CRC = (() => { const t = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
const crc32 = (buf) => { let c = 0xFFFFFFFF; for (let i = 0; i < buf.length; i++) c = CRC[(c ^ buf[i]) & 0xFF] ^ (c >>> 8); return (c ^ 0xFFFFFFFF) >>> 0; };
function zip(files) {
  const parts = [], central = [];
  let offset = 0;
  const d = new Date(), dosTime = (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1), dosDate = ((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate();
  for (const f of files) {
    const name = Buffer.from(f.name, 'utf8');
    const data = Buffer.isBuffer(f.data) ? f.data : Buffer.from(f.data, 'utf8');
    const comp = zlib.deflateRawSync(data);
    const crc = crc32(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4); local.writeUInt16LE(0x0800, 6); local.writeUInt16LE(8, 8);
    local.writeUInt16LE(dosTime, 10); local.writeUInt16LE(dosDate, 12); local.writeUInt32LE(crc, 14); local.writeUInt32LE(comp.length, 18);
    local.writeUInt32LE(data.length, 22); local.writeUInt16LE(name.length, 26); local.writeUInt16LE(0, 28);
    parts.push(local, name, comp);
    const cen = Buffer.alloc(46);
    cen.writeUInt32LE(0x02014b50, 0); cen.writeUInt16LE(20, 4); cen.writeUInt16LE(20, 6); cen.writeUInt16LE(0x0800, 8); cen.writeUInt16LE(8, 10);
    cen.writeUInt16LE(dosTime, 12); cen.writeUInt16LE(dosDate, 14); cen.writeUInt32LE(crc, 16); cen.writeUInt32LE(comp.length, 20); cen.writeUInt32LE(data.length, 24);
    cen.writeUInt16LE(name.length, 28); cen.writeUInt32LE(offset, 42);
    central.push(cen, name);
    offset += 30 + name.length + comp.length;
  }
  const cenBuf = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(files.length, 8); end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(cenBuf.length, 12); end.writeUInt32LE(offset, 16);
  return Buffer.concat([...parts, cenBuf, end]);
}

// ---------- WordprocessingML ----------
const x = (s) => String(s === undefined || s === null ? '' : s).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
/** Runs from text with **bold** and `code`. */
function runs(text, { bold = false, color = null, size = null } = {}) {
  const out = [];
  const re = /(\*\*[^*]+\*\*|`[^`]+`)/g;
  let last = 0, m;
  const s = String(text === undefined || text === null ? '' : text);
  const run = (t, b, mono) => {
    if (!t) return;
    const pr = [b ? '<w:b/>' : '', mono ? '<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas"/>' : '', color ? `<w:color w:val="${color}"/>` : '', size ? `<w:sz w:val="${size}"/>` : ''].join('');
    out.push(`<w:r>${pr ? `<w:rPr>${pr}</w:rPr>` : ''}<w:t xml:space="preserve">${x(t)}</w:t></w:r>`);
  };
  while ((m = re.exec(s))) { run(s.slice(last, m.index), bold, false); const t = m[0]; if (t.startsWith('**')) run(t.slice(2, -2), true, false); else run(t.slice(1, -1), bold, true); last = m.index + t.length; }
  run(s.slice(last), bold, false);
  return out.join('');
}
const para = (text, opts = {}) => `<w:p>${opts.style ? `<w:pPr><w:pStyle w:val="${opts.style}"/>${opts.numId ? `<w:numPr><w:ilvl w:val="0"/><w:numId w:val="${opts.numId}"/></w:numPr>` : ''}${opts.shade ? `<w:shd w:val="clear" w:color="auto" w:fill="${opts.shade}"/>` : ''}</w:pPr>` : ''}${runs(text, opts)}</w:p>`;
function table(t) {
  const cols = Math.max(t.head ? t.head.length : 0, ...(t.rows || []).map(r => r.length));
  const total = 9638;   // A4/Letter text width in twentieths of a point (about 6.7 inches)
  const w = (t.widths && t.widths.length === cols ? t.widths : Array(cols).fill(100 / cols)).map(p => Math.round(total * p / 100));
  const cell = (v, i, head) => `<w:tc><w:tcPr><w:tcW w:w="${w[i]}" w:type="dxa"/>${head ? '<w:shd w:val="clear" w:color="auto" w:fill="E8EEF5"/>' : ''}</w:tcPr>${String(v === undefined || v === null ? '' : v).split('\n').map(line => `<w:p><w:pPr><w:spacing w:before="20" w:after="20"/></w:pPr>${runs(line, { bold: head, size: 18 })}</w:p>`).join('')}</w:tc>`;
  const row = (r, head) => `<w:tr>${head ? '<w:trPr><w:tblHeader/></w:trPr>' : ''}${Array.from({ length: cols }, (_, i) => cell(r[i], i, head)).join('')}</w:tr>`;
  return `<w:tbl><w:tblPr><w:tblW w:w="${total}" w:type="dxa"/><w:tblBorders>${['top', 'left', 'bottom', 'right', 'insideH', 'insideV'].map(b => `<w:${b} w:val="single" w:sz="4" w:space="0" w:color="C9D3DF"/>`).join('')}</w:tblBorders><w:tblLayout w:type="fixed"/></w:tblPr>`
    + `<w:tblGrid>${w.map(v => `<w:gridCol w:w="${v}"/>`).join('')}</w:tblGrid>${t.head ? row(t.head, true) : ''}${(t.rows || []).map(r => row(r, false)).join('')}</w:tbl><w:p/>`;
}
function body(blocks) {
  return blocks.map(b => {
    if (b.h) return para(b.text, { style: `Heading${b.h}` });
    if (b.p !== undefined) return para(b.p, { bold: b.bold, color: b.color });
    if (b.note) return para(b.note, { style: 'Note', shade: 'FFF4DC' });
    if (b.bullets) return b.bullets.map(t => para(t, { style: 'ListParagraph', numId: 1 })).join('');
    if (b.numbers) return b.numbers.map(t => para(t, { style: 'ListParagraph', numId: 2 })).join('');
    if (b.table) return table(b.table);
    return '';
  }).join('');
}

const STYLES = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:cs="Calibri"/><w:sz w:val="21"/><w:color w:val="14202E"/></w:rPr></w:rPrDefault><w:pPrDefault><w:pPr><w:spacing w:after="100" w:line="276" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>
<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style>
<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:after="60"/></w:pPr><w:rPr><w:b/><w:sz w:val="40"/><w:color w:val="0B3B6F"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Subtitle"><w:name w:val="Subtitle"/><w:basedOn w:val="Normal"/><w:rPr><w:color w:val="5B6B7F"/><w:sz w:val="19"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="320" w:after="100"/><w:outlineLvl w:val="0"/></w:pPr><w:rPr><w:b/><w:sz w:val="30"/><w:color w:val="0B3B6F"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="240" w:after="80"/><w:outlineLvl w:val="1"/></w:pPr><w:rPr><w:b/><w:sz w:val="25"/><w:color w:val="0B5CAD"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="180" w:after="60"/><w:outlineLvl w:val="2"/></w:pPr><w:rPr><w:b/><w:sz w:val="22"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="ListParagraph"><w:name w:val="List Paragraph"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:after="40"/><w:ind w:left="720"/></w:pPr></w:style>
<w:style w:type="paragraph" w:styleId="Note"><w:name w:val="Note"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:before="80" w:after="120"/></w:pPr><w:rPr><w:color w:val="8A5A00"/></w:rPr></w:style>
</w:styles>`;
const NUMBERING = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:numbering xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:abstractNum w:abstractNumId="0"><w:lvl w:ilvl="0"><w:start w:val="1"/><w:numFmt w:val="bullet"/><w:lvlText w:val="•"/><w:lvlJc w:val="left"/><w:pPr><w:ind w:left="720" w:hanging="360"/></w:pPr></w:lvl></w:abstractNum>
<w:abstractNum w:abstractNumId="1"><w:lvl w:ilvl="0"><w:start w:val="1"/><w:numFmt w:val="decimal"/><w:lvlText w:val="%1."/><w:lvlJc w:val="left"/><w:pPr><w:ind w:left="720" w:hanging="360"/></w:pPr></w:lvl></w:abstractNum>
<w:num w:numId="1"><w:abstractNumId w:val="0"/></w:num><w:num w:numId="2"><w:abstractNumId w:val="1"/></w:num>
</w:numbering>`;

/** { title, subtitle, blocks, landscape } → Buffer (.docx) */
function build({ title, subtitle = '', blocks = [], landscape = false }) {
  const pg = landscape ? '<w:pgSz w:w="15840" w:h="12240" w:orient="landscape"/>' : '<w:pgSz w:w="12240" w:h="15840"/>';
  const doc = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><w:body>
${para(title, { style: 'Title' })}${subtitle ? para(subtitle, { style: 'Subtitle' }) : ''}${body(blocks)}
<w:sectPr>${pg}<w:pgMar w:top="1080" w:right="1080" w:bottom="1080" w:left="1080" w:header="708" w:footer="708" w:gutter="0"/></w:sectPr></w:body></w:document>`;
  return zip([
    { name: '[Content_Types].xml', data: '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/><Override PartName="/word/numbering.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/></Types>' },
    { name: '_rels/.rels', data: '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/></Relationships>' },
    { name: 'docProps/core.xml', data: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><dc:title>${x(title)}</dc:title><dc:creator>ZTP Policy Wizard</dc:creator><dcterms:created xsi:type="dcterms:W3CDTF">${new Date().toISOString().replace(/\.\d+Z$/, 'Z')}</dcterms:created></cp:coreProperties>` },
    { name: 'word/_rels/document.xml.rels', data: '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/numbering" Target="numbering.xml"/></Relationships>' },
    { name: 'word/document.xml', data: doc },
    { name: 'word/styles.xml', data: STYLES },
    { name: 'word/numbering.xml', data: NUMBERING }
  ]);
}

/** The report's Markdown → blocks (headings, paragraphs, bullet and numbered lists, pipe tables, > notes, ``` code). */
function fromMarkdown(md) {
  const lines = String(md || '').split(/\r?\n/);
  const blocks = [];
  let title = null, subtitle = null;
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (!l.trim()) continue;
    let m;
    if ((m = l.match(/^(#{1,3})\s+(.*)$/))) { if (m[1].length === 1 && title === null) { title = m[2]; continue; } blocks.push({ h: Math.max(1, m[1].length - 1), text: m[2] }); continue; }
    if (l.startsWith('```')) { const code = []; for (i++; i < lines.length && !lines[i].startsWith('```'); i++) code.push(lines[i]); blocks.push({ p: '`' + code.join(' ') + '`' }); continue; }
    if (/^>\s?/.test(l)) { blocks.push({ note: l.replace(/^>\s?/, '') }); continue; }
    if (/^\|/.test(l)) {
      const rows = [];
      for (; i < lines.length && /^\|/.test(lines[i]); i++) if (!/^\|\s*-{2,}/.test(lines[i])) rows.push(lines[i].replace(/^\||\|$/g, '').split(/(?<!\\)\|/).map(c => c.trim().replace(/\\\|/g, '|')));
      i--;
      blocks.push({ table: { head: rows[0], rows: rows.slice(1) } });
      continue;
    }
    if (/^\s*[-*]\s+/.test(l)) { const items = []; for (; i < lines.length && /^\s*[-*]\s+/.test(lines[i]); i++) items.push(lines[i].replace(/^\s*[-*]\s+/, '')); i--; blocks.push({ bullets: items }); continue; }
    if (/^\s*\d+\.\s+/.test(l)) { const items = []; for (; i < lines.length && /^\s*\d+\.\s+/.test(lines[i]); i++) items.push(lines[i].replace(/^\s*\d+\.\s+/, '')); i--; blocks.push({ numbers: items }); continue; }
    if (subtitle === null && title !== null && !blocks.length) { subtitle = l.replace(/`/g, ''); continue; }
    blocks.push({ p: l.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '$1 ($2)') });
  }
  return { title: title || 'Report', subtitle: subtitle || '', blocks };
}

module.exports = { build, fromMarkdown, zip, crc32 };
