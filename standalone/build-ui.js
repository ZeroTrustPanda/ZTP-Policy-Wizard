/**
 * Compile the UI into one self-contained HTML string for the standalone build.
 *  - JSX in public/index.html is compiled ahead of time (no Babel in the browser)
 *  - React / ReactDOM are inlined (no CDN)
 *  - IBM Plex fonts are inlined (no Google Fonts)
 * Output: standalone/dist/ui-bundle.js  (module.exports = "<!DOCTYPE html>...")
 */
const fs = require('fs');
const path = require('path');
const esbuild = require('esbuild');

const root = path.join(__dirname, '..');
// Read files straight from standalone/node_modules (some packages don't export these paths)
const nm = (p) => {
  const f = path.join(__dirname, 'node_modules', p);
  if (!fs.existsSync(f)) throw new Error(`Missing ${p}. Run "npm ci" in standalone/ first.`);
  return f;
};
let html = fs.readFileSync(path.join(root, 'public', 'index.html'), 'utf8');

// 1. Compile the text/babel block
const m = html.match(/<script type="text\/babel">([\s\S]*?)<\/script>/);
if (!m) throw new Error('No <script type="text/babel"> block found in public/index.html');
const compiled = esbuild.transformSync(m[1], { loader: 'jsx', jsxFactory: 'React.createElement', jsxFragment: 'React.Fragment', target: 'es2020', minify: true }).code;
const safe = (js) => js.replace(/<\/script/gi, '<\\/script');
html = html.replace(m[0], () => `<script>\n${safe(compiled)}\n</script>`);

// 2. Inline React / ReactDOM, drop Babel
const react = fs.readFileSync(nm('react/umd/react.production.min.js'), 'utf8');
const reactDom = fs.readFileSync(nm('react-dom/umd/react-dom.production.min.js'), 'utf8');
const swap = (re, replacement) => {
  if (!re.test(html)) throw new Error('Expected tag not found: ' + re);
  html = html.replace(re, () => replacement);
};
swap(/<script src="https:\/\/cdnjs\.cloudflare\.com\/ajax\/libs\/react\/[^"]+"><\/script>/, `<script>${safe(react)}</script>`);
swap(/<script src="https:\/\/cdnjs\.cloudflare\.com\/ajax\/libs\/react-dom\/[^"]+"><\/script>/, `<script>${safe(reactDom)}</script>`);
swap(/<script src="https:\/\/cdnjs\.cloudflare\.com\/ajax\/libs\/babel-standalone\/[^"]+"><\/script>/, '');

// 3. Inline fonts instead of Google Fonts
const face = (family, pkg, weight) => {
  const file = nm(`@fontsource/${pkg}/files/${pkg}-latin-${weight}-normal.woff2`);
  const b64 = fs.readFileSync(file).toString('base64');
  return `@font-face{font-family:'${family}';font-style:normal;font-weight:${weight};font-display:swap;src:url(data:font/woff2;base64,${b64}) format('woff2');}`;
};
const fonts = [300, 400, 500, 600, 700].map(w => face('IBM Plex Sans', 'ibm-plex-sans', w))
  .concat([400, 500].map(w => face('IBM Plex Mono', 'ibm-plex-mono', w))).join('\n');
html = html.replace(/\s*<link rel="preconnect" href="https:\/\/fonts\.googleapis\.com">/, '');
swap(/<link href="https:\/\/fonts\.googleapis\.com\/css2[^"]*" rel="stylesheet">/, `<style>${fonts}</style>`);

if (/cdnjs|googleapis|text\/babel/.test(html)) throw new Error('External UI reference left in the standalone HTML');
fs.mkdirSync(path.join(__dirname, 'dist'), { recursive: true });
fs.writeFileSync(path.join(__dirname, 'dist', 'ui-bundle.js'), `module.exports = ${JSON.stringify(html)};\n`);
console.log(`[build-ui] dist/ui-bundle.js written (${(html.length / 1024).toFixed(0)} KB, no external resources)`);
