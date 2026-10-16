/**
 * Input validation shared by the server routes (VAL-01). The UI runs the same rules inline (public/index.html).
 * ZCC-08: VPN Gateway Bypasses take CIDR or FQDN (no wildcards; a plain IPv4 address is accepted as a /32).
 *         IP / DNS inclusions and exclusions take wildcard FQDN (*.example.com), FQDN, IP or CIDR.
 */
const { classifyEntry } = require('./zpa');

const LIST_KEYS = ['vpnGateways', 'ipInclusions', 'ipExclusions', 'dnsInclusions', 'dnsExclusions'];
const LIST_LABELS = { vpnGateways: 'VPN Gateway Bypasses', ipInclusions: 'IP Inclusions', ipExclusions: 'IP Exclusions', dnsInclusions: 'DNS Inclusions', dnsExclusions: 'DNS Exclusions' };

function checkListEntry(key, raw) {
  const s = String(raw).trim();
  if (key === 'dnsInclusions' && s === '*') return null;           // "all domains" is the documented default
  if (key === 'ipInclusions' && s === '0.0.0.0/0') return null;
  const c = classifyEntry(s);
  if (!c.ok) return c.why;
  if (key === 'vpnGateways' && c.type === 'wildcard') return 'wildcards are not allowed for VPN gateways (use a CIDR or FQDN)';
  return null;
}

/** lists: { key: [entries] | null }. Returns a list of human-readable errors naming each bad entry. */
function validateProfileLists(lists) {
  const errors = [];
  if (!lists) return errors;
  for (const k of LIST_KEYS) {
    const v = lists[k];
    if (v === null || v === undefined) continue;
    if (!Array.isArray(v)) { errors.push(`${LIST_LABELS[k]} must be a list.`); continue; }
    for (const e of v) { const why = checkListEntry(k, e); if (why) errors.push(`${LIST_LABELS[k]}: "${e}" — ${why}.`); }
  }
  return errors;
}

module.exports = { LIST_KEYS, LIST_LABELS, checkListEntry, validateProfileLists };
