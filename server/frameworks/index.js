/**
 * Every framework definition, required one by one so the standalone (Bun) build bundles them.
 * Add a new framework: drop its JSON here and add one line below.
 */
module.exports = [
  require('./BALANCED.json'),
  require('./CJIS.json'),
  require('./FERPA.json'),
  require('./GDPR.json'),
  require('./HIPAA.json'),
  require('./HITRUST.json'),
  require('./NIST_800_171.json'),
  require('./NIST_800_53.json'),
  require('./PCI.json'),
  require('./PERMISSIVE.json'),
  require('./SOX.json'),
  require('./STRICT.json'),
  require('./ZTH_EBOOK.json'),
];
