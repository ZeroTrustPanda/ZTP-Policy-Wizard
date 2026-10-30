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
  // v2.7 federal
  require('./FEDRAMP_MOD.json'),
  require('./FEDRAMP_HIGH.json'),
  require('./CMMC_L2.json'),
  require('./FED_ZT.json'),
  require('./IRS_1075.json'),
  require('./GOVRAMP.json'),
  // v2.8
  require('./SOC2.json'),
  require('./ISO_27001.json'),
  require('./NIST_CSF_2.json'),
  require('./GLBA.json'),
];
