/**
 * ZTP Policy Templates
 * 
 * Three tiers: Strict, Balanced, Permissive
 * Compliance frameworks: HIPAA, HITRUST, NIST 800-53, NIST 800-171, PCI-DSS, CJIS, SOX, FERPA, GDPR
 * 
 * All rules use ZTP- naming prefix
 * Based on Zscaler Recommended Baseline Policies
 */

// URL Categories organized by class
const URL_CATEGORY_CLASSES = {
  // Category Enum Values verified from official Zscaler ZIA URL Categories CSV export
  // Column: "URL Category Enum Value (Cloud Service API)"
  LEGAL_LIABILITY: [
    'OTHER_ADULT_MATERIAL', 'ADULT_THEMES', 'LINGERIE_BIKINI', 'NUDITY',
    'PORNOGRAPHY', 'SEXUALITY', 'ADULT_SEX_EDUCATION', 'K_12_SEX_EDUCATION',
    'SOCIAL_ADULT',
    'OTHER_DRUGS', 'MARIJUANA', 'GAMBLING',
    'OTHER_ILLEGAL_OR_QUESTIONABLE', 'COPYRIGHT_INFRINGEMENT',
    'COMPUTER_HACKING', 'QUESTIONABLE', 'PROFANITY', 'MATURE_HUMOR',
    'ANONYMIZER', 'MILITANCY_HATE_AND_EXTREMISM', 'TASTELESS', 'VIOLENCE',
    'WEAPONS_AND_BOMBS'
  ],
  PRIVACY_RISK: [
    'OTHER_SECURITY', 'ADWARE_OR_SPYWARE', 'ENCR_WEB_CONTENT',
    'DYNAMIC_DNS', 'NEWLY_REVIVED_DOMAINS'
  ],
  BANDWIDTH_LOSS: [
    'STREAMING_MEDIA', 'RADIO_STATIONS', 'TELEVISION_AND_MOVIES', 'MUSIC',
    'ENTERTAINMENT', 'OTHER_ENTERTAINMENT_AND_RECREATION', 'NEWS_AND_MEDIA'
  ],
  PRODUCTIVITY_LOSS: [
    'OTHER_GAMES', 'SOCIAL_NETWORKING_GAMES', 'SPECIALIZED_SHOPPING',
    'ONLINE_AUCTIONS', 'OTHER_SHOPPING_AND_AUCTIONS',
    'SOCIAL_NETWORKING', 'SPORTS'
  ],
  SECURITY_RISK: [
    'NEWLY_REG_DOMAINS', 'NON_CATEGORIZABLE',
    'P2P_COMMUNICATION', 'REMOTE_ACCESS'
  ],
  // Isolated rather than blocked: users can still reach obscure but legitimate sites, safely in Browser Isolation
  MISC_UNKNOWN: ['MISCELLANEOUS_OR_UNKNOWN', 'OTHER_MISCELLANEOUS']
};

// Fallback: if specific categories fail, use ANY (matches all categories)
const SAFE_ALL_CATEGORIES = ['ANY'];

const ALL_PROTOCOLS = [
  'WEBSOCKETSSL_RULE', 'WEBSOCKET_RULE', 'DOHTTPS_RULE', 'TUNNELSSL_RULE',
  'HTTP_PROXY', 'FOHTTP_RULE', 'FTP_RULE', 'HTTPS_RULE', 'HTTP_RULE', 'SSL_RULE'
];

// Use ANY_RULE for simplified protocol matching
const ANY_PROTOCOL = ['ANY_RULE'];

const ALL_REQUEST_METHODS = [
  'OPTIONS', 'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'TRACE',
  'CONNECT', 'OTHER'
];

// ========================
// COMPLIANCE FRAMEWORKS
// ========================

const COMPLIANCE_FRAMEWORKS = {
  HIPAA: {
    name: 'HIPAA',
    fullName: 'Health Insurance Portability and Accountability Act',
    description: 'Federal law requiring protection of sensitive patient health information',
    controls: [
      { id: '164.312(a)(1)', name: 'Access Control', description: 'Implement technical policies to allow access only to authorized persons' },
      { id: '164.312(c)(1)', name: 'Integrity', description: 'Protect ePHI from improper alteration or destruction' },
      { id: '164.312(d)', name: 'Authentication', description: 'Verify identity of persons seeking access to ePHI' },
      { id: '164.312(e)(1)', name: 'Transmission Security', description: 'Guard against unauthorized access to ePHI during transmission' },
      { id: '164.308(a)(5)', name: 'Security Awareness Training', description: 'Protection from malicious software and login monitoring' }
    ]
  },
  HITRUST: {
    name: 'HITRUST CSF',
    fullName: 'Health Information Trust Alliance Common Security Framework',
    description: 'Certifiable security framework for healthcare organizations',
    controls: [
      { id: '09.j', name: 'Controls Against Malicious Code', description: 'Detection, prevention, and recovery controls' },
      { id: '09.m', name: 'Network Controls', description: 'Networks managed and controlled to protect information' },
      { id: '10.d', name: 'SSL/TLS Inspection', description: 'Cryptographic controls for data in transit' },
      { id: '01.v', name: 'Information Access Restriction', description: 'Access to information and functions restricted' }
    ]
  },
  'NIST_800_53': {
    name: 'NIST 800-53',
    fullName: 'NIST Special Publication 800-53 Rev 5',
    description: 'Security and Privacy Controls for Federal Information Systems',
    controls: [
      { id: 'AC-4', name: 'Information Flow Enforcement', description: 'Enforce approved authorizations for controlling information flow' },
      { id: 'SC-7', name: 'Boundary Protection', description: 'Monitor and control communications at external boundary' },
      { id: 'SI-3', name: 'Malicious Code Protection', description: 'Employ malicious code protection mechanisms' },
      { id: 'SI-4', name: 'System Monitoring', description: 'Monitor the system to detect attacks and unauthorized connections' },
      { id: 'SC-8', name: 'Transmission Confidentiality', description: 'Protect confidentiality of transmitted information' },
      { id: 'AU-2', name: 'Audit Events', description: 'Identify events that need to be audited' }
    ]
  },
  'NIST_800_171': {
    name: 'NIST 800-171',
    fullName: 'Protecting Controlled Unclassified Information in Nonfederal Systems',
    description: 'Requirements for protecting CUI in non-federal systems',
    controls: [
      { id: '3.1.3', name: 'Control CUI Flow', description: 'Control the flow of CUI in accordance with approved authorizations' },
      { id: '3.13.1', name: 'Boundary Protection', description: 'Monitor, control, and protect communications at external boundaries' },
      { id: '3.14.2', name: 'Malicious Code Protection', description: 'Provide protection from malicious code at designated locations' }
    ]
  },
  PCI: {
    name: 'PCI DSS',
    fullName: 'Payment Card Industry Data Security Standard v4.0',
    description: 'Security standard for organizations that handle cardholder data',
    controls: [
      { id: '1.2', name: 'Network Security Controls', description: 'Network security controls configured and maintained' },
      { id: '5.2', name: 'Malicious Software Prevention', description: 'Malicious software is prevented or detected and addressed' },
      { id: '6.4', name: 'Web Application Protection', description: 'Public-facing web applications are protected against attacks' },
      { id: '10.2', name: 'Audit Logs', description: 'Audit logs record user activities and anomalies' }
    ]
  },
  CJIS: {
    name: 'CJIS',
    fullName: 'Criminal Justice Information Services Security Policy',
    description: 'Security requirements for access to FBI CJIS data',
    controls: [
      { id: '5.10.1.2', name: 'Internet Access', description: 'Agencies shall control and monitor access to the internet' },
      { id: '5.10.1.3', name: 'Encryption', description: 'Encryption shall be used for CJI in transit' }
    ]
  },
  SOX: {
    name: 'SOX',
    fullName: 'Sarbanes-Oxley Act',
    description: 'Financial reporting and auditing requirements for public companies',
    controls: [
      { id: 'Section 302', name: 'Corporate Responsibility', description: 'Executives personally certify accuracy of financial reports' },
      { id: 'Section 404', name: 'Internal Controls', description: 'Assessment of internal controls over financial reporting' }
    ]
  },
  FERPA: {
    name: 'FERPA',
    fullName: 'Family Educational Rights and Privacy Act',
    description: 'Federal law protecting student education records',
    controls: [
      { id: '99.31', name: 'Access Controls', description: 'Control access to education records' },
      { id: '99.35', name: 'Security Measures', description: 'Reasonable methods to ensure access limited to legitimate parties' }
    ]
  },
  GDPR: {
    name: 'GDPR',
    fullName: 'General Data Protection Regulation',
    description: 'EU regulation on data protection and privacy',
    controls: [
      { id: 'Art.25', name: 'Data Protection by Design', description: 'Implement appropriate technical measures' },
      { id: 'Art.32', name: 'Security of Processing', description: 'Implement appropriate technical and organizational measures' },
      { id: 'Art.30', name: 'Records of Processing', description: 'Maintain records of processing activities' }
    ]
  }
};

// ========================
// URL FILTERING TEMPLATES
// ========================

function generateUrlFilteringRules(tier, complianceFramework, prefix = 'ZTP') {
  const rules = [];
  let order = 1;

  // Rule 1: Block Legal Liability (all tiers)
  rules.push({
    name: `${prefix}-Block-Legal-Liability`,
    order: order++,
    state: 'ENABLED',
    action: 'BLOCK',
    urlCategories: URL_CATEGORY_CLASSES.LEGAL_LIABILITY,
    protocols: ANY_PROTOCOL,
    requestMethods: ALL_REQUEST_METHODS,
    description: 'Block all URLs in Legal Liability class including adult content, gambling, drugs, and violence',
    tier,
    complianceMapping: mapToCompliance('url_legal_liability', complianceFramework)
  });

  // Rule 2: Block Privacy Risk (all tiers)
  rules.push({
    name: `${prefix}-Block-Privacy-Risk`,
    order: order++,
    state: 'ENABLED',
    action: 'BLOCK',
    urlCategories: URL_CATEGORY_CLASSES.PRIVACY_RISK,
    protocols: ANY_PROTOCOL,
    requestMethods: ALL_REQUEST_METHODS,
    description: 'Block all URLs in Privacy Risk class including spyware, adware, and dynamic DNS',
    tier,
    complianceMapping: mapToCompliance('url_privacy_risk', complianceFramework)
  });

  // Rule 3: Block Security Risk categories
  rules.push({
    name: `${prefix}-Block-Security-Risk`,
    order: order++,
    state: 'ENABLED',
    action: 'BLOCK',
    urlCategories: URL_CATEGORY_CLASSES.SECURITY_RISK,
    protocols: ANY_PROTOCOL,
    requestMethods: ALL_REQUEST_METHODS,
    description: 'Block newly registered domains, uncategorizable sites, and P2P/remote access sites',
    tier,
    complianceMapping: mapToCompliance('url_security_risk', complianceFramework)
  });

  // Rule 4: Isolate Miscellaneous / Unknown (Cloud Browser Isolation; falls back to Caution with no isolation profile)
  rules.push({
    name: `${prefix}-Isolate-Misc-Unknown`,
    order: order++,
    state: 'ENABLED',
    action: 'ISOLATE',
    isolateFallback: 'CAUTION',
    urlCategories: URL_CATEGORY_CLASSES.MISC_UNKNOWN,
    protocols: ['HTTPS_RULE', 'HTTP_RULE'],
    requestMethods: ALL_REQUEST_METHODS,
    description: 'Open Miscellaneous and Unknown sites in Cloud Browser Isolation: users can still read them, but no active content reaches the device and nothing can be uploaded or downloaded.',
    tier,
    complianceMapping: mapToCompliance('url_security_risk', complianceFramework)
  });

  // Tier-specific: Bandwidth Loss
  if (tier === 'STRICT') {
    rules.push({
      name: `${prefix}-Block-Bandwidth-Loss`,
      order: order++,
      state: 'ENABLED',
      action: 'BLOCK',
      urlCategories: URL_CATEGORY_CLASSES.BANDWIDTH_LOSS,
      protocols: ANY_PROTOCOL,
      requestMethods: ALL_REQUEST_METHODS,
      description: 'Block streaming media and entertainment sites (Strict mode)',
      tier,
      complianceMapping: mapToCompliance('url_bandwidth', complianceFramework)
    });
  } else if (tier === 'BALANCED') {
    rules.push({
      name: `${prefix}-Caution-Bandwidth-Loss`,
      order: order++,
      state: 'ENABLED',
      action: 'CAUTION',
      urlCategories: URL_CATEGORY_CLASSES.BANDWIDTH_LOSS,
      protocols: ANY_PROTOCOL,
      requestMethods: ALL_REQUEST_METHODS,
      description: 'Caution page for streaming media and entertainment (Balanced mode)',
      tier,
      complianceMapping: mapToCompliance('url_bandwidth', complianceFramework)
    });
  }
  // Permissive: no bandwidth restriction

  // Tier-specific: Productivity Loss
  if (tier === 'STRICT') {
    rules.push({
      name: `${prefix}-Block-Productivity-Loss`,
      order: order++,
      state: 'ENABLED',
      action: 'BLOCK',
      urlCategories: URL_CATEGORY_CLASSES.PRODUCTIVITY_LOSS,
      protocols: ANY_PROTOCOL,
      requestMethods: ALL_REQUEST_METHODS,
      description: 'Block gaming, shopping, social media, and other productivity loss sites (Strict mode)',
      tier,
      complianceMapping: mapToCompliance('url_productivity', complianceFramework)
    });
  } else if (tier === 'BALANCED') {
    rules.push({
      name: `${prefix}-Caution-Productivity-Loss`,
      order: order++,
      state: 'ENABLED',
      action: 'CAUTION',
      urlCategories: URL_CATEGORY_CLASSES.PRODUCTIVITY_LOSS,
      protocols: ANY_PROTOCOL,
      requestMethods: ALL_REQUEST_METHODS,
      description: 'Caution page for productivity loss sites (Balanced mode)',
      tier,
      complianceMapping: mapToCompliance('url_productivity', complianceFramework)
    });
  }
  // Permissive: no productivity restriction

  // Custom block category placeholder
  rules.push({
    name: `${prefix}-Block-Custom-Category`,
    order: order++,
    state: 'ENABLED',
    action: 'BLOCK',
    urlCategories: [`${prefix}_Custom_Block`],
    protocols: ANY_PROTOCOL,
    requestMethods: ALL_REQUEST_METHODS,
    description: 'Block URLs manually added to custom block category',
    tier,
    complianceMapping: mapToCompliance('url_custom_block', complianceFramework),
    requiresCustomCategory: true,
    customCategoryName: `${prefix}_Custom_Block`
  });

  return rules;
}

// ========================
// FIREWALL TEMPLATES
// ========================

// Countries with high-risk remote-access traffic. Remote admin and file transfer protocols to or from them are dropped.
const HIGH_RISK_COUNTRIES = ['COUNTRY_CN', 'COUNTRY_RU', 'COUNTRY_KP', 'COUNTRY_IR'];
const REMOTE_ACCESS_APPS = ['SSH', 'RDP', 'FTP'];
function geoFirewallRules(prefix, tier, complianceFramework) {
  const where = 'China, Russia, North Korea and Iran';
  return [
    { name: `${prefix}-FW-Geo-Block-Out`, state: 'ENABLED', action: 'BLOCK_DROP',
      nwApplications: REMOTE_ACCESS_APPS.slice(), destCountries: HIGH_RISK_COUNTRIES.slice(),
      description: `Drop SSH, RDP and FTP to ${where}. Remote administration and file transfer to high-risk countries is a common exfiltration path.`,
      tier, complianceMapping: mapToCompliance('fw_geo', complianceFramework) },
    { name: `${prefix}-FW-Geo-Block-In`, state: 'ENABLED', action: 'BLOCK_DROP',
      nwApplications: REMOTE_ACCESS_APPS.slice(), sourceCountries: HIGH_RISK_COUNTRIES.slice(),
      description: `Drop SSH, RDP and FTP coming from ${where}.`,
      tier, complianceMapping: mapToCompliance('fw_geo', complianceFramework) }
  ];
}

function generateFirewallRules(tier, complianceFramework, prefix = 'ZTP') {
  const rules = [];
  let order = 5;

  for (const g of geoFirewallRules(prefix, tier, complianceFramework)) rules.push({ ...g, order: order++ });

  // Block QUIC protocol
  rules.push({
    name: `${prefix}-Block-QUIC`,
    order: order++,
    state: 'ENABLED',
    action: 'BLOCK_DROP',
    nwApplications: ['QUIC'],
    description: 'Block QUIC to force TCP for SSL inspectability.',
    tier,
    complianceMapping: mapToCompliance('fw_quic', complianceFramework)
  });

  // Allow core web + DNS + auth traffic
  rules.push({
    name: `${prefix}-Allow-Web`,
    order: order++,
    state: 'ENABLED',
    action: 'ALLOW',
    nwApplications: ['HTTP', 'HTTPS', 'HTTP2', 'DNS', 'SSL'],
    description: 'Allow HTTP, HTTPS, HTTP2, DNS, and SSL traffic.',
    tier,
    complianceMapping: mapToCompliance('fw_allow_web', complianceFramework)
  });

  // Allow NTP
  rules.push({
    name: `${prefix}-Allow-NTP`,
    order: order++,
    state: 'ENABLED',
    action: 'ALLOW',
    nwApplications: ['NTP'],
    description: 'Allow NTP for time synchronization.',
    tier,
    complianceMapping: mapToCompliance('fw_ntp', complianceFramework)
  });

  // Allow collaboration (Teams, Zoom, WebEx, etc.)
  rules.push({
    name: `${prefix}-Allow-Collab`,
    order: order++,
    state: 'ENABLED',
    action: 'ALLOW',
    nwApplications: ['ZOOM', 'WEBEX', 'GOTOMEETING', 'SKYPE', 'SKYPE_FOR_BUSINESS', 'FACETIME', 'RINGCENTRAL', 'SIP', 'RTP', 'RTCP'],
    description: 'Allow collaboration apps (Zoom, WebEx, Teams, RingCentral, SIP/RTP).',
    tier,
    complianceMapping: mapToCompliance('fw_allow_web', complianceFramework)
  });

  // Allow common enterprise services
  rules.push({
    name: `${prefix}-Allow-Enterprise`,
    order: order++,
    state: 'ENABLED',
    action: 'ALLOW',
    nwApplications: ['LDAP', 'LDAPS', 'KRB5', 'RADIUS', 'SNMP', 'DHCP', 'ICMP', 'SSH', 'RDP', 'OCSP'],
    description: 'Allow enterprise services (LDAP, Kerberos, RADIUS, SNMP, DHCP, SSH, RDP, OCSP).',
    tier,
    complianceMapping: mapToCompliance('fw_allow_web', complianceFramework)
  });

  // STRICT/ZTH: Block high-risk apps
  if (tier === 'STRICT' || tier === 'ZTH_EBOOK') {
    rules.push({
      name: `${prefix}-Block-P2P`,
      order: order++,
      state: 'ENABLED',
      action: 'BLOCK_DROP',
      nwApplications: [
        'BITTORRENT', 'EDONKEY', 'GNUTELLA', 'KAZAA', 'ARES', 'DIRECTCONNECT',
        'THUNDER', 'SLSK', 'PANDO', 'IMESH', 'APPLEJUICE', 'MUTE', 'GNUNET',
        'FOXY', 'WINMX', 'WINNY', 'SHARE'
      ],
      description: 'Block P2P file sharing applications.',
      tier,
      complianceMapping: mapToCompliance('fw_default_deny', complianceFramework)
    });

    rules.push({
      name: `${prefix}-Block-Tunnels`,
      order: order++,
      state: 'ENABLED',
      action: 'BLOCK_DROP',
      nwApplications: [
        'TOR', 'ULTRASURF', 'PSIPHON', 'OPENVPN', 'HTTPTUNNEL',
        'SOCKS2HTTP', 'SOCKS4', 'SOCKS5', 'TEREDO', 'WSTUNNEL'
      ],
      description: 'Block tunneling and proxy evasion apps.',
      tier,
      complianceMapping: mapToCompliance('fw_default_deny', complianceFramework)
    });
  }

  // STRICT/ZTH: Default deny
  if (tier === 'STRICT' || tier === 'ZTH_EBOOK') {
    rules.push({
      name: `${prefix}-Default-Block-All`,
      order: 999,
      state: 'ENABLED',
      action: 'BLOCK_DROP',
      description: 'Default deny — block all traffic not allowed above.',
      tier,
      complianceMapping: mapToCompliance('fw_default_deny', complianceFramework)
    });
  }

  return rules;
}

// ========================
// SSL INSPECTION TEMPLATES
// ========================

function generateSslInspectionRules(tier, complianceFramework, prefix = 'ZTP') {
  const rules = [];
  let order = 1;

  if (tier === 'STRICT') {
    // Inspect everything
    rules.push({
      name: `${prefix}-SSL-Inspect-All`,
      order: order++,
      state: 'ENABLED',
      action: 'DECRYPT',
      urlCategories: ['ANY'],
      description: 'Inspect all remaining SSL/TLS traffic (Strict mode). Sits below the Zscaler predefined exemptions. Blocks TLS 1.0 and 1.1.',
      tier,
      minClientTLS: 'CLIENT_TLS_1_2',
      minServerTLS: 'SERVER_TLS_1_2',
      complianceMapping: mapToCompliance('ssl_inspect_all', complianceFramework)
    });
  } else if (tier === 'BALANCED') {
    // Bypass health and finance for privacy
    rules.push({
      name: `${prefix}-SSL-Bypass-Health`,
      order: order++,
      state: 'ENABLED',
      action: 'DO_NOT_DECRYPT',
      urlCategories: ['HEALTH'],
      description: 'Do not inspect healthcare sites for patient privacy (Balanced mode)',
      tier,
      complianceMapping: mapToCompliance('ssl_bypass_health', complianceFramework)
    });

    rules.push({
      name: `${prefix}-SSL-Bypass-Finance`,
      order: order++,
      state: 'ENABLED',
      action: 'DO_NOT_DECRYPT',
      urlCategories: ['FINANCE'],
      description: 'Do not inspect financial institution sites for user privacy (Balanced mode)',
      tier,
      complianceMapping: mapToCompliance('ssl_bypass_finance', complianceFramework)
    });

    rules.push({
      name: `${prefix}-SSL-Inspect-Remaining`,
      order: order++,
      state: 'ENABLED',
      action: 'DECRYPT',
      urlCategories: ['ANY'],
      description: 'Inspect all remaining SSL/TLS traffic (Balanced mode). Sits below the Zscaler predefined exemptions. Blocks TLS 1.0 and 1.1.',
      tier,
      minClientTLS: 'CLIENT_TLS_1_2',
      minServerTLS: 'SERVER_TLS_1_2',
      complianceMapping: mapToCompliance('ssl_inspect_all', complianceFramework)
    });
  } else {
    // Permissive: No SSL inspection
    rules.push({
      name: `${prefix}-SSL-No-Inspection`,
      order: order++,
      state: 'ENABLED',
      action: 'DO_NOT_DECRYPT',
      urlCategories: ['ANY'],
      description: 'No SSL/TLS inspection (Permissive mode). WARNING: Significantly reduces security visibility.',
      tier,
      isRisky: true,
      complianceMapping: mapToCompliance('ssl_no_inspect', complianceFramework)
    });
  }

  return rules;
}

// ========================
// MALWARE PROTECTION TEMPLATES
// ========================

function generateMalwareProtectionSettings(tier, complianceFramework, prefix = 'ZTP') {
  const base = {
    name: `${prefix}-Malware-Protection`,
    tier,
    complianceMapping: mapToCompliance('malware_protection', complianceFramework),
    settings: {
      // Traffic Inspection
      inspectInbound: true,
      inspectOutbound: true,
      inspectHttp: true,
      inspectFtpOverHttp: true,
      inspectFtp: tier !== 'PERMISSIVE',

      // Malware Protection
      unwantedApps: 'BLOCK',
      trojans: 'BLOCK',
      worms: 'BLOCK',
      ransomware: 'BLOCK',
      remoteAccess: 'BLOCK',
      otherViruses: 'BLOCK',

      // Adware/Spyware
      adware: 'BLOCK',
      spyware: 'BLOCK',

      // Security Exceptions
      passwordProtectedFiles: tier === 'STRICT' ? 'BLOCK' : 'ALLOW',
      unscannableFiles: tier === 'STRICT' ? 'BLOCK' : 'ALLOW',

      // Advanced Threat Protection
      commandAndControlServers: 'BLOCK',
      commandAndControlTraffic: 'BLOCK',
      dgaDomains: 'BLOCK',
      maliciousContent: 'BLOCK',
      vulnerableActiveX: 'BLOCK',
      browserExploits: 'BLOCK',
      fileFormatVulnerabilities: 'BLOCK',
      knownPhishingSites: 'BLOCK',
      suspectedPhishingSites: 'BLOCK',
      spywareCallback: 'BLOCK',
      webSpam: 'BLOCK',
      cryptoMining: 'BLOCK',
      knownAdwareSpywareSites: 'BLOCK',
      ircTunneling: 'BLOCK',
      sshTunneling: tier === 'PERMISSIVE' ? 'ALLOW' : 'BLOCK',
      anonymizers: 'BLOCK',
      cookieStealing: 'BLOCK',
      potentiallyMaliciousRequests: 'BLOCK',
      bitTorrent: 'BLOCK',
      tor: 'BLOCK'
    }
  };

  return base;
}

// ========================
// ADVANCED SETTINGS TEMPLATES
// ========================

function generateAdvancedSettings(tier, complianceFramework, prefix = 'ZTP') {
  return {
    name: `${prefix}-Advanced-Settings`,
    tier,
    complianceMapping: mapToCompliance('advanced_settings', complianceFramework),
    settings: {
      enablePolicyForUnauthenticatedTraffic: true,
      inspectTunneledHttpTraffic: true,
      blockTunnelingToNonHttpPorts: true,
      blockNonRfcCompliantHttp: tier !== 'PERMISSIVE',
      blockDomainFronting: tier !== 'PERMISSIVE',
      blockConnectHostSniMismatch: tier !== 'PERMISSIVE',
      autoProxyForwarding: true,
      enableFirewallForRoadWarriors: tier !== 'PERMISSIVE'
    }
  };
}

// ========================
// COMPLIANCE MAPPING
// ========================

function mapToCompliance(policyType, framework) {
  if (!framework || !COMPLIANCE_FRAMEWORKS[framework]) return [];

  const mappings = {
    // URL Filtering mappings
    url_legal_liability: {
      HIPAA: ['164.312(a)(1)', '164.308(a)(5)'],
      HITRUST: ['09.m', '01.v'],
      'NIST_800_53': ['AC-4', 'SC-7'],
      'NIST_800_171': ['3.1.3', '3.13.1'],
      PCI: ['1.2', '6.4'],
      CJIS: ['5.10.1.2'],
      SOX: ['Section 404'],
      FERPA: ['99.31'],
      GDPR: ['Art.25']
    },
    url_privacy_risk: {
      HIPAA: ['164.312(a)(1)', '164.312(e)(1)'],
      HITRUST: ['09.j', '09.m'],
      'NIST_800_53': ['AC-4', 'SI-3', 'SI-4'],
      'NIST_800_171': ['3.13.1', '3.14.2'],
      PCI: ['1.2', '5.2'],
      CJIS: ['5.10.1.2'],
      SOX: ['Section 404'],
      FERPA: ['99.35'],
      GDPR: ['Art.32']
    },
    url_security_risk: {
      HIPAA: ['164.312(a)(1)'],
      HITRUST: ['09.j'],
      'NIST_800_53': ['SI-3', 'SI-4'],
      'NIST_800_171': ['3.14.2'],
      PCI: ['5.2'],
      CJIS: ['5.10.1.2'],
      SOX: ['Section 404'],
      FERPA: ['99.35'],
      GDPR: ['Art.32']
    },
    url_bandwidth: {
      'NIST_800_53': ['AC-4'],
      PCI: ['1.2'],
      CJIS: ['5.10.1.2']
    },
    url_productivity: {
      'NIST_800_53': ['AC-4'],
      CJIS: ['5.10.1.2']
    },
    url_custom_block: {
      HIPAA: ['164.312(a)(1)'],
      HITRUST: ['01.v'],
      'NIST_800_53': ['AC-4'],
      'NIST_800_171': ['3.1.3'],
      PCI: ['1.2'],
      CJIS: ['5.10.1.2'],
      SOX: ['Section 404'],
      FERPA: ['99.31'],
      GDPR: ['Art.25']
    },
    // Firewall mappings
    fw_geo: {
      'NIST_800_53': ['SC-7', 'AC-4'],
      'NIST_800_171': ['3.13.1'],
      PCI: ['1.3']
    },
    fw_quic: {
      'NIST_800_53': ['SC-7'],
      'NIST_800_171': ['3.13.1'],
      PCI: ['1.2']
    },
    fw_allow_web: {
      'NIST_800_53': ['SC-7'],
      'NIST_800_171': ['3.13.1']
    },
    fw_ntp: {
      'NIST_800_53': ['AU-2']
    },
    fw_malicious: {
      HIPAA: ['164.308(a)(5)'],
      HITRUST: ['09.j'],
      'NIST_800_53': ['SI-3', 'SI-4'],
      'NIST_800_171': ['3.14.2'],
      PCI: ['5.2'],
      CJIS: ['5.10.1.2'],
      GDPR: ['Art.32']
    },
    fw_default_deny: {
      HIPAA: ['164.312(a)(1)'],
      HITRUST: ['09.m'],
      'NIST_800_53': ['SC-7', 'AC-4'],
      'NIST_800_171': ['3.13.1', '3.1.3'],
      PCI: ['1.2'],
      CJIS: ['5.10.1.2'],
      GDPR: ['Art.25']
    },
    // SSL Inspection mappings
    ssl_inspect_all: {
      HIPAA: ['164.312(e)(1)'],
      HITRUST: ['10.d'],
      'NIST_800_53': ['SC-8', 'SI-4'],
      'NIST_800_171': ['3.13.1'],
      PCI: ['6.4'],
      CJIS: ['5.10.1.3'],
      GDPR: ['Art.32']
    },
    ssl_bypass_health: {
      HIPAA: ['164.312(e)(1)']
    },
    ssl_bypass_finance: {
      PCI: ['6.4']
    },
    ssl_no_inspect: {},
    // Malware mappings
    malware_protection: {
      HIPAA: ['164.308(a)(5)'],
      HITRUST: ['09.j'],
      'NIST_800_53': ['SI-3'],
      'NIST_800_171': ['3.14.2'],
      PCI: ['5.2'],
      CJIS: ['5.10.1.2'],
      SOX: ['Section 404'],
      GDPR: ['Art.32']
    },
    advanced_settings: {
      'NIST_800_53': ['SC-7', 'SI-4'],
      'NIST_800_171': ['3.13.1'],
      PCI: ['1.2']
    },
    // Sandbox mappings
    sandbox_office: {
      HIPAA: ['164.308(a)(5)'],
      HITRUST: ['09.j'],
      'NIST_800_53': ['SI-3'],
      'NIST_800_171': ['3.14.2'],
      PCI: ['5.2'],
      CJIS: ['5.10.1.2'],
      GDPR: ['Art.32']
    },
    sandbox_executables: {
      HIPAA: ['164.308(a)(5)'],
      HITRUST: ['09.j'],
      'NIST_800_53': ['SI-3', 'SI-4'],
      'NIST_800_171': ['3.14.2'],
      PCI: ['5.2'],
      CJIS: ['5.10.1.2']
    },
    sandbox_catchall: {
      HIPAA: ['164.308(a)(5)'],
      HITRUST: ['09.j'],
      'NIST_800_53': ['SI-3'],
      PCI: ['5.2']
    },
    // DNS Security mappings
    dns_critical: {
      HIPAA: ['164.308(a)(5)', '164.312(a)(1)'],
      HITRUST: ['09.j', '09.m'],
      'NIST_800_53': ['SI-3', 'SI-4', 'SC-7'],
      'NIST_800_171': ['3.14.2', '3.13.1'],
      PCI: ['5.2', '1.2'],
      CJIS: ['5.10.1.2'],
      GDPR: ['Art.32']
    },
    dns_tunnels_critical: {
      HIPAA: ['164.312(e)(1)'],
      HITRUST: ['09.m'],
      'NIST_800_53': ['SC-7', 'SI-4'],
      'NIST_800_171': ['3.13.1'],
      PCI: ['1.2']
    },
    dns_high: {
      'NIST_800_53': ['SI-3', 'SI-4'],
      'NIST_800_171': ['3.14.2'],
      PCI: ['5.2']
    },
    dns_tunnels_high: {
      'NIST_800_53': ['SC-7'],
      'NIST_800_171': ['3.13.1']
    },
    dns_doh: {
      'NIST_800_53': ['SC-7', 'SI-4'],
      'NIST_800_171': ['3.13.1']
    },
    dns_resolver: {
      'NIST_800_53': ['SC-20', 'SC-21', 'SC-7'],
      'NIST_800_171': ['3.13.1']
    },
    dns_unknown: {
      HIPAA: ['164.312(a)(1)'],
      'NIST_800_53': ['SC-7', 'AC-4'],
      CJIS: ['5.10.1.2']
    },
    // File Type Control mappings
    ftc_database: {
      HIPAA: ['164.312(e)(1)', '164.312(c)(1)'],
      HITRUST: ['09.m'],
      'NIST_800_53': ['AC-4', 'SC-7'],
      PCI: ['1.2'],
      GDPR: ['Art.32']
    },
    ftc_pw_archives: {
      HIPAA: ['164.308(a)(5)'],
      HITRUST: ['09.j'],
      'NIST_800_53': ['SI-3'],
      PCI: ['5.2']
    },
    ftc_executables: {
      HIPAA: ['164.308(a)(5)'],
      HITRUST: ['09.j'],
      'NIST_800_53': ['SI-3'],
      'NIST_800_171': ['3.14.2'],
      PCI: ['5.2'],
      CJIS: ['5.10.1.2']
    },
    ftc_scripts: {
      HIPAA: ['164.308(a)(5)'],
      'NIST_800_53': ['SI-3', 'SI-4'],
      PCI: ['5.2']
    },
    // Cloud App Control mappings
    cac_doh: {
      'NIST_800_53': ['SC-7', 'SI-4'],
      'NIST_800_171': ['3.13.1'],
      PCI: ['1.2']
    },
    cac_fileshare: {
      HIPAA: ['164.312(e)(1)', '164.312(c)(1)'],
      HITRUST: ['09.m'],
      'NIST_800_53': ['AC-4', 'SC-7'],
      PCI: ['1.2'],
      GDPR: ['Art.25', 'Art.32']
    },
    cac_im: {
      'NIST_800_53': ['AC-4'],
      PCI: ['1.2']
    },
    cac_social: {
      HIPAA: ['164.312(e)(1)'],
      'NIST_800_53': ['AC-4'],
      GDPR: ['Art.25']
    },
    cac_webmail: {
      HIPAA: ['164.312(e)(1)'],
      HITRUST: ['09.m'],
      'NIST_800_53': ['AC-4', 'SC-7'],
      PCI: ['1.2'],
      GDPR: ['Art.32']
    },
    cac_streaming: {
      'NIST_800_53': ['AC-4']
    },
    cac_aiml: {
      HIPAA: ['164.312(e)(1)', '164.312(c)(1)'],
      HITRUST: ['09.m'],
      'NIST_800_53': ['AC-4', 'SC-7'],
      GDPR: ['Art.25', 'Art.32']
    },
    // DLP mappings
    dlp_hipaa: {
      HIPAA: ['164.312(e)(1)', '164.312(c)(1)', '164.312(a)(1)'],
      HITRUST: ['09.m', '01.v'],
      'NIST_800_53': ['AC-4', 'SC-7', 'SI-4'],
      'NIST_800_171': ['3.1.3', '3.13.1'],
      GDPR: ['Art.32']
    },
    dlp_pci: {
      PCI: ['1.2', '6.4', '10.2'],
      HIPAA: ['164.312(e)(1)'],
      'NIST_800_53': ['AC-4', 'SC-7'],
      SOX: ['Section 404']
    },
    dlp_glba: {
      SOX: ['Section 302', 'Section 404'],
      PCI: ['1.2'],
      'NIST_800_53': ['AC-4'],
      GDPR: ['Art.32']
    },
    dlp_gdpr: {
      GDPR: ['Art.25', 'Art.32', 'Art.30'],
      HIPAA: ['164.312(e)(1)'],
      'NIST_800_53': ['AC-4', 'SC-7']
    },
    dlp_pii: {
      HIPAA: ['164.312(e)(1)', '164.312(a)(1)'],
      GDPR: ['Art.25', 'Art.32'],
      'NIST_800_53': ['AC-4', 'SI-4'],
      'NIST_800_171': ['3.1.3'],
      FERPA: ['99.31', '99.35'],
      CJIS: ['5.10.1.2']
    },
    dlp_medical: {
      HIPAA: ['164.312(e)(1)', '164.312(c)(1)', '164.308(a)(5)'],
      HITRUST: ['09.m', '09.j', '01.v'],
      'NIST_800_53': ['AC-4', 'SC-7', 'SI-4']
    },
    dlp_financial: {
      SOX: ['Section 302', 'Section 404'],
      PCI: ['1.2', '10.2'],
      'NIST_800_53': ['AC-4', 'SC-7'],
      GDPR: ['Art.32']
    },
    dlp_legal: {
      SOX: ['Section 404'],
      'NIST_800_53': ['AC-4'],
      GDPR: ['Art.32']
    },
    dlp_credentials: {
      HIPAA: ['164.312(d)', '164.312(a)(1)'],
      HITRUST: ['09.j'],
      'NIST_800_53': ['AC-4', 'SI-4'],
      'NIST_800_171': ['3.14.2'],
      PCI: ['5.2'],
      CJIS: ['5.10.1.2']
    },
    dlp_ccpa: {
      GDPR: ['Art.25', 'Art.32'],
      HIPAA: ['164.312(e)(1)'],
      'NIST_800_53': ['AC-4', 'SI-4']
    },
    dlp_fisma: {
      'NIST_800_53': ['AC-4', 'SC-7', 'SI-4', 'SC-8'],
      'NIST_800_171': ['3.1.3', '3.13.1', '3.14.2'],
      CJIS: ['5.10.1.2', '5.10.1.3']
    },
    dlp_source_code: {
      'NIST_800_53': ['AC-4', 'SC-7'],
      PCI: ['6.4'],
      SOX: ['Section 404']
    },
    dlp_offensive: {
      FERPA: ['99.31', '99.35'],
      'NIST_800_53': ['AC-4']
    },
    dlp_selfharm: {
      FERPA: ['99.31', '99.35']
    }
  };

  const mapping = mappings[policyType];
  if (!mapping || !mapping[framework]) return [];

  const controlIds = mapping[framework];
  const frameworkDef = COMPLIANCE_FRAMEWORKS[framework];
  return controlIds.map(id => {
    const control = frameworkDef.controls.find(c => c.id === id);
    return control ? { ...control, framework: frameworkDef.name } : { id, framework: frameworkDef.name };
  });
}

// ========================
// DLP POLICY RULE TEMPLATES
// Dictionary-first approach: uses predefined DLP dictionaries as the universal
// building block, with engines as a preferred shortcut when available.
// All rules use action=ALLOW with Zscaler Incident Receiver for monitoring.
// Per the Web DLP Rule API: POST /api/v1/webDlpRules
// ========================

// Predefined DLP engine names (attempted first at apply time — names vary per tenant)
const DLP_ENGINE_MAP = {
  HIPAA: { name: 'HIPAA', description: 'Health Insurance Portability and Accountability Act' },
  GLBA: { name: 'GLBA', description: 'Gramm-Leach-Bliley Act' },
  PCI: { name: 'PCI', description: 'Payment Card Industry Data Security Standard' },
  OFFENSIVE: { name: 'Offensive Language', description: 'Offensive Language Detection' },
  SELF_HARM: { name: 'Self-Harm & Cyberbullying', description: 'Student Safety - Self-Harm Detection' }
};

// DLP rule definitions: each maps to predefined dictionaries (universal across all tenants)
// and optionally to a preferred engine name (attempted first, fall back to dictionaries)
// Dictionary names come from: https://help.zscaler.com/zia/understanding-predefined-dlp-dictionaries
const DLP_RULE_DEFS = {
  HIPAA_SSN_MEDICAL: {
    label: 'HIPAA-SSN-Medical',
    description: 'HIPAA: Detect SSNs and medical information in transit',
    preferredEngines: ['HIPAA'],
    dictionaries: ['Social Security Numbers (US)', 'Medical Information'],
    complianceKey: 'dlp_hipaa',
    severity: { STRICT: 'RULE_SEVERITY_HIGH', BALANCED: 'RULE_SEVERITY_HIGH', PERMISSIVE: 'RULE_SEVERITY_MEDIUM', ZTH_EBOOK: 'RULE_SEVERITY_HIGH' }
  },
  PCI_CARDS: {
    label: 'PCI-Credit-Cards',
    description: 'PCI: Detect credit card numbers and SSNs',
    preferredEngines: ['PCI'],
    dictionaries: ['Credit Cards', 'Social Security Numbers (US)'],
    complianceKey: 'dlp_pci',
    severity: { STRICT: 'RULE_SEVERITY_HIGH', BALANCED: 'RULE_SEVERITY_HIGH', PERMISSIVE: 'RULE_SEVERITY_MEDIUM', ZTH_EBOOK: 'RULE_SEVERITY_HIGH' }
  },
  GLBA_FINANCIAL: {
    label: 'GLBA-Financial',
    description: 'GLBA: Detect SSNs and financial statements',
    preferredEngines: ['GLBA'],
    dictionaries: ['Social Security Numbers (US)', 'Financial Statements'],
    complianceKey: 'dlp_glba',
    severity: { STRICT: 'RULE_SEVERITY_HIGH', BALANCED: 'RULE_SEVERITY_MEDIUM', PERMISSIVE: 'RULE_SEVERITY_LOW', ZTH_EBOOK: 'RULE_SEVERITY_HIGH' }
  },
  MEDICAL_INFO: {
    label: 'Medical-Information',
    description: 'Detect medical information, diseases, drugs, and treatment data',
    preferredEngines: [],
    dictionaries: ['Medical Information', 'Diseases Information', 'Drugs Information', 'Treatments Information', 'Medical Document'],
    complianceKey: 'dlp_medical',
    severity: { STRICT: 'RULE_SEVERITY_HIGH', BALANCED: 'RULE_SEVERITY_MEDIUM', PERMISSIVE: 'RULE_SEVERITY_LOW', ZTH_EBOOK: 'RULE_SEVERITY_HIGH' }
  },
  PII_SSN_NAMES: {
    label: 'PII-SSN-Names',
    description: 'PII: Detect Social Security Numbers and name patterns',
    preferredEngines: [],
    dictionaries: ['Social Security Numbers (US)', 'Names (US)', "Driver's License (United States)"],
    complianceKey: 'dlp_pii',
    severity: { STRICT: 'RULE_SEVERITY_HIGH', BALANCED: 'RULE_SEVERITY_HIGH', PERMISSIVE: 'RULE_SEVERITY_MEDIUM', ZTH_EBOOK: 'RULE_SEVERITY_HIGH' }
  },
  PII_TAX_ID: {
    label: 'PII-Tax-ID',
    description: 'PII: Detect tax identification numbers',
    preferredEngines: [],
    dictionaries: ['Tax Identification Number (US)', 'Individual Taxpayer Registry ID (Brazil)'],
    complianceKey: 'dlp_pii',
    severity: { STRICT: 'RULE_SEVERITY_HIGH', BALANCED: 'RULE_SEVERITY_MEDIUM', PERMISSIVE: 'RULE_SEVERITY_LOW', ZTH_EBOOK: 'RULE_SEVERITY_HIGH' }
  },
  FINANCIAL_DOCS: {
    label: 'Financial-Documents',
    description: 'Detect financial statements, invoices, tax, and corporate finance documents',
    preferredEngines: [],
    dictionaries: ['Financial Statements', 'Invoice Document', 'Tax Document', 'Corporate Finance Document', 'ABA Bank Routing Numbers', 'International Bank Account Number (IBAN)'],
    complianceKey: 'dlp_financial',
    severity: { STRICT: 'RULE_SEVERITY_MEDIUM', BALANCED: 'RULE_SEVERITY_MEDIUM', PERMISSIVE: 'RULE_SEVERITY_LOW', ZTH_EBOOK: 'RULE_SEVERITY_MEDIUM' }
  },
  CREDENTIALS: {
    label: 'Credentials-Secrets',
    description: 'Detect credentials, API keys, tokens, and secrets',
    preferredEngines: [],
    dictionaries: ['Credentials and Secrets'],
    complianceKey: 'dlp_credentials',
    severity: { STRICT: 'RULE_SEVERITY_HIGH', BALANCED: 'RULE_SEVERITY_HIGH', PERMISSIVE: 'RULE_SEVERITY_MEDIUM', ZTH_EBOOK: 'RULE_SEVERITY_HIGH' }
  },
  SOURCE_CODE: {
    label: 'Source-Code',
    description: 'Detect source code uploads/downloads',
    preferredEngines: [],
    dictionaries: ['Source Code'],
    complianceKey: 'dlp_source_code',
    severity: { STRICT: 'RULE_SEVERITY_MEDIUM', BALANCED: 'RULE_SEVERITY_LOW', PERMISSIVE: 'RULE_SEVERITY_LOW', ZTH_EBOOK: 'RULE_SEVERITY_MEDIUM' }
  },
  LEGAL_DOCS: {
    label: 'Legal-Documents',
    description: 'Detect legal, court, and immigration documents',
    preferredEngines: [],
    dictionaries: ['Legal Document', 'Court Document', 'Immigration Document'],
    complianceKey: 'dlp_legal',
    severity: { STRICT: 'RULE_SEVERITY_MEDIUM', BALANCED: 'RULE_SEVERITY_LOW', PERMISSIVE: 'RULE_SEVERITY_LOW', ZTH_EBOOK: 'RULE_SEVERITY_MEDIUM' }
  },
  OFFENSIVE_LANG: {
    label: 'Offensive-Language',
    description: 'Detect adult content and offensive language',
    preferredEngines: ['Offensive Language'],
    dictionaries: ['Adult Content'],
    complianceKey: 'dlp_offensive',
    severity: { STRICT: 'RULE_SEVERITY_MEDIUM', BALANCED: 'RULE_SEVERITY_LOW', PERMISSIVE: 'RULE_SEVERITY_LOW', ZTH_EBOOK: 'RULE_SEVERITY_MEDIUM' }
  },
  SELF_HARM: {
    label: 'Self-Harm-Cyberbullying',
    description: 'Detect self-harm and cyberbullying content (K-12 student safety)',
    preferredEngines: ['Self-Harm & Cyberbullying'],
    dictionaries: ['Self-Harm & Cyberbullying'],
    complianceKey: 'dlp_selfharm',
    severity: { STRICT: 'RULE_SEVERITY_HIGH', BALANCED: 'RULE_SEVERITY_HIGH', PERMISSIVE: 'RULE_SEVERITY_MEDIUM', ZTH_EBOOK: 'RULE_SEVERITY_HIGH' }
  },
  GDPR_EU_IDS: {
    label: 'GDPR-EU-Identifiers',
    description: 'GDPR: Detect EU national identification numbers, passport numbers, and tax IDs',
    preferredEngines: [],
    dictionaries: [
      'National Identification Number (France)', 'National Identification Number (Spain)',
      'National Identification Number (Poland)', 'Passport Number (European Union)',
      'Citizen Service Numbers (Netherlands)', 'Fiscal Code (Italy)',
      'National Insurance Number (UK)', 'National Health Service Number (UK)'
    ],
    complianceKey: 'dlp_gdpr',
    severity: { STRICT: 'RULE_SEVERITY_HIGH', BALANCED: 'RULE_SEVERITY_MEDIUM', PERMISSIVE: 'RULE_SEVERITY_LOW', ZTH_EBOOK: 'RULE_SEVERITY_HIGH' }
  },
  RESUME_HR: {
    label: 'Resume-HR-Documents',
    description: 'Detect resume and HR-related documents',
    preferredEngines: [],
    dictionaries: ['Resume Document', 'Insurance Document'],
    complianceKey: 'dlp_pii',
    severity: { STRICT: 'RULE_SEVERITY_LOW', BALANCED: 'RULE_SEVERITY_LOW', PERMISSIVE: 'RULE_SEVERITY_LOW', ZTH_EBOOK: 'RULE_SEVERITY_LOW' }
  }
};

// Which DLP rule definitions to include for each compliance framework + tier
function getComplianceDlpRuleDefs(complianceFramework, tier) {
  const frameworkRules = {
    HIPAA: {
      STRICT:     ['HIPAA_SSN_MEDICAL', 'PCI_CARDS', 'MEDICAL_INFO', 'PII_SSN_NAMES', 'CREDENTIALS', 'SOURCE_CODE'],
      BALANCED:   ['HIPAA_SSN_MEDICAL', 'PCI_CARDS', 'MEDICAL_INFO', 'PII_SSN_NAMES', 'CREDENTIALS'],
      PERMISSIVE: ['HIPAA_SSN_MEDICAL', 'MEDICAL_INFO'],
      ZTH_EBOOK:  ['HIPAA_SSN_MEDICAL', 'PCI_CARDS', 'MEDICAL_INFO', 'PII_SSN_NAMES', 'PII_TAX_ID', 'CREDENTIALS', 'FINANCIAL_DOCS', 'SOURCE_CODE']
    },
    HITRUST: {
      STRICT:     ['HIPAA_SSN_MEDICAL', 'PCI_CARDS', 'MEDICAL_INFO', 'PII_SSN_NAMES', 'CREDENTIALS', 'FINANCIAL_DOCS', 'SOURCE_CODE'],
      BALANCED:   ['HIPAA_SSN_MEDICAL', 'PCI_CARDS', 'MEDICAL_INFO', 'PII_SSN_NAMES', 'CREDENTIALS'],
      PERMISSIVE: ['HIPAA_SSN_MEDICAL', 'MEDICAL_INFO', 'PCI_CARDS'],
      ZTH_EBOOK:  ['HIPAA_SSN_MEDICAL', 'PCI_CARDS', 'MEDICAL_INFO', 'PII_SSN_NAMES', 'PII_TAX_ID', 'CREDENTIALS', 'FINANCIAL_DOCS', 'SOURCE_CODE']
    },
    'NIST_800_53': {
      STRICT:     ['PII_SSN_NAMES', 'PII_TAX_ID', 'CREDENTIALS', 'HIPAA_SSN_MEDICAL', 'PCI_CARDS', 'FINANCIAL_DOCS', 'SOURCE_CODE'],
      BALANCED:   ['PII_SSN_NAMES', 'CREDENTIALS', 'HIPAA_SSN_MEDICAL', 'PCI_CARDS'],
      PERMISSIVE: ['PII_SSN_NAMES', 'CREDENTIALS'],
      ZTH_EBOOK:  ['PII_SSN_NAMES', 'PII_TAX_ID', 'CREDENTIALS', 'HIPAA_SSN_MEDICAL', 'PCI_CARDS', 'MEDICAL_INFO', 'FINANCIAL_DOCS', 'SOURCE_CODE']
    },
    'NIST_800_171': {
      STRICT:     ['PII_SSN_NAMES', 'PII_TAX_ID', 'CREDENTIALS', 'HIPAA_SSN_MEDICAL', 'PCI_CARDS', 'SOURCE_CODE'],
      BALANCED:   ['PII_SSN_NAMES', 'CREDENTIALS', 'HIPAA_SSN_MEDICAL'],
      PERMISSIVE: ['PII_SSN_NAMES', 'CREDENTIALS'],
      ZTH_EBOOK:  ['PII_SSN_NAMES', 'PII_TAX_ID', 'CREDENTIALS', 'HIPAA_SSN_MEDICAL', 'PCI_CARDS', 'MEDICAL_INFO', 'SOURCE_CODE']
    },
    PCI: {
      STRICT:     ['PCI_CARDS', 'GLBA_FINANCIAL', 'FINANCIAL_DOCS', 'CREDENTIALS', 'PII_SSN_NAMES', 'SOURCE_CODE'],
      BALANCED:   ['PCI_CARDS', 'GLBA_FINANCIAL', 'FINANCIAL_DOCS', 'CREDENTIALS'],
      PERMISSIVE: ['PCI_CARDS', 'GLBA_FINANCIAL', 'FINANCIAL_DOCS'],
      ZTH_EBOOK:  ['PCI_CARDS', 'GLBA_FINANCIAL', 'FINANCIAL_DOCS', 'CREDENTIALS', 'PII_SSN_NAMES', 'HIPAA_SSN_MEDICAL', 'SOURCE_CODE']
    },
    CJIS: {
      STRICT:     ['PII_SSN_NAMES', 'PII_TAX_ID', 'CREDENTIALS', 'HIPAA_SSN_MEDICAL', 'PCI_CARDS', 'SOURCE_CODE'],
      BALANCED:   ['PII_SSN_NAMES', 'CREDENTIALS', 'HIPAA_SSN_MEDICAL'],
      PERMISSIVE: ['PII_SSN_NAMES', 'CREDENTIALS'],
      ZTH_EBOOK:  ['PII_SSN_NAMES', 'PII_TAX_ID', 'CREDENTIALS', 'HIPAA_SSN_MEDICAL', 'PCI_CARDS', 'SOURCE_CODE']
    },
    SOX: {
      STRICT:     ['FINANCIAL_DOCS', 'GLBA_FINANCIAL', 'PCI_CARDS', 'CREDENTIALS', 'LEGAL_DOCS', 'PII_SSN_NAMES', 'SOURCE_CODE'],
      BALANCED:   ['FINANCIAL_DOCS', 'GLBA_FINANCIAL', 'PCI_CARDS', 'CREDENTIALS', 'LEGAL_DOCS'],
      PERMISSIVE: ['FINANCIAL_DOCS', 'GLBA_FINANCIAL', 'CREDENTIALS'],
      ZTH_EBOOK:  ['FINANCIAL_DOCS', 'GLBA_FINANCIAL', 'PCI_CARDS', 'CREDENTIALS', 'LEGAL_DOCS', 'PII_SSN_NAMES', 'SOURCE_CODE']
    },
    FERPA: {
      STRICT:     ['PII_SSN_NAMES', 'CREDENTIALS', 'OFFENSIVE_LANG', 'SELF_HARM', 'RESUME_HR'],
      BALANCED:   ['PII_SSN_NAMES', 'CREDENTIALS', 'OFFENSIVE_LANG', 'SELF_HARM'],
      PERMISSIVE: ['PII_SSN_NAMES', 'OFFENSIVE_LANG', 'SELF_HARM'],
      ZTH_EBOOK:  ['PII_SSN_NAMES', 'CREDENTIALS', 'OFFENSIVE_LANG', 'SELF_HARM', 'RESUME_HR']
    },
    GDPR: {
      STRICT:     ['GDPR_EU_IDS', 'PII_SSN_NAMES', 'CREDENTIALS', 'HIPAA_SSN_MEDICAL', 'PCI_CARDS', 'FINANCIAL_DOCS', 'SOURCE_CODE'],
      BALANCED:   ['GDPR_EU_IDS', 'PII_SSN_NAMES', 'CREDENTIALS', 'HIPAA_SSN_MEDICAL', 'PCI_CARDS'],
      PERMISSIVE: ['GDPR_EU_IDS', 'PII_SSN_NAMES', 'CREDENTIALS'],
      ZTH_EBOOK:  ['GDPR_EU_IDS', 'PII_SSN_NAMES', 'CREDENTIALS', 'HIPAA_SSN_MEDICAL', 'PCI_CARDS', 'FINANCIAL_DOCS', 'MEDICAL_INFO', 'SOURCE_CODE']
    }
  };

  // No framework — general-purpose set
  if (!complianceFramework || !frameworkRules[complianceFramework]) {
    const general = {
      STRICT:     ['HIPAA_SSN_MEDICAL', 'PCI_CARDS', 'GLBA_FINANCIAL', 'PII_SSN_NAMES', 'CREDENTIALS', 'FINANCIAL_DOCS', 'MEDICAL_INFO', 'LEGAL_DOCS', 'SOURCE_CODE'],
      BALANCED:   ['HIPAA_SSN_MEDICAL', 'PCI_CARDS', 'GLBA_FINANCIAL', 'PII_SSN_NAMES', 'CREDENTIALS', 'FINANCIAL_DOCS'],
      PERMISSIVE: ['HIPAA_SSN_MEDICAL', 'PCI_CARDS', 'CREDENTIALS'],
      ZTH_EBOOK:  ['HIPAA_SSN_MEDICAL', 'PCI_CARDS', 'GLBA_FINANCIAL', 'PII_SSN_NAMES', 'PII_TAX_ID', 'CREDENTIALS', 'FINANCIAL_DOCS', 'MEDICAL_INFO', 'LEGAL_DOCS', 'SOURCE_CODE']
    };
    return general[tier] || general['BALANCED'];
  }

  return frameworkRules[complianceFramework][tier] || frameworkRules[complianceFramework]['BALANCED'];
}

function generateDlpRules(tier, complianceFramework, prefix = 'ZTP') {
  const rules = [];
  let order = 1;

  const ruleDefKeys = getComplianceDlpRuleDefs(complianceFramework, tier);

  for (const defKey of ruleDefKeys) {
    const def = DLP_RULE_DEFS[defKey];
    if (!def) continue;

    rules.push({
      name: `${prefix}-DLP-${def.label}`,
      order: order++,
      state: 'ENABLED',
      action: 'ALLOW',
      protocols: ['ANY_RULE'],
      // Engine resolution: tried first at apply time; names may differ per tenant
      preferredEngineNames: def.preferredEngines || [],
      // Dictionary names: universal across all tenants, used as fallback
      // and also to build a custom engine if no predefined engine matches
      dictionaryNames: def.dictionaries || [],
      severity: def.severity[tier] || 'RULE_SEVERITY_MEDIUM',
      useZscalerIncidentReceiver: true,
      matchOnly: false,
      withoutContentInspection: false,
      description: `DLP: ${def.description}. Action=Allow with Incident Receiver. Dictionaries: ${def.dictionaries.join(', ')}`,
      tier,
      complianceMapping: mapToCompliance(def.complianceKey, complianceFramework)
    });
  }

  return rules;
}

// ========================
// ZERO TRUST HOSPITAL EBOOK TEMPLATES
// Based on "Zero Trust Hospital Architects Policy" document
// Global rules only (no user/group targeting)
// ========================

function generateZTHUrlFilteringRules(prefix = 'ZTP') {
  const rules = [];
  let order = 1;

  // 1. Block Legal Liability Class (Block With Override in doc, but we use BLOCK for API — override needs group config)
  rules.push({
    name: `${prefix}-Block-Legal-Liability`,
    order: order++,
    state: 'ENABLED',
    action: 'BLOCK',
    urlCategories: [
      'OTHER_ADULT_MATERIAL', 'ADULT_THEMES', 'LINGERIE_BIKINI', 'NUDITY',
      'PORNOGRAPHY', 'SEXUALITY', 'ADULT_SEX_EDUCATION', 'K_12_SEX_EDUCATION',
      'SOCIAL_ADULT', 'OTHER_DRUGS', 'MARIJUANA', 'GAMBLING',
      'OTHER_ILLEGAL_OR_QUESTIONABLE', 'COPYRIGHT_INFRINGEMENT',
      'COMPUTER_HACKING', 'QUESTIONABLE', 'PROFANITY', 'MATURE_HUMOR',
      'ANONYMIZER', 'MILITANCY_HATE_AND_EXTREMISM', 'TASTELESS', 'VIOLENCE',
      'WEAPONS_AND_BOMBS'
    ],
    protocols: ['ANY_RULE'],
    description: 'Block Legal Liability class. In production, enable Block With Override for IT staff investigating security incidents.',
    tier: 'ZTH_EBOOK'
  });

  // 2. Block Security Globally
  rules.push({
    name: `${prefix}-Block-Security-Globally`,
    order: order++,
    state: 'ENABLED',
    action: 'BLOCK',
    urlCategories: [
      'OTHER_SECURITY', 'ADWARE_OR_SPYWARE', 'ENCR_WEB_CONTENT',
      'DYNAMIC_DNS', 'NEWLY_REVIVED_DOMAINS', 'NEWLY_REG_DOMAINS'
    ],
    protocols: ['ANY_RULE'],
    description: 'Blocks critical security risk categories including spyware, adware, newly registered domains, and dynamic DNS hosts.',
    tier: 'ZTH_EBOOK'
  });

  // 3. Block FileHost & Webmail Globally
  rules.push({
    name: `${prefix}-Block-FileHost-Webmail`,
    order: order++,
    state: 'ENABLED',
    action: 'BLOCK',
    urlCategories: ['FILE_HOST', 'EMAIL_HOST'],
    protocols: ['ANY_RULE'],
    description: 'Global block for file hosting and personal webmail. Exceptions handled through Cloud App Control for approved services.',
    tier: 'ZTH_EBOOK'
  });

  // 4. Caution New Domains
  rules.push({
    name: `${prefix}-Caution-New-Domains`,
    order: order++,
    state: 'ENABLED',
    action: 'CAUTION',
    urlCategories: ['NEWLY_REG_DOMAINS', 'NEWLY_REVIVED_DOMAINS'],
    protocols: ['ANY_RULE'],
    description: 'Display end-user notification for newly registered or revived domains. Allows user to proceed after acknowledging phishing risk warning.',
    tier: 'ZTH_EBOOK'
  });

  // 5. Block Cryptocurrency — uses custom category since CRYPTOMINING enum varies by tenant
  rules.push({
    name: `${prefix}-Block-Crypto`,
    order: order++,
    state: 'ENABLED',
    action: 'BLOCK',
    urlCategories: ['OTHER_INTERNET_COMMUNICATION'],
    protocols: ['ANY_RULE'],
    description: 'Blocks cryptocurrency/mining sites. If your tenant has a dedicated Cryptocurrency URL category, update this rule in the ZIA portal.',
    tier: 'ZTH_EBOOK'
  });

  // 6. Block Remote Access Tools
  rules.push({
    name: `${prefix}-Block-Remote-Access`,
    order: order++,
    state: 'ENABLED',
    action: 'BLOCK',
    urlCategories: ['REMOTE_ACCESS', 'ANONYMIZER'],
    protocols: ['ANY_RULE'],
    description: 'Blocks unauthorized remote access tools commonly exploited in ransomware attacks. IT support staff can override via ZIA admin portal.',
    tier: 'ZTH_EBOOK'
  });

  // 7. Caution Generative AI — use valid categories; AI_ML categories vary by tenant/version
  rules.push({
    name: `${prefix}-Caution-AI`,
    order: order++,
    state: 'ENABLED',
    action: 'CAUTION',
    urlCategories: ['OTHER_INFORMATION_TECHNOLOGY'],
    protocols: ['ANY_RULE'],
    description: 'Caution page for AI/technology platforms. If your tenant has dedicated AI/ML URL categories, update this rule in the ZIA portal.',
    tier: 'ZTH_EBOOK'
  });

  // 8. Block Translation Services
  rules.push({
    name: `${prefix}-Block-Translation`,
    order: order++,
    state: 'ENABLED',
    action: 'BLOCK',
    urlCategories: ['TRANSLATORS'],
    protocols: ['ANY_RULE'],
    description: 'Blocks public translation services (Google Translate) that could expose PHI through text input.',
    tier: 'ZTH_EBOOK'
  });

  // 9. Block Miscellaneous/Uncategorized
  rules.push({
    name: `${prefix}-Isolate-Misc-Unknown`,
    order: order++,
    state: 'ENABLED',
    action: 'ISOLATE',
    isolateFallback: 'CAUTION',
    urlCategories: ['MISCELLANEOUS_OR_UNKNOWN', 'OTHER_MISCELLANEOUS', 'NON_CATEGORIZABLE'],
    protocols: ['HTTPS_RULE', 'HTTP_RULE'],
    description: 'Open uncategorized and miscellaneous sites in Cloud Browser Isolation, so obscure but legitimate sites (e.g. medical device vendors) stay reachable without risk to the device.',
    tier: 'ZTH_EBOOK'
  });

  // 10. Block P2P Communication
  rules.push({
    name: `${prefix}-Block-P2P`,
    order: order++,
    state: 'ENABLED',
    action: 'BLOCK',
    urlCategories: ['P2P_COMMUNICATION'],
    protocols: ['ANY_RULE'],
    description: 'Block peer-to-peer communication sites to prevent data exfiltration and unauthorized file sharing.',
    tier: 'ZTH_EBOOK'
  });

  // 11. Custom block category
  rules.push({
    name: `${prefix}-Block-Custom-Category`,
    order: order++,
    state: 'ENABLED',
    action: 'BLOCK',
    urlCategories: [`${prefix}_Custom_Block`],
    protocols: ['ANY_RULE'],
    description: 'Block URLs manually added to custom block category',
    tier: 'ZTH_EBOOK',
    requiresCustomCategory: true,
    customCategoryName: `${prefix}_Custom_Block`
  });

  return rules;
}

function generateZTHFirewallRules(prefix = 'ZTP') {
  const rules = [];
  let order = 5;

  for (const g of geoFirewallRules(prefix, 'ZTH_EBOOK', null)) rules.push({ ...g, order: order++ });

  rules.push({
    name: `${prefix}-Block-QUIC`,
    order: order++,
    state: 'ENABLED',
    action: 'BLOCK_DROP',
    nwApplications: ['QUIC'],
    description: 'Block QUIC to force TCP for SSL inspectability.',
    tier: 'ZTH_EBOOK'
  });

  rules.push({
    name: `${prefix}-Allow-Web`,
    order: order++,
    state: 'ENABLED',
    action: 'ALLOW',
    nwApplications: ['HTTP', 'HTTPS', 'HTTP2', 'DNS', 'SSL'],
    description: 'Allow HTTP, HTTPS, HTTP2, DNS, and SSL traffic.',
    tier: 'ZTH_EBOOK'
  });

  rules.push({
    name: `${prefix}-Allow-NTP`,
    order: order++,
    state: 'ENABLED',
    action: 'ALLOW',
    nwApplications: ['NTP'],
    description: 'Allow NTP for time synchronization.',
    tier: 'ZTH_EBOOK'
  });

  rules.push({
    name: `${prefix}-Allow-Collab`,
    order: order++,
    state: 'ENABLED',
    action: 'ALLOW',
    nwApplications: ['ZOOM', 'WEBEX', 'GOTOMEETING', 'SKYPE', 'SKYPE_FOR_BUSINESS', 'SIP', 'RTP', 'RTCP'],
    description: 'Allow collaboration (Zoom, WebEx, Teams, SIP/RTP).',
    tier: 'ZTH_EBOOK'
  });

  rules.push({
    name: `${prefix}-Allow-Enterprise`,
    order: order++,
    state: 'ENABLED',
    action: 'ALLOW',
    nwApplications: ['LDAP', 'LDAPS', 'KRB5', 'RADIUS', 'SNMP', 'DHCP', 'ICMP', 'SSH', 'RDP', 'OCSP'],
    description: 'Allow enterprise services (LDAP, Kerberos, RADIUS, SSH, RDP).',
    tier: 'ZTH_EBOOK'
  });

  rules.push({
    name: `${prefix}-Block-P2P`,
    order: order++,
    state: 'ENABLED',
    action: 'BLOCK_DROP',
    nwApplications: [
      'BITTORRENT', 'EDONKEY', 'GNUTELLA', 'KAZAA', 'ARES', 'DIRECTCONNECT',
      'THUNDER', 'SLSK', 'PANDO', 'IMESH', 'APPLEJUICE'
    ],
    description: 'Block P2P file sharing applications.',
    tier: 'ZTH_EBOOK'
  });

  rules.push({
    name: `${prefix}-Block-Tunnels`,
    order: order++,
    state: 'ENABLED',
    action: 'BLOCK_DROP',
    nwApplications: ['TOR', 'ULTRASURF', 'PSIPHON', 'OPENVPN', 'HTTPTUNNEL', 'SOCKS2HTTP', 'TEREDO'],
    description: 'Block tunneling and proxy evasion apps.',
    tier: 'ZTH_EBOOK'
  });

  return rules;
}

function generateZTHSslInspectionRules(prefix = 'ZTP') {
  const rules = [];
  let order = 1;

  // 1. Exclude Finance, Health, Government
  rules.push({
    name: `${prefix}-SSL-Excl-Fin-Hlth-Gov`,
    order: order++,
    state: 'ENABLED',
    action: 'DO_NOT_DECRYPT',
    urlCategories: ['FINANCE', 'HEALTH', 'GOVERNMENT', 'OTHER_GOVERNMENT_AND_POLITICS'],
    description: 'Exclude Finance, Health, and Government categories from SSL Inspection. Evaluate URL Filtering and Cloud App Control policies.',
    tier: 'ZTH_EBOOK'
  });

  // 2. SSL Inspect Catch All — TLS 1.2 minimum (stricter than Balanced)
  rules.push({
    name: `${prefix}-SSL-Inspect-Catch-All`,
    order: order++,
    state: 'ENABLED',
    action: 'DECRYPT',
    urlCategories: ['ANY'],
    description: 'Inspect all remaining SSL/TLS traffic. Blocks TLS 1.0 & 1.1 globally. Untrusted server certificates blocked. OCSP check enabled.',
    tier: 'ZTH_EBOOK',
    // ZTH-specific: TLS 1.2 minimum (stricter than balanced TLS 1.0)
    minClientTLS: 'CLIENT_TLS_1_2',
    minServerTLS: 'SERVER_TLS_1_2'
  });

  return rules;
}

// ========================
// SANDBOX (BA) RULE TEMPLATES
// Based on Zero Trust Hospital Architects Policy
// API: POST /api/v1/sandboxRules
// ========================

function generateSandboxRules(tier, complianceFramework, prefix = 'ZTP') {
  const rules = [];
  let order = 1;

  const ALL_BA_CATEGORIES = [
    'ADWARE_BLOCK', 'BOTMAL_BLOCK', 'ANONYP2P_BLOCK',
    'RANSOMWARE_BLOCK', 'OFFSEC_TOOLS_BLOCK', 'SUSPICIOUS_BLOCK'
  ];

  // 1. Office & PDF Quarantine + Isolate using the Default Isolation Profile
  rules.push({
    name: `${prefix}-Sandbox-OfficePDF`,
    order: order++,
    state: 'ENABLED',
    protocols: ['HTTPS_RULE', 'HTTP_RULE'],
    fileTypes: [
      'FTCATEGORY_MS_EXCEL', 'FTCATEGORY_MS_WORD', 'FTCATEGORY_MS_RTF',
      'FTCATEGORY_MS_POWERPOINT', 'FTCATEGORY_PDF_DOCUMENT'
    ],
    baPolicyCategories: ALL_BA_CATEGORIES,
    baRuleAction: 'BLOCK',
    firstTimeEnable: true,
    firstTimeOperation: 'QUARANTINE_ISOLATE',
    mlActionEnabled: true,
    // cbiProfile will be resolved at apply time by looking up "Default Isolation Profile"
    cbiProfileName: 'Default Isolation Profile',
    description: 'Quarantine & isolate Office/PDF files during sandbox analysis using Default Isolation Profile. Block subsequent known-bad downloads.',
    tier,
    complianceMapping: mapToCompliance('sandbox_office', complianceFramework)
  });

  // 2. Windows Executables — Allow & Scan for known software sources
  if (tier === 'STRICT' || tier === 'BALANCED' || tier === 'ZTH_EBOOK') {
    rules.push({
      name: `${prefix}-Sandbox-Executables`,
      order: order++,
      state: 'ENABLED',
      protocols: ['HTTPS_RULE', 'HTTP_RULE'],
      fileTypes: [
        'FTCATEGORY_WINDOWS_EXECUTABLES', 'FTCATEGORY_WINDOWS_LIBRARY',
        'FTCATEGORY_POWERSHELL', 'FTCATEGORY_VISUAL_BASIC_SCRIPT'
      ],
      baPolicyCategories: ALL_BA_CATEGORIES,
      baRuleAction: 'BLOCK',
      firstTimeEnable: true,
      firstTimeOperation: 'ALLOW_SCAN',
      mlActionEnabled: true,
      description: 'Allow & scan executables on first download. Block subsequent known-bad downloads. AI Instant Verdict enabled.',
      tier,
      complianceMapping: mapToCompliance('sandbox_executables', complianceFramework)
    });
  }

  // 3. Catch-all — Quarantine archives and remaining risky types
  // Note: Sandbox API does not accept "ANY" for fileTypes — must list explicit types
  rules.push({
    name: `${prefix}-Sandbox-CatchAll`,
    order: order++,
    state: 'ENABLED',
    protocols: ['ANY_RULE'],
    fileTypes: [
      'FTCATEGORY_ZIP', 'FTCATEGORY_RAR', 'FTCATEGORY_TAR', 'FTCATEGORY_BZIP2',
      'FTCATEGORY_P7Z', 'FTCATEGORY_ISO', 'FTCATEGORY_SCZIP',
      'FTCATEGORY_HTA', 'FTCATEGORY_FLASH', 'FTCATEGORY_JAVA_APPLET',
      'FTCATEGORY_MICROSOFT_INSTALLER', 'FTCATEGORY_BAT',
      'FTCATEGORY_WINDOWS_SCRIPT_FILES', 'FTCATEGORY_APK',
      'FTCATEGORY_PYTHON', 'FTCATEGORY_PDF_DOCUMENT'
    ],
    baPolicyCategories: ALL_BA_CATEGORIES,
    baRuleAction: 'BLOCK',
    firstTimeEnable: true,
    firstTimeOperation: 'QUARANTINE',
    mlActionEnabled: true,
    description: 'Catch-all sandbox rule for archives and remaining risky file types. Quarantine on first download.',
    tier,
    complianceMapping: mapToCompliance('sandbox_catchall', complianceFramework)
  });

  return rules;
}

// ========================
// DNS SECURITY (DNS CONTROL) RULE TEMPLATES
// Based on Zero Trust Hospital Architects Policy
// API: POST /api/v1/firewallDnsRules
// ========================

function generateDnsSecurityRules(tier, complianceFramework, prefix = 'ZTP') {
  const rules = [];
  let order = 1;

  // 1. Block Critical risk DNS tunnels (specific malicious tunnel apps)
  rules.push({
    name: `${prefix}-DNS-Block-Critical-Tunnels`,
    order: order++,
    state: 'ENABLED',
    action: 'BLOCK',
    rank: 7,
    protocols: ['ANY_RULE'],
    applications: [
      'BAIDUYUNDNS', 'DNSTUN_MALICIOUS', 'GENESISMISSIONARYBAPTISTCHURCH',
      'HOFF', 'KR0', 'LEARNZOLASUITE', 'MAILSHELL', 'SONGMOUNTAINFINEART',
      'TGIN', 'THREEMINUTEWEBSITE', 'TOADTEXTURE', 'TRUCKINSURANCE',
      'WEAVERPUBLISHING'
    ],
    description: 'Block critical risk DNS tunnels (known malicious DNS tunnel applications)',
    tier,
    complianceMapping: mapToCompliance('dns_tunnels_critical', complianceFramework)
  });

  // 2. Block High risk DNS tunnels (all DNS tunnel categories)
  if (tier === 'STRICT' || tier === 'BALANCED' || tier === 'ZTH_EBOOK') {
    rules.push({
      name: `${prefix}-DNS-Block-High-Tunnels`,
      order: order++,
      state: 'ENABLED',
      action: 'BLOCK',
      rank: 7,
      protocols: ['ANY_RULE'],
      applications: [
        'DNSTUN_UNKNOWN', 'DNSTUN_SOCIAL', 'DNSTUN_IM', 'DNSTUN_P2P',
        'DNSTUN_STREAMING', 'DNSTUN_WEBSEARCH', 'DNSTUN_MALWARE',
        'DNSTUN_IMAGEHOST', 'DNSTUN_ENTERPRISE', 'DNSTUN_BUSINESS',
        'DNSTUN_MAPPSTORE', 'DNSTUN_GAMING', 'DNSTUN_NETMGMT',
        'DNSTUN_AUTH', 'DNSTUN_TUNNELING', 'DNSTUN_FILESERVER_TRANSFER',
        'DNSTUN_DATABASE', 'DNSTUN_CONFERENCE', 'DNSTUN_REMOTE',
        'DNSTUN_MOBILE', 'DNSTUN_ADS'
      ],
      description: 'Block high risk DNS tunnels (all DNS tunnel categories)',
      tier,
      complianceMapping: mapToCompliance('dns_tunnels_high', complianceFramework)
    });
  }

  // 3. DNS over HTTPS is inspected, not just blocked: DoH lookups of risky domains are blocked, the rest resolve normally
  rules.push({
    name: `${prefix}-DNS-DoH-Block-Risky`,
    order: order++,
    state: 'ENABLED',
    action: 'BLOCK',
    rank: 7,
    protocols: ['DOHTTPS_RULE'],
    destIpCategories: ['NEWLY_REG_DOMAINS', 'NEWLY_REVIVED_DOMAINS', 'DYNAMIC_DNS', 'ADWARE_OR_SPYWARE', 'OTHER_SECURITY'],
    description: 'Inspect DNS over HTTPS: block DoH lookups of newly registered, dynamic DNS and spyware domains. Other DoH lookups are allowed and logged (check with 1.1.1.1/help).',
    tier,
    complianceMapping: mapToCompliance('dns_doh', complianceFramework)
  });

  // 4. Resolver control: plain DNS sent to any resolver (e.g. 8.8.8.8) is answered by the Zscaler Trusted Resolver
  rules.push({
    name: `${prefix}-DNS-Trusted-Resolver`,
    order: order++,
    state: 'ENABLED',
    action: 'REDIR_REQ',
    rank: 7,
    protocols: ['TCP_RULE', 'UDP_RULE'],
    useTrustedResolver: true,
    description: 'Send DNS requests to the Zscaler Trusted Resolver, even when a device is set to use another resolver (e.g. 8.8.8.8). ZPA resolver rules above still apply.',
    tier,
    complianceMapping: mapToCompliance('dns_resolver', complianceFramework)
  });

  return rules;
}

// ========================
// FILE TYPE CONTROL RULE TEMPLATES
// Based on Zero Trust Hospital Architects Policy
// API: POST /api/v1/fileTypeRules
// ========================

function generateFileTypeControlRules(tier, complianceFramework, prefix = 'ZTP') {
  const rules = [];
  let order = 1;

  // 1. Block Database Files upload
  rules.push({
    name: `${prefix}-FTC-Block-Database-Upload`,
    order: order++,
    state: 'ENABLED',
    protocols: ['HTTPS_RULE', 'HTTP_RULE'],
    fileTypes: [
      'FTCATEGORY_ACCDB', 'FTCATEGORY_SQL', 'FTCATEGORY_DBF',
      'FTCATEGORY_DB', 'FTCATEGORY_SDB', 'FTCATEGORY_DB2'
    ],
    filteringAction: 'BLOCK',
    operation: 'UPLOAD',
    description: 'Block upload of database files to internet destinations. Prevents mass data exfiltration through database exports.',
    tier,
    complianceMapping: mapToCompliance('ftc_database', complianceFramework)
  });

  // 2. Block Password-Protected Archives
  if (tier === 'STRICT' || tier === 'ZTH_EBOOK') {
    rules.push({
      name: `${prefix}-FTC-Block-PW-Archives`,
      order: order++,
      state: 'ENABLED',
      protocols: ['ANY_RULE'],
      fileTypes: [
        'FTCATEGORY_ZIP', 'FTCATEGORY_RAR', 'FTCATEGORY_P7Z'
      ],
      filteringAction: 'BLOCK',
      operation: 'UPLOAD_DOWNLOAD',
      passwordProtected: true,
      description: 'Block password-protected archives that cannot be inspected. Prevents blind spots for DLP and malware.',
      tier,
      complianceMapping: mapToCompliance('ftc_pw_archives', complianceFramework)
    });
  }

  // 3. Block executables from untrusted sources
  rules.push({
    name: `${prefix}-FTC-Block-Exe-DL`,
    order: order++,
    state: 'ENABLED',
    protocols: ['HTTPS_RULE', 'HTTP_RULE'],
    fileTypes: [
      'FTCATEGORY_WINDOWS_EXECUTABLES', 'FTCATEGORY_MICROSOFT_INSTALLER',
      'FTCATEGORY_APPX'
    ],
    filteringAction: 'BLOCK',
    operation: 'DOWNLOAD',
    description: 'Block download of executables from internet. Exceptions for approved software repos should be added above this rule.',
    tier,
    complianceMapping: mapToCompliance('ftc_executables', complianceFramework)
  });

  // 4. Block script files
  if (tier === 'STRICT' || tier === 'BALANCED' || tier === 'ZTH_EBOOK') {
    rules.push({
      name: `${prefix}-FTC-Block-Scripts`,
      order: order++,
      state: 'ENABLED',
      protocols: ['HTTPS_RULE', 'HTTP_RULE'],
      fileTypes: [
        'FTCATEGORY_POWERSHELL', 'FTCATEGORY_VISUAL_BASIC_SCRIPT',
        'FTCATEGORY_BAT', 'FTCATEGORY_WINDOWS_SCRIPT_FILES',
        'FTCATEGORY_PYTHON', 'FTCATEGORY_BASH_SCRIPTS'
      ],
      filteringAction: 'BLOCK',
      operation: 'UPLOAD_DOWNLOAD',
      description: 'Block upload/download of script files (PowerShell, VBS, BAT, Python, Bash). Common malware delivery mechanism.',
      tier,
      complianceMapping: mapToCompliance('ftc_scripts', complianceFramework)
    });
  }

  // 5. Caution on large file uploads (Balanced/Permissive)
  // Note: File Type Control API doesn't have a CAUTION action; use ALLOW with size quota
  // We use BLOCK for strict, skip for permissive

  return rules;
}

// ========================
// CLOUD APP CONTROL RULE TEMPLATES
// Based on Zero Trust Hospital Architects Policy
// API: POST /api/v1/webApplicationRules/:rule_type
// ========================

// App-specific Cloud App Control rules that show granular controls (view but not upload / post).
// They come first in their rule type, so they win over the category-wide rules further down.
// App enums and actions were read from ZTH with /cloudApplications/policy and /webApplicationRules/{type}/availableActions.
// fallbackActions: used when the tenant rejects the first set (re-runs accept either set as No change).
const GRANULAR_CAC_RULES = [
  { key: 'CAC-FileShare-ViewOnly', type: 'FILE_SHARE', applications: ['GDRIVE', 'DROPBOX', 'BOXNET'],
    actions: ['ALLOW_FILE_SHARE_VIEW', 'DENY_FILE_SHARE_UPLOAD'],
    fallbackActions: ['ALLOW_FILE_SHARE_DOWNLOAD', 'DENY_FILE_SHARE_CREATE', 'DENY_FILE_SHARE_EDIT', 'DENY_FILE_SHARE_SHARE'],
    description: 'Google Drive, Dropbox and Box: users can open and download files but cannot upload, edit or share. Every other file-sharing app falls through to the file-sharing rule below.' },
  { key: 'CAC-Social-ViewNoPost', type: 'SOCIAL_NETWORKING', applications: ['FACEBOOK', 'TWITTER'],
    actions: ['ALLOW_SOCIAL_NETWORKING_VIEW', 'BLOCK_SOCIAL_NETWORKING_POST'],
    description: 'Facebook and X: reading is allowed, posting is blocked.' },
  { key: 'CAC-LinkedIn-ReadOnly', type: 'SOCIAL_NETWORKING', applications: ['LINKEDIN'],
    actions: ['ALLOW_SOCIAL_NETWORKING_VIEW', 'BLOCK_SOCIAL_NETWORKING_POST', 'BLOCK_SOCIAL_NETWORKING_COMMENT', 'BLOCK_SOCIAL_NETWORKING_SHARE', 'BLOCK_SOCIAL_NETWORKING_UPLOAD'],
    fallbackActions: ['ALLOW_SOCIAL_NETWORKING_VIEW', 'BLOCK_SOCIAL_NETWORKING_POST'],
    description: 'LinkedIn: browsing and recruiting research allowed; posting, commenting, sharing and uploading are blocked.' },
  { key: 'CAC-GenAI-NoUpload', type: 'AI_ML', applications: ['CHATGPT_AI', 'GOOGLE_GEMINI', 'MICROSOFT_COPILOT'],
    actions: ['ALLOW_AI_ML_WEB_USE', 'DENY_AI_ML_UPLOAD'],
    description: 'ChatGPT, Gemini and Copilot: prompts are allowed (and captured by AI Prompt Capture), file uploads are blocked.' },
  { key: 'CAC-Slack-NoFileUpload', type: 'ENTERPRISE_COLLABORATION', applications: ['SLACK'],
    actions: ['ALLOW_ENTERPRISE_COLLABORATION_CHAT', 'BLOCK_ENTERPRISE_COLLABORATION_UPLOAD'],
    fallbackActions: ['BLOCK_ENTERPRISE_COLLABORATION_UPLOAD'],
    description: 'Slack: chat is allowed, file uploads are blocked.' }
];

function generateCloudAppControlRules(tier, complianceFramework, prefix = 'ZTP') {
  const rules = [];
  let order = 1;

  for (const g of GRANULAR_CAC_RULES) {
    rules.push({
      name: `${prefix}-${g.key}`,
      order: order++,
      state: 'ENABLED',
      type: g.type,
      ruleType: g.type,
      applications: g.applications.slice(),
      actions: g.actions.slice(),
      ...(g.fallbackActions ? { fallbackActions: g.fallbackActions.slice() } : {}),
      granular: true,
      description: g.description,
      tier,
      complianceMapping: mapToCompliance('cac_fileshare', complianceFramework)
    });
  }

  // 1. Block DNS over HTTPS — 12 apps (AdGuard, Cloudflare DNS, Google DNS, Quad9, etc.)
  rules.push({
    name: `${prefix}-CAC-Block-DoH`,
    order: order++,
    // Off by default: DNS Control inspects DoH (DNS-DoH-Block-Risky). Turn on to block DoH apps outright instead.
    state: 'DISABLED',
    type: 'DNS_OVER_HTTPS',
    ruleType: 'DNS_OVER_HTTPS',
    actions: ['DENY_DNS_OVER_HTTPS_USE'],
    description: 'Optional (off): block all 12 DNS over HTTPS apps outright. Off by default because DNS Control inspects DoH instead.',
    tier,
    complianceMapping: mapToCompliance('cac_doh', complianceFramework)
  });

  // 2. Block file sharing (global) — 218 apps (4Shared, Box, Dropbox, Google Drive, etc.)
  // Note: When targeting all apps in the category, use the top-level block action only.
  // Granular sub-actions (upload/download/share) require specific app selection.
  rules.push({
    name: `${prefix}-CAC-Block-FileShare`,
    order: order++,
    state: 'ENABLED',
    type: 'FILE_SHARE',
    ruleType: 'FILE_SHARE',
    actions: ['DENY_FILE_SHARE_VIEW', 'DENY_FILE_SHARE_UPLOAD'],
    description: 'Block viewing/uploading across all 218 file-sharing apps. Add allow rules above for approved services (Box, Google Drive, OneDrive).',
    tier,
    complianceMapping: mapToCompliance('cac_fileshare', complianceFramework)
  });

  // 3. Block instant messaging — 56 apps (AIM, ChatWork, Discord, Facebook IM, Google Chat, etc.)
  if (tier === 'STRICT' || tier === 'ZTH_EBOOK') {
    rules.push({
      name: `${prefix}-CAC-Block-IM`,
      order: order++,
      state: 'ENABLED',
      type: 'INSTANT_MESSAGING',
      ruleType: 'INSTANT_MESSAGING',
      actions: ['BLOCK_CHAT', 'BLOCK_FILE_TRANSFER_IN_CHAT'],
      description: 'Block all 56 IM apps (Discord, Facebook IM, Google Chat, Kik, Telegram, etc.). Add allow rules above for Teams, Slack.',
      tier,
      complianceMapping: mapToCompliance('cac_im', complianceFramework)
    });
  } else if (tier === 'BALANCED') {
    rules.push({
      name: `${prefix}-CAC-Restrict-IM`,
      order: order++,
      state: 'ENABLED',
      type: 'INSTANT_MESSAGING',
      ruleType: 'INSTANT_MESSAGING',
      actions: ['BLOCK_FILE_TRANSFER_IN_CHAT'],
      description: 'Block file transfers in IM apps. Chat allowed. Add allow rules above for approved enterprise IM.',
      tier,
      complianceMapping: mapToCompliance('cac_im', complianceFramework)
    });
  }

  // 4. Block social networking — 81 apps (Facebook, Instagram, LinkedIn, Twitter, TikTok, etc.)
  rules.push({
    name: `${prefix}-CAC-Restrict-Social`,
    order: order++,
    state: 'ENABLED',
    type: 'SOCIAL_NETWORKING',
    ruleType: 'SOCIAL_NETWORKING',
    actions: tier === 'STRICT' || tier === 'ZTH_EBOOK'
      ? ['BLOCK_SOCIAL_NETWORKING_VIEW', 'BLOCK_SOCIAL_NETWORKING_POST']
      : ['ALLOW_SOCIAL_NETWORKING_VIEW', 'BLOCK_SOCIAL_NETWORKING_POST'],
    description: tier === 'STRICT' || tier === 'ZTH_EBOOK'
      ? 'Block all 81 social networking apps. Add exceptions above for marketing/communications.'
      : 'Block posting on 81 social apps. Read-only viewing allowed.',
    tier,
    complianceMapping: mapToCompliance('cac_social', complianceFramework)
  });

  // 5. Block webmail — 44 apps (Gmail, Outlook Personal, Yahoo, ProtonMail, AOL, etc.)
  rules.push({
    name: `${prefix}-CAC-Block-Webmail`,
    order: order++,
    state: 'ENABLED',
    type: 'WEBMAIL',
    ruleType: 'WEBMAIL',
    actions: ['BLOCK_WEBMAIL_VIEW', 'BLOCK_WEBMAIL_ATTACHMENT_SEND', 'BLOCK_WEBMAIL_SEND'],
    description: 'Block all 44 personal webmail apps (Gmail, Yahoo, ProtonMail, etc.). Add allow rules above for corporate Outlook Web.',
    tier,
    complianceMapping: mapToCompliance('cac_webmail', complianceFramework)
  });

  // 6. Block/restrict streaming media — 214 apps (YouTube, Netflix, Spotify, Hulu, etc.)
  if (tier === 'STRICT' || tier === 'ZTH_EBOOK') {
    rules.push({
      name: `${prefix}-CAC-Block-Streaming`,
      order: order++,
      state: 'ENABLED',
      type: 'STREAMING_MEDIA',
      ruleType: 'STREAMING_MEDIA',
      actions: ['BLOCK_STREAMING_VIEW_LISTEN'],
      description: 'Block all 214 streaming media apps. Add exceptions above for approved services.',
      tier,
      complianceMapping: mapToCompliance('cac_streaming', complianceFramework)
    });
  } else if (tier === 'BALANCED') {
    rules.push({
      name: `${prefix}-CAC-NoUpload-Stream`,
      order: order++,
      state: 'ENABLED',
      type: 'STREAMING_MEDIA',
      ruleType: 'STREAMING_MEDIA',
      actions: ['BLOCK_STREAMING_UPLOAD'],
      description: 'Block uploads to 214 streaming apps. Viewing/listening allowed.',
      tier,
      complianceMapping: mapToCompliance('cac_streaming', complianceFramework)
    });
  }

  // 7. Restrict Enterprise Collaboration — 1499 apps (Zoom, Teams, Slack, WebEx, etc.)
  // Note: Granular sub-actions require specific app selection. Use top-level block for category-wide rule.
  if (tier === 'STRICT' || tier === 'ZTH_EBOOK') {
    rules.push({
      name: `${prefix}-CAC-Restrict-Collab`,
      order: order++,
      state: 'ENABLED',
      type: 'ENTERPRISE_COLLABORATION',
      ruleType: 'ENTERPRISE_COLLABORATION',
      actions: ['BLOCK_ENTERPRISE_COLLABORATION_APPS'],
      description: 'Block all 1499 collaboration apps. Add allow rules above for corporate Zoom, Teams, Slack.',
      tier,
      complianceMapping: mapToCompliance('cac_fileshare', complianceFramework)
    });
  }

  // 8. Restrict AI/ML apps — 144 apps (ChatGPT, Claude, Gemini, Copilot, DALL-E, Hugging Face, etc.)
  rules.push({
    name: `${prefix}-CAC-Restrict-AI-ML`,
    order: order++,
    state: 'ENABLED',
    type: 'AI_ML',
    ruleType: 'AI_ML',
    actions: tier === 'STRICT' || tier === 'ZTH_EBOOK'
      ? ['DENY_AI_ML_WEB_USE']
      : ['CAUTION_AI_ML_WEB_USE'],   // category-wide rules take web-use actions only; upload controls need specific apps (live, ZTH)
    description: tier === 'STRICT' || tier === 'ZTH_EBOOK'
      ? 'Block all 144 AI/ML apps (ChatGPT, Claude, Gemini, DALL-E, etc.). Add exceptions above for approved research teams with DLP.'
      : 'Caution page on 144 AI/ML apps. Upload blocking needs specific apps selected; inline DLP covers PHI/PII leakage to AI platforms.',
    tier,
    complianceMapping: mapToCompliance('cac_aiml', complianceFramework)
  });

  return rules;
}

// ========================
// ALLOW / BLOCK ACTION SETTINGS (v1.6.0)
// ========================
//
// Lets the operator choose Allow or Block per policy type and per rule, so the tier's
// defaults never silently block something important.
//
// actionSettings = {
//   policy: { urlFiltering|firewallFiltering|dnsSecurity|fileTypeControl|cloudAppControl|dlp: 'DEFAULT'|'ALLOW'|'BLOCK' },
//   rules:  { '<policyKey>:<rule name without prefix>': 'ALLOW'|'BLOCK' }   // wins over policy-level
// }
// 'DEFAULT' (or absent) keeps exactly what the selected tier generates, including CAUTION.

// Which field holds the action for each policy type, and what Allow/Block map to.
const ACTION_POLICY_TYPES = {
  urlFiltering:      { label: 'URL Filtering',          field: 'action',          allow: 'ALLOW', block: 'BLOCK' },
  firewallFiltering: { label: 'Cloud Firewall',         field: 'action',          allow: 'ALLOW', block: 'BLOCK_DROP' },
  dnsSecurity:       { label: 'DNS Security',           field: 'action',          allow: 'ALLOW', block: 'BLOCK' },
  fileTypeControl:   { label: 'File Type Control',      field: 'filteringAction', allow: 'ALLOW', block: 'BLOCK' },
  cloudAppControl:   { label: 'Cloud App Control',      field: 'actions' },
  dlp:               { label: 'Data Loss Prevention',   field: 'action',          allow: 'ALLOW', block: 'BLOCK' }
};

// Rules that keep the internet working; flipping them to Block would cut off all users.
const LOCKED_RULE_SUFFIXES = new Set(['Allow-Web', 'Allow-NTP']);

// Cloud App Control action bases that use DENY_ instead of BLOCK_ (from the
// webApplicationRules action enum in the Automation Hub docs).
const CAC_DENY_BASES = new Set([
  'AI_ML_CHAT', 'AI_ML_CREATE', 'AI_ML_DELETE', 'AI_ML_DOWNLOAD', 'AI_ML_INVITE', 'AI_ML_RENAME',
  'AI_ML_SHARE', 'AI_ML_UPLOAD', 'AI_ML_WEB_USE', 'DNS_OVER_HTTPS_USE', 'FILE_SHARE_CREATE',
  'FILE_SHARE_DELETE', 'FILE_SHARE_DOWNLOAD', 'FILE_SHARE_EDIT', 'FILE_SHARE_FORM_SHARE',
  'FILE_SHARE_INVITE', 'FILE_SHARE_RENAME', 'FILE_SHARE_SHARE', 'FILE_SHARE_UPLOAD', 'FILE_SHARE_VIEW',
  'FINANCE_USE', 'HEALTH_CARE_USE', 'HOSTING_PROVIDER_CREATE', 'HOSTING_PROVIDER_DELETE',
  'HOSTING_PROVIDER_DOWNLOAD', 'HOSTING_PROVIDER_EDIT', 'HOSTING_PROVIDER_MOVE', 'HOSTING_PROVIDER_USE',
  'HUMAN_RESOURCES_USE', 'IT_SERVICES_USE', 'LEGAL_USE'
]);

const CAC_PREFIX_RE = /^(ALLOW|BLOCK|DENY|CAUTION|ISOLATE)_/;
const cacBase = (a) => a.replace(CAC_PREFIX_RE, '');
const cacToAllow = (a) => 'ALLOW_' + cacBase(a);
const cacToBlock = (a) => (CAC_DENY_BASES.has(cacBase(a)) ? 'DENY_' : 'BLOCK_') + cacBase(a);
const uniq = (arr) => [...new Set(arr)];

const isBlockLike = (a) => typeof a === 'string' && /^(BLOCK|DENY)/.test(a);
const isRestrictive = (a) => typeof a === 'string' && /^(BLOCK|DENY|CAUTION|ISOLATE)/.test(a);

// One-word summary of a rule's action (Cloud App Control has an array).
function summarizeAction(policyKey, rule) {
  if (policyKey === 'cloudAppControl') {
    const acts = rule.actions || [];
    if (acts.some(isBlockLike)) return 'BLOCK';
    if (acts.some(a => /^(CAUTION|ISOLATE)/.test(a))) return 'CAUTION';
    return 'ALLOW';
  }
  return rule[ACTION_POLICY_TYPES[policyKey].field];
}

function applyActionSettings(policyKey, rules, actionSettings, prefix) {
  const meta = ACTION_POLICY_TYPES[policyKey];
  const policyChoice = actionSettings?.policy?.[policyKey];
  const ruleChoices = actionSettings?.rules || {};

  return rules.map(rule => {
    const suffix = rule.name.startsWith(`${prefix}-`) ? rule.name.slice(prefix.length + 1) : rule.name;
    const key = `${policyKey}:${suffix}`;
    // Redirect rules (resolver control) are not allow/block rules: flipping one to Block would block all DNS
    const locked = (policyKey === 'firewallFiltering' && LOCKED_RULE_SUFFIXES.has(suffix)) || (policyKey === 'dnsSecurity' && /^REDIR/.test(rule.action || ''));
    const defaultAction = summarizeAction(policyKey, rule);

    let choice = null;
    const okChoice = (c) => c === 'ALLOW' || c === 'BLOCK' || (c === 'ISOLATE' && policyKey === 'urlFiltering');
    if (!locked) {
      if (okChoice(ruleChoices[key])) choice = ruleChoices[key];
      else if (okChoice(policyChoice)) choice = policyChoice;
    }

    const out = { ...rule, actionKey: key, actionPolicyType: policyKey, defaultAction, locked };

    if (choice && policyKey === 'cloudAppControl') {
      out.defaultActions = rule.actions;
      out.actions = uniq((rule.actions || []).map(choice === 'ALLOW' ? cacToAllow : cacToBlock));
      if (rule.fallbackActions) out.fallbackActions = uniq(rule.fallbackActions.map(choice === 'ALLOW' ? cacToAllow : cacToBlock));
    } else if (choice === 'ISOLATE') {
      // Open these categories in Cloud Browser Isolation (profile chosen on the Customize step)
      out.action = 'ISOLATE';
      out.protocols = ['HTTPS_RULE', 'HTTP_RULE'];
    } else if (choice === 'ALLOW') {
      out[meta.field] = meta.allow;
    } else if (choice === 'BLOCK') {
      // Keep the rule's own block flavour (e.g. BLOCK_DROP vs BLOCK_RESET) if it already blocks
      out[meta.field] = isBlockLike(rule[meta.field]) ? rule[meta.field] : meta.block;
    }

    // DLP descriptions advertise the action; keep them honest
    if (policyKey === 'dlp' && choice === 'BLOCK' && typeof out.description === 'string') {
      out.description = out.description.replace('Action=Allow with Incident Receiver', 'Action=Block');
    }

    out.effectiveAction = summarizeAction(policyKey, out);
    out.userChoice = choice;
    out.actionChanged = choice !== null && JSON.stringify(policyKey === 'cloudAppControl' ? out.actions : out.effectiveAction)
      !== JSON.stringify(policyKey === 'cloudAppControl' ? rule.actions : defaultAction);
    out.weakened = isRestrictive(defaultAction) && !isRestrictive(out.effectiveAction);
    if (out.weakened) out.isRisky = true;
    return out;
  });
}

function applyAllActionSettings(template, actionSettings) {
  const prefix = template.metadata.prefix;
  for (const policyKey of Object.keys(ACTION_POLICY_TYPES)) {
    if (Array.isArray(template.policies[policyKey])) {
      template.policies[policyKey] = applyActionSettings(policyKey, template.policies[policyKey], actionSettings, prefix);
    }
  }
  template.actionChanges = Object.keys(ACTION_POLICY_TYPES).flatMap(k =>
    (template.policies[k] || []).filter(r => r.actionChanged).map(r => ({
      key: r.actionKey, name: r.name, policyType: k,
      from: r.defaultAction, to: r.effectiveAction, weakened: !!r.weakened
    })));
  return template;
}

/**
 * Every rule with its default, for the wizard's Rules step: an on/off switch for every rule,
 * Allow / Block overrides where the policy type supports them, and Isolate for URL rules.
 */
function getActionCatalog(config) {
  const full = generateFullTemplate({ ...config, actionSettings: null, disabledRules: {} });
  const prefix = full.metadata.prefix;
  const out = [];
  for (const [policyKey, label] of Object.entries(RULE_POLICY_TYPES)) {
    const rules = full.policies[policyKey];
    if (!Array.isArray(rules) || rules.length === 0) continue;
    const canOverride = !!ACTION_POLICY_TYPES[policyKey];
    out.push({
      type: policyKey, label, canOverride, canIsolate: policyKey === 'urlFiltering',
      rules: rules.map(r => ({
        key: r.toggleKey || ruleKey(policyKey, r, prefix), name: r.name, description: r.description,
        defaultAction: canOverride ? r.defaultAction
          : (typeof r.action === 'string' ? r.action : (r.action && r.action.type) || r.baRuleAction || r.filteringAction || ''),
        defaultActions: policyKey === 'cloudAppControl' ? r.actions : undefined,
        locked: !!r.locked,
        categoryCount: Array.isArray(r.urlCategories) ? r.urlCategories.length : undefined
      }))
    });
  }
  return out;
}

// Every rule-based policy type gets toggle keys (`policy:Suffix`); Allow/Block overrides stay limited to ACTION_POLICY_TYPES.
const RULE_POLICY_TYPES = {
  urlFiltering: 'URL Filtering', firewallFiltering: 'Cloud Firewall', sslInspection: 'SSL Inspection', sandbox: 'Sandbox',
  dnsSecurity: 'DNS Security', fileTypeControl: 'File Type Control', cloudAppControl: 'Cloud App Control', dlp: 'Data Loss Prevention'
};
const ruleKey = (policyKey, rule, prefix) => `${policyKey}:${rule.name.startsWith(`${prefix}-`) ? rule.name.slice(prefix.length + 1) : rule.name}`;

/**
 * Turn off the rules the user switched off and attach the isolation profile / interception certificate.
 * disabledRules: { 'urlFiltering:Block-Security-Risk': true }
 * cbiProfile {id,name,url}: used by URL Isolate rules and Sandbox "Quarantine & Isolate"; cbiProfileName comes from a framework file.
 * sslCertificate {id,name}: used by the SSL Inspect (DECRYPT) rules this tool creates; none = Zscaler default certificate.
 */
function applyToggles(template, { disabledRules = {}, cbiProfile = null, cbiProfileName = null, sslCertificate = null } = {}) {
  const prefix = template.metadata.prefix;
  const off = [];
  disabledRules = disabledRules || {};
  for (const policyKey of Object.keys(RULE_POLICY_TYPES)) {
    const rules = template.policies[policyKey];
    if (!Array.isArray(rules)) continue;
    template.policies[policyKey] = rules.filter(r => {
      const key = r.actionKey || ruleKey(policyKey, r, prefix);
      r.toggleKey = key;
      if (disabledRules[key]) { off.push({ key, name: r.name, policyType: policyKey }); return false; }
      return true;
    });
    if (!template.policies[policyKey].length) delete template.policies[policyKey];
  }
  const cbi = cbiProfile || (cbiProfileName ? { name: cbiProfileName } : null);
  if (cbi) {
    for (const r of (template.policies.urlFiltering || [])) if (r.action === 'ISOLATE') r.cbiProfile = cbi;
    for (const r of (template.policies.sandbox || [])) if (r.firstTimeOperation === 'QUARANTINE_ISOLATE') r.cbiProfile = cbi;
  }
  if (sslCertificate && sslCertificate.id !== undefined && template.policies.sslInspection) {
    for (const r of template.policies.sslInspection) if (r.action === 'DECRYPT' || r.action === 'INSPECT') r.sslInterceptionCert = { id: sslCertificate.id, name: sslCertificate.name };
  }
  template.disabledItems = off;
  return template;
}

// ZIA rejects rule names longer than 31 characters ("Name exceeds the max length 31 characters").
const MAX_RULE_NAME = 31;
const NAME_ABBREV = [[/Advanced-Threat-Protection/g, 'ATP'], [/Inspection/g, 'Insp'], [/Inspect/g, 'Insp'], [/Ransomware/g, 'Ransom'],
  [/Malware/g, 'Mal'], [/Exemptions?/g, 'Exempt'], [/Communication/g, 'Comm'], [/Applications?/g, 'Apps'], [/Recommended/g, 'Rec'],
  [/Unknown/g, 'Unk'], [/Suspicious/g, 'Susp'], [/Newly-Registered/g, 'NRD'], [/Remaining/g, 'Rest'], [/Control/g, 'Ctl'],
  [/Security/g, 'Sec'], [/Category/g, 'Cat'], [/Block/g, 'Blk'], [/Allow/g, 'Alw']];
function shortRuleName(name, prefix = '') {
  const full = String(name || '');
  // Abbreviate only the part after "<prefix>-" so every name keeps the global prefix (GLB-02)
  const head = prefix && full.startsWith(prefix + '-') ? prefix + '-' : '';
  let n = full.slice(head.length);
  const room = MAX_RULE_NAME - head.length;
  for (const [re, to] of NAME_ABBREV) { if (n.length <= room) break; n = n.replace(re, to); }
  if (n.length > room) n = n.substring(0, room).replace(/[-_ ]+$/, '');
  return head + n;
}
function clampRuleNames(template) {
  const prefix = (template.metadata && template.metadata.prefix) || '';
  for (const rules of Object.values(template.policies || {})) {
    if (!Array.isArray(rules)) continue;
    const used = new Set();
    for (const r of rules) {
      if (!r || typeof r.name !== 'string') continue;
      let n = shortRuleName(r.name, prefix);
      for (let i = 2; used.has(n); i++) n = n.substring(0, MAX_RULE_NAME - String(i).length - 1).replace(/[-_ ]+$/, '') + '-' + i;
      if (n !== r.name) { r.fullName = r.fullName || r.name; r.name = n; }
      used.add(n);
    }
  }
  return template;
}

// Turn-off switches, isolation profile / certificate, 31-character names, checklist
function finishTemplate(template, config) {
  applyAllActionSettings(template, config.actionSettings || null);
  applyToggles(template, config);
  clampRuleNames(template);
  template.implementationChecklist = generateChecklist(template);
  return template;
}

function generateFullTemplate(config) {
  const {
    tier = 'BALANCED',
    complianceFramework = null,
    prefix = 'ZTP',
    enableUrlFiltering = true,
    enableFirewall = true,
    enableSslInspection = true,
    enableMalwareProtection = true,
    enableAdvancedSettings = true,
    enableSandbox = true,
    enableDnsSecurity = true,
    enableFileTypeControl = true,
    enableCloudAppControl = true,
    enableDlp = true,
    actionSettings = null,
    baseTemplate = null
  } = config;

  const template = {
    metadata: {
      name: `${prefix}-${complianceFramework || 'General'}-${tier}`,
      tier,
      complianceFramework: complianceFramework ? COMPLIANCE_FRAMEWORKS[complianceFramework] : null,
      prefix,
      generatedAt: new Date().toISOString(),
      version: '1.9.0',
      source: baseTemplate ? (baseTemplate.metadata?.source || 'framework file') : 'built-in',
      actionSettings: actionSettings || null
    },
    policies: {}
  };

  // A framework captured from a tenant (or loaded from a file that carries policies) is used as-is
  if (baseTemplate) {
    const base = JSON.parse(JSON.stringify(baseTemplate.policies || {}));
    const gate = { urlFiltering: enableUrlFiltering, firewallFiltering: enableFirewall, sslInspection: enableSslInspection, sandbox: enableSandbox,
      dnsSecurity: enableDnsSecurity, fileTypeControl: enableFileTypeControl, cloudAppControl: enableCloudAppControl, dlp: enableDlp,
      malwareProtection: enableMalwareProtection, advancedSettings: enableAdvancedSettings };
    for (const [k, v] of Object.entries(base)) if (gate[k] !== false) template.policies[k] = v;
    if (Array.isArray(baseTemplate.customCategories) && baseTemplate.customCategories.length) template.customCategories = JSON.parse(JSON.stringify(baseTemplate.customCategories));
    template.metadata.name = baseTemplate.metadata?.name || template.metadata.name;
    return finishTemplate(template, config);
  }

  // ZTH Ebook tier uses its own dedicated rule generators for URL/FW/SSL
  // but shares the new module generators with standard tiers
  if (tier === 'ZTH_EBOOK') {
    if (enableUrlFiltering) {
      template.policies.urlFiltering = generateZTHUrlFilteringRules(prefix);
    }
    if (enableFirewall) {
      template.policies.firewallFiltering = generateZTHFirewallRules(prefix);
    }
    if (enableSslInspection) {
      template.policies.sslInspection = generateZTHSslInspectionRules(prefix);
    }
    // New v1.2.0 modules — now automated for ZTH
    if (enableSandbox) {
      template.policies.sandbox = generateSandboxRules('ZTH_EBOOK', complianceFramework, prefix);
    }
    if (enableDnsSecurity) {
      template.policies.dnsSecurity = generateDnsSecurityRules('ZTH_EBOOK', complianceFramework, prefix);
    }
    if (enableFileTypeControl) {
      template.policies.fileTypeControl = generateFileTypeControlRules('ZTH_EBOOK', complianceFramework, prefix);
    }
    if (enableCloudAppControl) {
      template.policies.cloudAppControl = generateCloudAppControlRules('ZTH_EBOOK', complianceFramework, prefix);
    }
    // v1.5.0: DLP module — healthcare-focused for ZTH
    if (enableDlp) {
      template.policies.dlp = generateDlpRules('ZTH_EBOOK', complianceFramework, prefix);
    }
    return finishTemplate(template, config);
  }

  // Standard tiers (STRICT, BALANCED, PERMISSIVE)
  if (enableUrlFiltering) {
    template.policies.urlFiltering = generateUrlFilteringRules(tier, complianceFramework, prefix);
  }
  if (enableFirewall) {
    template.policies.firewallFiltering = generateFirewallRules(tier, complianceFramework, prefix);
  }
  if (enableSslInspection) {
    template.policies.sslInspection = generateSslInspectionRules(tier, complianceFramework, prefix);
  }
  if (enableMalwareProtection) {
    template.policies.malwareProtection = generateMalwareProtectionSettings(tier, complianceFramework, prefix);
  }
  if (enableAdvancedSettings) {
    template.policies.advancedSettings = generateAdvancedSettings(tier, complianceFramework, prefix);
  }
  if (enableSandbox) {
    template.policies.sandbox = generateSandboxRules(tier, complianceFramework, prefix);
  }
  if (enableDnsSecurity) {
    template.policies.dnsSecurity = generateDnsSecurityRules(tier, complianceFramework, prefix);
  }
  if (enableFileTypeControl) {
    template.policies.fileTypeControl = generateFileTypeControlRules(tier, complianceFramework, prefix);
  }
  if (enableCloudAppControl) {
    template.policies.cloudAppControl = generateCloudAppControlRules(tier, complianceFramework, prefix);
  }
  // v1.5.0: DLP module
  if (enableDlp) {
    template.policies.dlp = generateDlpRules(tier, complianceFramework, prefix);
  }

  return finishTemplate(template, config);
}

function generateChecklist(template) {
  const items = [];
  let order = 1;

  items.push({ order: order++, task: 'Authenticate to ZIA API', category: 'Prerequisites', status: 'pending' });
  items.push({ order: order++, task: 'Review current tenant configuration (dry run)', category: 'Prerequisites', status: 'pending' });
  items.push({ order: order++, task: 'Take snapshot of current state for rollback', category: 'Prerequisites', status: 'pending' });

  if (template.policies.urlFiltering) {
    const customCatRules = template.policies.urlFiltering.filter(r => r.requiresCustomCategory);
    if (customCatRules.length > 0) {
      items.push({ order: order++, task: `Create custom URL category: ${customCatRules[0].customCategoryName}`, category: 'URL Filtering', status: 'pending' });
    }
    items.push({ order: order++, task: `Create ${template.policies.urlFiltering.length} URL filtering rules`, category: 'URL Filtering', status: 'pending' });
  }

  if (template.policies.firewallFiltering) {
    items.push({ order: order++, task: `Create ${template.policies.firewallFiltering.length} firewall filtering rules`, category: 'Firewall', status: 'pending' });
  }

  if (template.policies.sslInspection) {
    items.push({ order: order++, task: `Create ${template.policies.sslInspection.length} SSL inspection rules`, category: 'SSL Inspection', status: 'pending' });
    if (template.metadata.tier !== 'PERMISSIVE') {
      items.push({ order: order++, task: 'Deploy Zscaler root certificate to endpoints (manual)', category: 'SSL Inspection', status: 'pending', manual: true });
    }
  }

  if (template.policies.sandbox) {
    items.push({ order: order++, task: `Create ${template.policies.sandbox.length} sandbox rules`, category: 'Sandbox', status: 'pending' });
  }

  if (template.policies.dnsSecurity) {
    items.push({ order: order++, task: `Create ${template.policies.dnsSecurity.length} DNS security rules`, category: 'DNS Security', status: 'pending' });
  }

  if (template.policies.fileTypeControl) {
    items.push({ order: order++, task: `Create ${template.policies.fileTypeControl.length} file type control rules`, category: 'File Type Control', status: 'pending' });
  }

  if (template.policies.cloudAppControl) {
    items.push({ order: order++, task: `Create ${template.policies.cloudAppControl.length} cloud app control rules`, category: 'Cloud App Control', status: 'pending' });
  }

  if (template.policies.dlp) {
    const dlpBlocks = template.policies.dlp.filter(r => r.action === 'BLOCK').length;
    const dlpAllows = template.policies.dlp.length - dlpBlocks;
    const dlpActionText = dlpBlocks === 0 ? 'Action: Allow with Incident Receiver'
      : dlpAllows === 0 ? 'Action: Block' : `${dlpAllows} Allow, ${dlpBlocks} Block`;
    items.push({ order: order++, task: `Create ${template.policies.dlp.length} DLP policy rules (${dlpActionText})`, category: 'Data Loss Prevention', status: 'pending' });
    items.push({ order: order++, task: 'Verify DLP engines are available on tenant (predefined engines may need Zscaler Support activation)', category: 'Data Loss Prevention', status: 'pending', manual: true });
  }

  if (template.actionChanges && template.actionChanges.length > 0) {
    const weak = template.actionChanges.filter(c => c.weakened).length;
    items.push({ order: order++, task: `Review ${template.actionChanges.length} Allow/Block override(s) vs tier default${weak ? ` (${weak} weaken protection)` : ''}`, category: 'Allow / Block', status: 'pending', manual: true });
  }

  if (template.policies.malwareProtection) {
    items.push({ order: order++, task: 'Configure malware protection settings', category: 'Malware Protection', status: 'pending' });
  }

  if (template.policies.advancedSettings) {
    items.push({ order: order++, task: 'Configure advanced cloud settings', category: 'Advanced Settings', status: 'pending' });
  }

  items.push({ order: order++, task: 'Review all changes in diff view', category: 'Verification', status: 'pending' });
  items.push({ order: order++, task: 'Activate changes', category: 'Activation', status: 'pending' });
  items.push({ order: order++, task: 'Verify policies are active', category: 'Verification', status: 'pending' });
  items.push({ order: order++, task: 'Generate evidence/compliance report', category: 'Documentation', status: 'pending' });

  return items;
}

module.exports = {
  ACTION_POLICY_TYPES,
  RULE_POLICY_TYPES,
  ruleKey,
  applyToggles,
  clampRuleNames,
  shortRuleName,
  applyActionSettings,
  getActionCatalog,
  COMPLIANCE_FRAMEWORKS,
  URL_CATEGORY_CLASSES,
  DLP_ENGINE_MAP,
  DLP_RULE_DEFS,
  generateFullTemplate,
  generateUrlFilteringRules,
  generateFirewallRules,
  generateSslInspectionRules,
  generateMalwareProtectionSettings,
  generateAdvancedSettings,
  generateSandboxRules,
  generateDnsSecurityRules,
  generateFileTypeControlRules,
  generateCloudAppControlRules,
  generateDlpRules,
  generateZTHUrlFilteringRules,
  generateZTHFirewallRules,
  generateZTHSslInspectionRules
};
