/**
 * Policy Wizard 2.0 — every piece of user-facing copy added in this release, in one place (§10).
 * Edit text here; the UI reads it from GET /api/v2/meta.
 */
module.exports = {
  scope: {
    title: 'What is in scope?',
    intro: 'Choose the Zscaler Internet Access features this proof of value covers. Only what you select here is generated, reviewed and applied.',
    items: {
      dlpMonitor: { label: 'Inline Data Loss Prevention: Monitor Mode', desc: 'Allow-only DLP rules using Zscaler\'s built-in DLP engines for the framework you pick (for example HIPAA → HIPAA engine).' },
      dlpBlock: { label: 'Inline Data Loss Prevention: Block Mode', desc: 'Creates custom dictionaries and engines from the framework\'s sensitive-data definitions, then DLP rules that block by default (each rule can be switched to Allow).' },
      endpointDlp: { label: 'Endpoint Data Protection', desc: 'Endpoint DLP rules for USB / removable storage, personal cloud storage and printing, in Monitor mode, for Windows and macOS.' },
      sandboxStandard: { label: 'Zscaler Cloud Sandbox: Standard', desc: 'Sandbox rules for .exe and .dll files, Allow and Scan on first download.' },
      sandboxAdvanced: { label: 'Zscaler Cloud Sandbox: Advanced', desc: 'AI Instant Verdict on every rule across expanded file types: high-risk types are quarantined on first download, lower-risk types are allowed and scanned.' },
      aiPromptCapture: { label: 'Zscaler AI Prompt Capture', desc: 'Turns on prompt capture for the GenAI and UCaaS apps listed on the next pages.' },
      urlFiltering: { label: 'URL Filtering', desc: 'URL category rules for the framework.' },
      cloudAppControl: { label: 'Cloud App Controls', desc: 'Cloud application rules (AI/ML, file sharing, webmail, social and more).' },
      fileTypeControl: { label: 'File Type Controls', desc: 'Block risky file types.' },
      advancedThreatProtection: { label: 'Advanced Threat Protection Defaults', desc: 'Botnet, malicious content, phishing, cryptomining and P2P protections.' },
      firewallFiltering: { label: 'Cloud Firewall', desc: 'Outbound firewall rules (QUIC, P2P, tunnels, default deny where the framework calls for it).' },
      dnsSecurity: { label: 'DNS Security', desc: 'Block malicious and newly registered domains and DNS tunnels.' },
      sslInspection: { label: 'SSL Inspection', desc: 'Inspect encrypted traffic so the other controls (DLP, sandbox, file type) can see it. Not in the 2.0 spec list; kept so existing behaviour does not regress.' }
    },
    exclusiveNote: 'Choosing one of these switches the other off. Leave both off to skip the feature.',
    endpointPrereq: 'Endpoint DLP must first be enabled in the Zscaler Client Connector Portal (Mobile Admin). The wizard could not confirm it is enabled on this tenant. You can still continue; this is noted in the summary report.',
    endpointPrereqDisabled: 'Endpoint DLP is not enabled in the Zscaler Client Connector Portal (Mobile Admin) on this tenant. Enable it there first, or the endpoint rules will not reach devices. You can still continue; this is noted in the summary report.',
    notLicensed: 'Not licensed on this tenant',
    licenceUnknown: 'Could not confirm this tenant is licensed for this feature. You can continue; the apply may fail if it is not.'
  },
  aiPrompt: {
    note: 'Enabling this feature allows Zscaler to store prompts.',
    genAiTitle: 'GenAI Prompt Configuration',
    ucaasTitle: 'UCaaS'
  },
  baseline: {
    title: 'Baseline Framework',
    intro: 'Pick one compliance framework, or one non-mapped security level. It decides which rules are generated for the features in scope.',
    nonMappedTitle: 'Non-Mapped Framework'
  },
  zcc: {
    bypassWarning: 'Enabling this bypasses all Zscaler security features and sends this traffic directly for some applications. This can include both data and control traffic.',
    listDescriptions: {
      vpnGateways: 'Gateway addresses of third-party VPN clients. Traffic to these gateways is not tunneled through Zscaler so the other VPN can establish its connection.',
      ipInclusions: 'Destination IPs/ranges that are always sent through Zscaler, even if they would otherwise be bypassed.',
      ipExclusions: 'Destination IPs/ranges that bypass Zscaler and go direct.',
      dnsInclusions: 'Domains whose traffic is always sent through Zscaler.',
      dnsExclusions: 'Domains whose traffic bypasses Zscaler and goes direct.'
    },
    listFormats: {
      vpnGateways: 'CIDR or FQDN only (no wildcards).',
      other: 'Wildcard FQDN (*.example.com), FQDN, IP or CIDR.'
    },
    reauth: 'Automatically Attempt ZPA Reauthentication: on by default for Windows and macOS. Set per app profile (the profile stops following the global Platform Settings value).'
  },
  zpa: {
    locationBanner: 'The App Connector Group is created in San Jose, CA. Change its location in the ZPA admin portal after the wizard so users are steered to the nearest connectors.',
    keyNote: 'The provisioning key is a secret. It is also retrievable later in the ZPA console (Configuration & Control › Private Infrastructure › Provisioning Keys).',
    connectorGroupDescription: 'Created by the Zscaler Policy Wizard for a proof of value.',
    appSegmentDescription: 'Basic wildcard application segment created by the Zscaler Policy Wizard.',
    fqdnHelp: '*.example.com, 10.0.0.0/24',
    defaultsNote: 'These defaults apply to the ZPA application segment only. Closer to User is used because UDP ports are not supported with Closer to Application.'
  },
  report: {
    sensitive: 'SENSITIVE — this report contains a ZPA provisioning key. Store it securely and share it only with people deploying App Connectors.',
    followUps: {
      zpaLocation: 'Change the ZPA App Connector Group location from San Jose, CA to where the connectors will run.',
      zpaDeploy: 'Deploy App Connectors and enroll them with the provisioning key in this report.',
      endpointDlp: 'Enable Endpoint DLP in the Zscaler Client Connector Portal (Mobile Admin), then confirm the endpoint rules reach devices.',
      modernUi: 'Set "Modern UI" on the macOS app profile in the Mobile Admin portal (not available through the API).'
    }
  },
  bulk: {
    zpaOrder: 'Deletes run in dependency order: application segment → server group → segment group → provisioning key → App Connector Group.'
  }
};
