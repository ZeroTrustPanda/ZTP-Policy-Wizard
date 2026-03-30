/**
 * ZCC (Zscaler Client Connector) Templates
 * 
 * Mobile Admin Best Practices template:
 *   - Forwarding Profile: Z-Tunnel 2.0, transparent redirection, all traffic via T2
 *   - App Profile (Windows): SSL cert install, WFP driver, V8 PAC parser, 
 *     IPv6 disabled, Windows Firewall rules, logging, notification framework
 */

// ========================
// FORWARDING PROFILE TEMPLATE
// ========================

function generateForwardingProfileTemplate(prefix = 'ZTP', wizardAnswers = {}) {
  return {
    name: `${prefix}-FwdProfile-BestPractice`,
    active: 'true',
    conditionType: 0,
    evaluateTrustedNetwork: '0',
    skipTrustedCriteriaMatch: '0',
    predefinedTnAll: false,
    predefinedTrustedNetworks: false,
    forwardingProfileActions: [
      {
        // Z-Tunnel action for ZIA
        actionType: '1', // 1 = Tunnel
        networkType: '2', // 2 = All networks
        primaryTransport: '2', // 2 = Z-Tunnel 2.0
        enablePacketTunnel: '1', // Enable packet tunnel (transparent redirection)
        redirectWebTraffic: '1', // Transparent redirection of web traffic
        useTunnel2ForProxiedWebTraffic: '1', // Use Z-Tunnel 2.0 for all traffic
        allowTLSFallback: '0', // Don't allow TLS fallback
        systemProxy: '0',
        dropIpv6Traffic: '1', // Drop IPv6 to prevent bypass
        dropIpv6IncludeTrafficInT2: '1',
        dropIpv6TrafficInIpv6Network: '1',
        blockUnreachableDomainsTraffic: '0',
        pathMtuDiscovery: '0',
        latencyBasedZenEnablement: '0',
        mtuForZadapter: 1500,
        TLSTimeout: 90,
        DTLSTimeout: 90,
        UDPTimeout: 90,
        zenProbeInterval: 600,
        zenProbeSampleSize: 2,
        zenThresholdLimit: 0,
        tunnel2FallbackType: '0'
      }
    ],
    forwardingProfileZpaActions: [
      {
        // Z-Tunnel action for ZPA
        actionType: '1',
        networkType: '2',
        primaryTransport: '2', // Z-Tunnel 2.0
        latencyBasedServerMTEnablement: 0,
        latencyBasedZpaServerEnablement: '0',
        mtuForZadapter: 1500,
        TLSTimeout: 90,
        DTLSTimeout: 90,
        lbsZpaProbeInterval: 600,
        lbsZpaProbeSampleSize: 2,
        lbsZpaThresholdLimit: 0,
        sendTrustedNetworkResultToZpa: '0'
      }
    ],
    description: `${prefix} Best Practice Forwarding Profile: Z-Tunnel 2.0 with transparent redirection for all traffic. IPv6 dropped to prevent bypass.`
  };
}

// ========================
// APP PROFILE (WINDOWS) TEMPLATE
// ========================

function generateAppProfileTemplate(prefix = 'ZTP', wizardAnswers = {}) {
  const {
    bypassIPs = '',
    bypassPreDefinedApps = false,
    domainExclusions = '',
    domainInclusions = '',
    dnsServerExclusions = ''
  } = wizardAnswers;

  const profile = {
    name: `${prefix}-AppProfile-Windows`,
    device_type: 'windows',
    active: 'true',
    description: `${prefix} Best Practice Windows App Profile`,

    // Forwarding Profile — will be linked at apply time to the created forwarding profile
    // forwardingProfileId will be set dynamically

    windowsPolicy: {
      // SSL Certificate Installation — enable
      installCerts: '1',
      // WFP Driver — required for process-based bypass, ZDX, flow logging
      wfpDriver: 1,
      // Install Windows Firewall Inbound Rules — inbound and outbound
      installWindowsFirewallInboundRule: 1,
      // PAC Parser — V8 engine
      // (set via policyExtension.useV8JsEngine)
      // Cache System Proxy
      cacheSystemProxy: 0,
      // Override WPAD
      overrideWPAD: 0,
      // Prioritize IPv4
      prioritizeIPv4: 1,
      // Disable parallel IPv4 and IPv6
      disableParallelIpv4andIpv6: '1',
      // Remove exempted containers
      removeExemptedContainers: 0,
      // Restart WinHTTP service
      restartWinHttpSvc: 0,
      // Disable loopback restriction
      disableLoopBackRestriction: 0,
      // Force location refresh SCCM
      forceLocationRefreshSccm: 0,
      // PAC type
      pacType: 0
    },

    policyExtension: {
      // PAC Parser V8 engine
      useV8JsEngine: '1',
      // Drop QUIC traffic
      dropQuicTraffic: '1',
      // Ensure traffic doesn't leak via IPv6 — disable IPv6
      // (handled via forwarding profile dropIpv6Traffic)
      // Enable Zscaler Notification Framework
      useZscalerNotificationFramework: '1',
      // ZPA Reauthentication Notifications
      advanceZpaReauth: true,
      advanceZpaReauthTime: 30,
      // Follow routing table
      followRoutingTable: '1',
      // Enable ZDP service
      enableZdpService: '1',
      // Enable anti-tampering
      enableAntiTampering: '1',
      reactivateAntiTamperingTime: 60
    },

    // Logging mode — Default or Debug
    logMode: 'default',
    logLevel: 'info',
    logFileSize: '10',

    // Reauth period
    reauth_period: '168', // 7 days in hours

    // Tunnel traffic
    tunnelZappTraffic: '1'
  };

  // Bypass IP addresses (Z-Tunnel 1.0 & 2.0)
  if (bypassIPs) {
    profile.policyExtension.packetTunnelExcludeList = bypassIPs;
    profile.policyExtension.packetTunnelExcludeListForIPv6 = '';
  }

  // Bypass pre-defined IP-based applications (Zoom/Teams)
  if (bypassPreDefinedApps) {
    // This is typically set via bypassAppIds — the exact IDs depend on the tenant
    // For now we flag it in the description
    profile.description += ' | Pre-defined app bypass enabled';
  }

  // Domain exclusions (Z-Tunnel 2.0 only)
  if (domainExclusions) {
    profile.policyExtension.packetTunnelDnsExcludeList = domainExclusions;
  }

  // Domain inclusions (Z-Tunnel 2.0 only)
  if (domainInclusions) {
    profile.policyExtension.packetTunnelDnsIncludeList = domainInclusions;
  }

  // DNS server exclusions for domain processing
  if (dnsServerExclusions) {
    profile.policyExtension.packetTunnelExcludeList =
      (profile.policyExtension.packetTunnelExcludeList || '') +
      (profile.policyExtension.packetTunnelExcludeList ? ',' : '') +
      dnsServerExclusions;
  }

  return profile;
}

// ========================
// FULL ZCC TEMPLATE
// ========================

function generateZCCTemplate(config) {
  const {
    prefix = 'ZTP',
    wizardAnswers = {}
  } = config;

  return {
    metadata: {
      name: `${prefix}-Mobile-Admin-BestPractice`,
      type: 'ZCC',
      generatedAt: new Date().toISOString(),
      version: '1.3.0'
    },
    forwardingProfile: generateForwardingProfileTemplate(prefix, wizardAnswers),
    appProfile: generateAppProfileTemplate(prefix, wizardAnswers),
    wizardAnswers,
    implementationNotes: [
      'Forwarding Profile creates Z-Tunnel 2.0 with transparent redirection for all traffic',
      'IPv6 is disabled in the forwarding profile to prevent traffic bypass',
      'Windows App Profile enables: SSL cert install, WFP driver, V8 PAC parser, Windows Firewall rules',
      'Zscaler Notification Framework is enabled for ZPA reauth notifications',
      'Logging is set to Default mode — no impact on user experience',
      'Anti-tampering is enabled with 60-minute reactivation',
      'QUIC traffic is dropped to ensure inspectability',
      wizardAnswers.bypassIPs ? `IP bypasses configured: ${wizardAnswers.bypassIPs}` : 'No IP bypasses configured',
      wizardAnswers.bypassPreDefinedApps ? 'Pre-defined app bypass (Zoom/Teams) enabled' : 'No pre-defined app bypass',
      wizardAnswers.domainExclusions ? `Domain exclusions: ${wizardAnswers.domainExclusions}` : 'No domain exclusions',
    ].filter(Boolean)
  };
}

module.exports = {
  generateForwardingProfileTemplate,
  generateAppProfileTemplate,
  generateZCCTemplate
};
