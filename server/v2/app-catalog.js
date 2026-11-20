/**
 * v2.11: app catalog for the ZPA and ZDX steps. Apps are grouped by category and tagged with the verticals they are common
 * in. Nothing is filled in for the customer: each app is a toggle, and turning it on adds its segments (ZPA) or probes
 * (ZDX) with the vendor's ports and a placeholder that says which customer host goes there, for example
 * "{customer Hyperspace Web VIP}". Ports come from the vendor's own documentation or the customer's network data flow
 * (see each app's `source`); confirm them with the customer.
 *
 * zpa: application segments  { name, placeholder, tcp, udp, on }      on = ticked when the app is turned on
 * zdx: probes                { name, placeholder, port, path, on }    Web probe on https://host[:port]/path plus a CloudPath
 *                                                                     probe to the same host and port
 */
'use strict';

const CATEGORIES = [
  { id: 'INFRA', name: 'Infrastructure and identity' },
  { id: 'EHR', name: 'EHR and clinical systems' },
  { id: 'IMAGING', name: 'Imaging and PACS' },
  { id: 'CLINICAL_ACCESS', name: 'Clinical access and single sign-on' },
  { id: 'VDI', name: 'Virtual desktops and published apps' },
  { id: 'ERP', name: 'ERP, finance and HR' },
  { id: 'BANKING', name: 'Banking and trading' },
  { id: 'EDU', name: 'Student and campus systems' },
  { id: 'GOV', name: 'Government and GIS' },
  { id: 'DATA', name: 'Databases' },
  { id: 'SAAS', name: 'Internet SaaS (ZDX only)' }
];

const H = 'HEALTHCARE', F = 'FINANCE', G = 'FEDERAL', E = 'EDUCATION', ALL = 'ALL';

const APPS = [
  // ---------------- Infrastructure (every vertical)
  { id: 'WILDCARD', name: 'All internal apps', category: 'INFRA', verticals: [ALL], defaultOn: true,
    description: 'One wildcard segment for the internal domain. ZPA picks the most specific segment, so named apps below still get their own segment and policy.',
    zpa: [{ name: 'All internal apps', placeholder: '*.{domain}', tcp: '1-52, 54-65535', udp: '1-52, 54-65535', on: true, fill: '*.{domain}' }] },
  { id: 'AD', name: 'Active Directory', category: 'INFRA', verticals: [ALL],
    description: 'Domain controllers: Kerberos, LDAP, RPC, SMB, global catalog.',
    zpa: [{ name: 'Active Directory', placeholder: '{customer domain controllers, e.g. dc01.domain}', tcp: '88, 135, 389, 445, 464, 636, 3268, 3269, 49152-65535', udp: '88, 123, 389, 464', on: true }],
    source: 'Microsoft: Active Directory and AD DS port requirements' },
  { id: 'FILES', name: 'File shares', category: 'INFRA', verticals: [ALL],
    zpa: [{ name: 'File shares', placeholder: '{customer file servers}', tcp: '445', udp: '', on: true }] },
  { id: 'INTRANET', name: 'Intranet', category: 'INFRA', verticals: [ALL],
    zpa: [{ name: 'Intranet', placeholder: '{customer intranet host}', tcp: '80, 443', udp: '', on: true }],
    zdx: [{ name: 'Intranet', placeholder: '{customer intranet host}', port: 443, path: '/', on: true }] },
  { id: 'RDP', name: 'Remote desktop jump host', category: 'INFRA', verticals: [ALL],
    zpa: [{ name: 'Remote desktop jump host', placeholder: '{customer jump host}', tcp: '3389', udp: '', on: true }] },

  // ---------------- Healthcare: Epic (ports from the customer's Epic Network Data Flow workbook)
  { id: 'EPIC', name: 'Epic', category: 'EHR', verticals: [H], collection: 'Epic',
    description: 'Hyperspace Web (Hyperdrive, Hyperspace in browsers), Web BLOB, Interconnect, Security Token Service and Perimeter Authentication. All client connections are HTTPS 443 except Perimeter Authentication (443 + 7327).',
    source: 'Epic Network Data Flow (Connection List: Client Systems H&D / W&SS)',
    zpa: [
      { name: 'Epic Hyperspace Web', placeholder: '{customer Hyperspace Web VIP}', tcp: '443', udp: '', on: true },
      { name: 'Epic Web BLOB', placeholder: '{customer Web BLOB VIP}', tcp: '443', udp: '', on: true },
      { name: 'Epic Interconnect', placeholder: '{customer Interconnect VIP}', tcp: '443', udp: '', on: true },
      { name: 'Epic Security Token Service', placeholder: '{customer STS VIP}', tcp: '443', udp: '', on: false },
      { name: 'Epic Perimeter Authentication', placeholder: '{customer Perimeter Authentication VIP}', tcp: '443, 7327', udp: '', on: false },
      { name: 'Epic SlicerDicer', placeholder: '{customer SlicerDicer host}', tcp: '443', udp: '', on: false },
      { name: 'Epic MyChart', placeholder: '{customer MyChart host}', tcp: '443', udp: '', on: false },
      { name: 'Epic printing', placeholder: '{customer printers or print servers}', tcp: '515, 9100', udp: '', on: false }
    ],
    zdx: [
      { name: 'Epic HSW', placeholder: '{customer Hyperspace Web VIP}', port: 443, path: '/', on: true },
      { name: 'Epic Web BLOB', placeholder: '{customer Web BLOB VIP}', port: 443, path: '/', on: true },
      { name: 'Epic Interconnect', placeholder: '{customer Interconnect VIP}', port: 443, path: '/', on: false },
      { name: 'Epic Perimeter Auth', placeholder: '{customer Perimeter Authentication VIP}', port: 7327, path: '/', on: false }
    ] },

  // ---------------- Healthcare: other EHRs, imaging, clinical access
  { id: 'CERNER', name: 'Oracle Health (Cerner) Millennium', category: 'EHR', verticals: [H], collection: 'Oracle Health',
    description: 'PowerChart / FirstNet published through Citrix. Client-hosted Millennium: StoreFront 443 plus ICA 1494 and session reliability 2598. CernerWorks (CWx) remote-hosted: users reach the Cerner StoreFront over the internet, so it belongs in ZIA, not ZPA, unless the customer reaches it over a private circuit.',
    source: 'Citrix default network ports; Cerner CWx external access guides',
    zpa: [
      { name: 'Cerner Citrix StoreFront', placeholder: '{customer Cerner StoreFront host}', tcp: '443', udp: '', on: true },
      { name: 'Cerner Citrix sessions', placeholder: '{customer Cerner Citrix VDA servers}', tcp: '1494, 2598', udp: '1494, 2598', on: true }
    ],
    zdx: [{ name: 'Cerner StoreFront', placeholder: '{customer Cerner StoreFront host}', port: 443, path: '/', on: true }] },
  { id: 'MEDITECH', name: 'MEDITECH Expanse', category: 'EHR', verticals: [H], collection: 'MEDITECH',
    description: 'Expanse in a browser over HTTPS 443; many hospitals publish Expanse and Ambulatory through Citrix (443, 1494, 2598) or Remote Desktop Services (3389, RD Gateway 443). MEDITECH does not publish a client port list: confirm the workstation client ports with the customer.',
    source: 'MEDITECH Expanse remote access guides; Citrix default network ports',
    zpa: [
      { name: 'MEDITECH Expanse web', placeholder: '{customer Expanse web host}', tcp: '443', udp: '', on: true },
      { name: 'MEDITECH Citrix sessions', placeholder: '{customer MEDITECH Citrix servers}', tcp: '443, 1494, 2598', udp: '1494, 2598', on: false },
      { name: 'MEDITECH RDS', placeholder: '{customer MEDITECH RDS hosts}', tcp: '3389', udp: '', on: false }
    ],
    zdx: [{ name: 'MEDITECH Expanse', placeholder: '{customer Expanse web host}', port: 443, path: '/', on: true }] },
  { id: 'SYNAPSE', name: 'Fujifilm Synapse PACS', category: 'IMAGING', verticals: [H], collection: 'Synapse PACS',
    description: 'Synapse web/app server on HTTP 80 (443 when hardened), Synapse Mobility zero-footprint viewer on 8443 (8080 HTTP), DICOM 104 for workstations. VNA web 80/443 and REST 8080/8443.',
    source: 'Fujifilm Synapse load balancer deployment guides (Loadbalancer.org, Edgenexus)',
    zpa: [
      { name: 'Synapse PACS web', placeholder: '{customer Synapse server}', tcp: '80, 443', udp: '', on: true },
      { name: 'Synapse Mobility', placeholder: '{customer Synapse Mobility host}', tcp: '8080, 8443', udp: '', on: true },
      { name: 'Synapse DICOM', placeholder: '{customer Synapse DICOM server}', tcp: '104', udp: '', on: false },
      { name: 'Synapse VNA', placeholder: '{customer Synapse VNA host}', tcp: '80, 443, 8080, 8443', udp: '', on: false }
    ],
    zdx: [
      { name: 'Synapse Mobility', placeholder: '{customer Synapse Mobility host}', port: 8443, path: '/', on: true },
      { name: 'Synapse PACS web', placeholder: '{customer Synapse server}', port: 443, path: '/', on: false }
    ] },
  { id: 'VISAGE', name: 'Visage 7 PACS', category: 'IMAGING', verticals: [H], collection: 'Visage PACS',
    description: 'Visage 7 thin client and web viewer: 80, 443 and 6100 to the Visage server (sites differ; confirm). The desktop client is downloaded from the server over HTTPS. Customers on Visage-hosted cloud (*.cloud.visageimaging.com) use ZIA instead.',
    source: 'Visage 7 Client Online Help; Visage customer IT port lists',
    zpa: [
      { name: 'Visage 7 server', placeholder: '{customer Visage server}', tcp: '80, 443, 6100', udp: '', on: true },
      { name: 'Visage DICOM', placeholder: '{customer Visage DICOM node}', tcp: '104, 11112', udp: '', on: false }
    ],
    zdx: [{ name: 'Visage 7', placeholder: '{customer Visage server}', port: 443, path: '/', on: true }] },
  { id: 'IMPRIVATA', name: 'Imprivata OneSign', category: 'CLINICAL_ACCESS', verticals: [H],
    description: 'OneSign agents talk to the appliances on HTTPS 443. Keep it on ZPA, not bypassed, so single sign-on and access policy can be shown.',
    source: 'Imprivata OneSign communication ports',
    zpa: [{ name: 'Imprivata OneSign', placeholder: '{customer Imprivata appliances}', tcp: '443', udp: '', on: true }],
    zdx: [{ name: 'Imprivata OneSign', placeholder: '{customer Imprivata appliance VIP}', port: 443, path: '/', on: true }] },
  { id: 'HC_SAAS', name: 'Clinical reference (UpToDate, Doximity, Epic UserWeb)', category: 'SAAS', verticals: [H],
    description: 'Internet SaaS clinicians use every day: ZDX only.',
    zdx: [
      { name: 'UpToDate', fill: 'www.uptodate.com', port: 443, path: '/', on: true },
      { name: 'Doximity', fill: 'www.doximity.com', port: 443, path: '/', on: true },
      { name: 'Epic UserWeb', fill: 'userweb.epic.com', port: 443, path: '/', on: false }
    ] },

  // ---------------- Virtual desktops (every vertical)
  { id: 'CITRIX', name: 'Citrix Virtual Apps and Desktops', category: 'VDI', verticals: [ALL], collection: 'Citrix',
    description: 'StoreFront / Gateway on 443, ICA 1494 and session reliability (CGP) 2598; EDT uses UDP 1494, 2598 and 443.',
    source: 'Citrix default network ports',
    zpa: [
      { name: 'Citrix StoreFront', placeholder: '{customer StoreFront host}', tcp: '443', udp: '', on: true },
      { name: 'Citrix sessions', placeholder: '{customer Citrix VDA servers}', tcp: '1494, 2598', udp: '1494, 2598', on: true }
    ],
    zdx: [{ name: 'Citrix StoreFront', placeholder: '{customer StoreFront host}', port: 443, path: '/', on: true }] },
  { id: 'HORIZON', name: 'Omnissa (VMware) Horizon', category: 'VDI', verticals: [ALL], collection: 'Horizon',
    description: 'Connection Server 443; direct to the agent: Blast 22443 (TCP/UDP), PCoIP 4172 (TCP/UDP), RDP 3389. With ZPA, connect straight to the agents and skip the Unified Access Gateway.',
    source: 'Omnissa: Network ports in Horizon 8',
    zpa: [
      { name: 'Horizon Connection Server', placeholder: '{customer Horizon Connection Server}', tcp: '443', udp: '', on: true },
      { name: 'Horizon desktops', placeholder: '{customer Horizon desktop pool subnet}', tcp: '22443, 4172, 3389', udp: '22443, 4172', on: true }
    ],
    zdx: [{ name: 'Horizon Connection Server', placeholder: '{customer Horizon Connection Server}', port: 443, path: '/', on: true }] },

  // ---------------- ERP and databases (every vertical)
  { id: 'SAP', name: 'SAP GUI and Fiori', category: 'ERP', verticals: [ALL], collection: 'SAP',
    description: 'SAP GUI: dispatcher 32NN, gateway 33NN, message server 36NN (NN = instance number, 00 shown); Fiori / Web GUI over ICM HTTPS 443NN. Change 00 to the customer\'s instance numbers.',
    source: 'SAP Help: TCP/IP ports of SAP products',
    zpa: [
      { name: 'SAP GUI', placeholder: '{customer SAP application servers}', tcp: '3200, 3300, 3600', udp: '', on: true },
      { name: 'SAP Fiori', placeholder: '{customer SAP Fiori host}', tcp: '443, 44300', udp: '', on: false }
    ],
    zdx: [{ name: 'SAP Fiori', placeholder: '{customer SAP Fiori host}', port: 443, path: '/', on: true }] },
  { id: 'ORACLE_EBS', name: 'Oracle E-Business Suite', category: 'ERP', verticals: [ALL],
    description: 'Oracle HTTP Server 8000 (HTTP) / 4443 (HTTPS); Forms in servlet mode uses the same port.',
    source: 'Oracle E-Business Suite 12.2 port appendix',
    zpa: [{ name: 'Oracle EBS', placeholder: '{customer EBS web entry host}', tcp: '8000, 4443', udp: '', on: true }],
    zdx: [{ name: 'Oracle EBS', placeholder: '{customer EBS web entry host}', port: 4443, path: '/', on: true }] },
  { id: 'MSSQL', name: 'Microsoft SQL Server', category: 'DATA', verticals: [ALL],
    description: 'Default instance TCP 1433; SQL Browser UDP 1434 for named instances (pin named instances to fixed ports); Reporting Services 80/443.',
    source: 'Microsoft Learn: configure the Windows Firewall for SQL Server',
    zpa: [{ name: 'SQL Server', placeholder: '{customer SQL servers}', tcp: '1433', udp: '1434', on: true }] },

  // ---------------- Finance
  { id: 'CORE_BANKING', name: 'Core banking (Jack Henry, Fiserv, FIS)', category: 'BANKING', verticals: [F],
    description: 'Core banking clients are usually HTTPS to the core or a hosted private circuit; vendors do not publish client ports. Confirm them with the customer.',
    zpa: [{ name: 'Core banking', placeholder: '{customer core banking host}', tcp: '443', udp: '', on: true }],
    zdx: [{ name: 'Core banking', placeholder: '{customer core banking host}', port: 443, path: '/', on: true }] },
  { id: 'BLOOMBERG', name: 'Bloomberg Terminal', category: 'BANKING', verticals: [F],
    description: 'Bloomberg runs on its own internet IP ranges (TCP 8194–8198, 8209–8220, 8290–8294; UDP 48129–48137): forward it through ZIA. ZDX probes its public site.',
    source: 'Bloomberg Network Connectivity Guide',
    zdx: [{ name: 'Bloomberg', fill: 'www.bloomberg.com', port: 443, path: '/', on: true }] },
  { id: 'FIN_SAAS', name: 'Business SaaS (Workday, DocuSign, Salesforce)', category: 'SAAS', verticals: [F, ALL],
    zdx: [
      { name: 'Workday', fill: 'www.myworkday.com', port: 443, path: '/', on: true },
      { name: 'DocuSign', fill: 'app.docusign.com', port: 443, path: '/', on: true },
      { name: 'Salesforce', fill: 'login.salesforce.com', port: 443, path: '/', on: false }
    ] },

  // ---------------- Education
  { id: 'BANNER', name: 'Ellucian Banner 9', category: 'EDU', verticals: [E], collection: 'Banner',
    description: 'Banner 9 Admin Pages and Self-Service in a browser, usually behind a load balancer on 443 (Tomcat 8443 direct).',
    source: 'Ellucian Banner 9 Admin Pages deployment notes',
    zpa: [{ name: 'Banner Admin Pages', placeholder: '{customer Banner admin host}', tcp: '443, 8443', udp: '', on: true }],
    zdx: [{ name: 'Banner Admin Pages', placeholder: '{customer Banner admin host}', port: 443, path: '/', on: true }] },
  { id: 'SIS', name: 'Student information system (self-hosted)', category: 'EDU', verticals: [E],
    description: 'Self-hosted SIS such as PowerSchool on-premises: browser HTTPS 443. Hosted PowerSchool is SaaS (ZIA).',
    zpa: [{ name: 'Student information system', placeholder: '{customer SIS host}', tcp: '443', udp: '', on: true }],
    zdx: [{ name: 'Student information system', placeholder: '{customer SIS host}', port: 443, path: '/', on: true }] },
  { id: 'EDU_SAAS', name: 'Learning platforms (Canvas, Google Classroom)', category: 'SAAS', verticals: [E],
    zdx: [
      { name: 'Canvas', fill: 'canvas.instructure.com', port: 443, path: '/', on: true },
      { name: 'Google Classroom', fill: 'classroom.google.com', port: 443, path: '/', on: true }
    ] },

  // ---------------- Public sector
  { id: 'ARCGIS', name: 'ArcGIS Enterprise', category: 'GOV', verticals: [G], collection: 'ArcGIS',
    description: 'Web Adaptor 443; Portal for ArcGIS 7443; ArcGIS Server 6443.',
    source: 'Esri: ArcGIS Enterprise ports',
    zpa: [
      { name: 'ArcGIS Web Adaptor', placeholder: '{customer ArcGIS web host}', tcp: '443', udp: '', on: true },
      { name: 'ArcGIS Portal and Server', placeholder: '{customer ArcGIS servers}', tcp: '6443, 7443', udp: '', on: false }
    ],
    zdx: [{ name: 'ArcGIS Portal', placeholder: '{customer ArcGIS web host}', port: 443, path: '/portal/', on: true }] },
  { id: 'CASE_MGMT', name: 'Case management', category: 'GOV', verticals: [G],
    zpa: [{ name: 'Case management', placeholder: '{customer case management host}', tcp: '443', udp: '', on: true }],
    zdx: [{ name: 'Case management', placeholder: '{customer case management host}', port: 443, path: '/', on: true }] },
  { id: 'GOV_SAAS', name: 'Government sites (Login.gov, SAM.gov, USAJOBS)', category: 'SAAS', verticals: [G],
    zdx: [
      { name: 'Login.gov', fill: 'secure.login.gov', port: 443, path: '/', on: true },
      { name: 'SAM.gov', fill: 'sam.gov', port: 443, path: '/', on: true },
      { name: 'USAJOBS', fill: 'www.usajobs.gov', port: 443, path: '/', on: false }
    ] }
];

/** The catalog for one vertical: its apps first (by category), then the rest. Placeholders keep {domain} for the UI. */
function catalog(vertical) {
  const v = String(vertical || '').toUpperCase();
  const mine = (a) => a.verticals.includes(v) || (a.verticals.includes(ALL) && a.category !== 'SAAS') || (v === 'GENERAL' && a.verticals.includes(ALL));
  return {
    categories: CATEGORIES,
    apps: APPS.map(a => ({ ...a, mine: mine(a), zpa: a.zpa || [], zdx: a.zdx || [] }))
  };
}

module.exports = { CATEGORIES, APPS, catalog };
