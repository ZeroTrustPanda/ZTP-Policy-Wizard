# 🐼 ZeroTrustPanda — ZTP Policy Wizard v1.8.2

Automated Zscaler Internet Access (ZIA) and Zscaler Client Connector (ZCC) policy configuration for healthcare and enterprise environments.

## What This Does

Deploy a complete Zscaler security policy stack in minutes instead of hours. Select a security tier, choose a compliance framework, review the rules, and apply — the wizard handles the API calls, rule ordering, and activation.

**Supported policy types:**
- **URL Filtering** — Block legal liability, security risk, bandwidth/productivity categories
- **Cloud Firewall** — Network application controls (QUIC block, web/NTP allow, P2P/tunnel block, default-deny)
- **SSL/TLS Inspection** — Decrypt/bypass rules with health, finance, government exemptions
- **Cloud Sandbox** — Quarantine Office/PDF, scan executables, AI Instant Verdict
- **DNS Security** — Block malicious DNS categories and 21+ DNS tunnel types
- **File Type Control** — Block database uploads, password-protected archives, executables, scripts
- **Cloud App Control** — Restrict DoH, file sharing, webmail, streaming, IM, AI/ML
- **Data Loss Prevention** — Dictionary-based DLP with auto-created custom engines per compliance framework

**Additional modules:**
- **Policy Catalog** — Browse all 1,098 rules across 4 tiers × 9 frameworks without connecting
- **Bulk Rule Manager** — Delete rules, DLP engines, and custom dictionaries across all categories
- **Mobile Admin Portal** — Configure ZCC forwarding profiles and app profiles via PATCH/POST edit
- **Digital Experience (ZDX)** — Set up ZDX Web and CloudPath probes from the Zscaler POV best practice guide, and manage existing apps and probes

## Allow / Block Step (v1.6.0)

After **Customize**, the wizard lists each policy type (URL Filtering, Cloud Firewall, DNS Security, File Type Control, Cloud App Control, DLP) with **Tier default / Allow all / Block all**. Expand a type to flip individual rules. Rules set to Allow that the tier would restrict are flagged as WEAKENED in Review and the dry run, and logged as `ACTION_OVERRIDES` at apply time. `ZTP-Allow-Web` and `ZTP-Allow-NTP` are locked so baseline internet access can't be blocked by accident.

## Mobile Admin: Create Forwarding + App Profile (v1.7.0)

Mobile Admin → **Create from template** builds the common Mobile Admin settings for Zscaler Client Connector, following the **Zscaler POV best practice guide**. It walks through the same flow as the ZIA wizard, with the forwarding profile first because the app profile has to point at it:

**Platform → Forwarding Profile → App Profile → Customize → Review → Dry Run → Apply**

**Forwarding Profile step**: a forwarding profile tells Client Connector how to send traffic on each network type (trusted network, VPN, off-network) to ZIA and ZPA. Create a new one (the default on both platforms) or pick an existing one. The *Zscaler POV Best Practice* forwarding template sets 8 things beyond a portal-default forwarding profile:

| Setting | Value | Portal default |
|---|---|---|
| ZIA action on every network (On-Trusted, VPN-Trusted, Off-Trusted, Split VPN-Trusted) | Tunnel | Tunnel with Local Proxy |
| Redirect web traffic to Client Connector listening proxy | On | Off |
| Use Z-Tunnel 2.0 for proxied web traffic | On | Off |
| Drop IPv6 traffic (incl. IPv6-only networks) | On | Off |
| Latency-based ZEN selection | On | Off |
| System proxy automatic configuration script | Off | On |
| ZPA on VPN-Trusted networks | Tunnel | None |
| ZPA latency-based server selection | On | Off |

Apply creates the forwarding profile first (`POST /webForwardingProfile/edit` with `id: "-1"`), verifies it, then creates the app profile linked to it. If the app profile fails, the new forwarding profile is deleted again. In edit mode, forwarding profiles can be deleted; the server refuses while any Windows or macOS app profile still uses one.

App profile steps (v1.6.0 Windows, v1.6.1 macOS):

1. **App Profile**: an app profile holds the Client Connector settings for the devices it applies to. Choose *Zscaler POV Best Practice* (12 settings on Windows, 16 on macOS, from the POV best practice guide) or *Portal Default* (blank).
2. **Customize**: name, description, forwarding profile, enable-after-create (off by default), and a toggle for each template setting.
3. **Review**: every setting with its new value, the portal default, and what it does.
4. **Dry Run**: read-only checks against the tenant (name unique, forwarding profile exists, bypass apps exist, placement above Default) and the resulting rule order.
5. **Apply**: creates the profile with `PUT /zcc/papi/public/v1/web/policy/edit`, reads it back and verifies each setting. Logged as `ZCC_DRY_RUN` / `ZCC_APPLY`.

macOS POV Best Practice: SSL certificate, block iCloud Private Relay, fail-close on tunnel exit off, recommended PAC URL, domain inclusions `*`, prioritize DNS exclusions off, flow-based tunnel, reconnect on wake, Teams/Zoom/W365-AVD IP bypass, notification framework, switch focus, re-enable Internet Security after 60 min, Modern UI, local packet capture, automatic packet capture extras off, all users.

**Manual step:** the public API ignores the macOS *Modern UI* setting on create, update and PATCH, so the wizard marks it MANUAL and reminds you to set it in the portal after creation.

The create body is the full payload the Mobile Admin portal sends (`server/zcc-windows-profile-template.json`, `server/zcc-mac-profile-template.json`); minimal bodies are rejected by ZCC with HTTP 200 + `success:"false"`. Template settings live in `server/zcc-app-profile-templates.js`.

## Digital Experience (ZDX) (v1.8.0)

Digital Experience → **Set up probes** turns on ZDX probes following the **Zscaler POV best practice guide**, with the same flow as the other wizards: **Template → Applications & Probes → Review → Dry Run → Apply**.

- A **Web probe** loads an app's page from each user's device and measures availability and page fetch time. A **CloudPath probe** traces the network path hop by hop (device, Wi-Fi, ISP, Zscaler, app).
- **Zscaler POV Best Practice** template: *Microsoft Login* (Zscaler predefined app, login.microsoftonline.com) and *zscaler.com* (custom app), each with a Web and a CloudPath probe, for all users.
- **Predefined apps** (Microsoft 365, Teams, SharePoint, OneDrive, Zoom, Okta, Box, Salesforce, ServiceNow, Webex): Zscaler maintains their probes. Apps not yet set up in the tenant are created first; some need the customer's tenant prefix (e.g. `contoso` for contoso.sharepoint.com).
- **Custom apps**: any URL (EHR, PACS viewer, intranet). Each gets a Web probe and, by default, a CloudPath probe to the same host; probe interval 5–30 min, CloudPath protocol Adaptive / ICMP / TCP / UDP.
- **Dry run** shows tenant state and the exact ordered steps; apps already set up are skipped or only the missing probes are turned on.
- **Apply** creates and turns on everything in the order ZDX requires, reads it back and verifies each app and probe, and removes a half-created custom app if any step fails. Logged as `ZDX_DRY_RUN` / `ZDX_APPLY`.
- **Manage apps & probes** lists every app and probe in the tenant; turn them on or off, delete custom apps (probes first) and custom probes. Zscaler predefined apps can only be turned off.

The API client needs the ZDX scope. ZDX refuses some hosts (for example `www.zscaler.com`); the error appears in the Apply results and nothing is left behind.

## Security Tiers

| Tier | Description |
|------|-------------|
| 🔒 **Strict** | Maximum security. Blocks productivity/streaming. Full SSL inspection. Default-deny firewall. |
| ⚖️ **Balanced** | Best-practice security with reasonable access. Caution pages for streaming/social. SSL with exemptions. |
| 🔓 **Permissive** | Minimal restrictions. Core security only. No SSL inspection. No bandwidth blocking. |
| 🏥 **ZTH Ebook** | Zero Trust Hospital policy. Healthcare-optimized with PHI protection and TLS 1.2 minimum. |

## Compliance Frameworks

HIPAA, HITRUST CSF, NIST 800-53, NIST 800-171, PCI-DSS, CJIS, SOX, FERPA, GDPR

Each framework maps specific controls to the generated rules. Compliance evidence is available in the Review step.

## Quick Start

### Prerequisites
- Node.js 18+
- Zscaler OneAPI OAuth2 credentials (client ID + secret from ZIdentity)

### Install & Run

```bash
npm install
npm start
```

Open `http://localhost:3000` in your browser.

### Windows Service Install (optional)

```bash
npm run install-service
```

Or double-click `install.bat`.

## Authentication

The wizard uses OneAPI OAuth2 exclusively. You need:

1. A Zscaler tenant with API access enabled
2. An API client configured in **ZIdentity → Integration → API Clients**
3. The client must have **Read/Write** scope for:
   - ZIA (URL Filtering, Firewall, SSL, Sandbox, DNS, File Type, Cloud Apps, DLP)
   - ZCC / Client Connector (for Mobile Admin Portal)

Enter your vanity domain (e.g., `zth`), cloud (`production`), client ID, and client secret on the Connect page.

## Architecture

```
public/index.html     — Single-page React app (Babel standalone, dark theme)
server/index.js       — Express server, API routes, session management
server/templates.js   — Policy template generation (all tiers × frameworks)
server/zia-client.js  — ZIA API client (OneAPI OAuth2, rate limiting, retry)
server/zcc-client.js  — ZCC API client (PATCH app profiles, POST edit forwarding)
server/zcc-templates.js — ZCC best-practice templates
server/audit-logger.js — Structured audit logging (JSONL + CSV export)
```

### Multi-User Sessions

- Up to 50 concurrent sessions (1-hour TTL each)
- Session cleanup runs every 5 minutes
- Each browser tab gets its own session UUID
- Multiple admins can work against different tenants simultaneously

### DLP Module

The DLP module uses a **dictionary-first** approach:

1. Each DLP rule definition maps to predefined dictionaries (universal across all tenants)
2. At apply time, dictionaries are resolved by exact internal name (SSN, CREDIT_CARD, MEDICAL, etc.)
3. A custom DLP engine is auto-created with `engineExpression` built from dictionary IDs
4. The DLP rule references the custom engine for content inspection
5. Text-based file types only (Word, Excel, PowerPoint, RTF, PDF, Text, CSV, HTML) to avoid OCR errors

14 DLP rule definitions across 9 compliance frameworks, producing 3–9 rules per deployment depending on tier and framework.

## API Endpoints

### No Auth Required
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/version` | Version info, active sessions |
| GET | `/api/catalog` | Full policy catalog (all tiers × frameworks) |
| GET | `/api/catalog/:tier?framework=X` | Single tier preview |

### Auth Required
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/auth/oneapi` | Authenticate via OneAPI OAuth2 |
| POST | `/api/templates/generate` | Generate policy template |
| POST | `/api/plan/dryrun` | Dry run against live tenant |
| POST | `/api/apply` | Apply template to tenant |
| GET | `/api/state/all-rules` | Fetch all rules (URL, FW, SSL, Sandbox, DNS, FTC, DLP, DLP Engines, DLP Dictionaries) |
| POST | `/api/bulk-delete` | Delete selected rules across all categories |
| GET | `/api/zcc/profiles` | Fetch ZCC forwarding + app profiles |
| POST | `/api/zcc/apply` | Apply ZCC changes (PATCH app, POST edit forwarding) |
| GET | `/api/zdx/catalog` | ZDX templates and predefined apps with tenant state |
| POST | `/api/zdx/dryrun` | Read-only ZDX plan: checks and ordered steps |
| POST | `/api/zdx/apply` | Create/turn on ZDX apps and probes, verify, roll back failures |
| GET | `/api/zdx/overview` | ZDX apps with their probes |
| POST | `/api/zdx/apps/:key/:action` | Turn a ZDX app on or off (`activate` / `deactivate`) |
| POST | `/api/zdx/apps/:key/monitors/:mid/:action` | Turn a probe on or off |
| DELETE | `/api/zdx/apps/:id?confirmName=` | Delete a custom ZDX app and its probes |
| DELETE | `/api/zdx/apps/:key/monitors/:mid?confirmName=` | Delete a custom probe |
| GET | `/api/zcc/fwd-templates` | Forwarding profile template catalog |
| POST | `/api/zcc/forwarding-profiles/dryrun` | Read-only plan for a new forwarding profile |
| POST | `/api/zcc/forwarding-profiles` | Create forwarding profile, read back and verify |
| DELETE | `/api/zcc/forwarding-profiles/:id?confirmName=` | Delete a forwarding profile (refused while in use) |
| GET | `/api/zcc/templates/:platform` | App profile template catalog (`windows` / `macos`) |
| GET | `/api/zcc/app-profiles/:platform` | List app profiles for a platform |
| POST | `/api/zcc/app-profiles/:platform/dryrun` | Read-only plan and checks for a new app profile |
| POST | `/api/zcc/app-profiles/:platform` | Create app profile (and, with `newForwardingProfile`, its forwarding profile first), read back and verify |
| DELETE | `/api/zcc/app-profiles/:id?confirmName=&platform=` | Delete an app profile (name must match) |
| GET | `/api/diag/dlp` | DLP diagnostic (engines, dictionaries, rules) |

## Version History

| Version | Changes |
|---------|---------|
| **1.8.2** | Fix: ZDX wizard failed on brand-new ZDX tenants ("No Custom Apps Collection in this tenant"); the wizard now creates the collection as a first setup step |
| **1.8.1** | Fix: macOS app profile (and its forwarding profile) failed to create on any tenant other than ZTH; the tenant-specific notification template 2221 was removed from the macOS POV Best Practice template (now 16 settings) |
| **1.8.0** | New Digital Experience (ZDX) module: POV best practice probes (Microsoft Login + zscaler.com), predefined and custom apps, dry run, apply with verification and rollback, Manage screen |
| **1.7.1** | Mobile Admin wording: templates renamed *Zscaler POV Best Practice*, steps explain what forwarding and app profiles are; macOS defaults to a new forwarding profile; tenant-specific notification template flagged REVIEW |
| **1.7.0** | Mobile Admin: forwarding profile step before the app profile (POV best practice template, 8 settings), created first and linked, with rollback; forwarding profile delete with in-use guard |
| **1.6.1** | Mobile Admin: macOS app profile create from the POV best practice template (platform picker, Modern UI as a manual step), macOS profiles listed for delete |
| **1.6.0** | Mobile Admin: Windows app profile create from the POV best practice template; Allow / Block step: pick Allow or Block per policy type (URL, Firewall, DNS, File Type, Cloud App Control, DLP), flip individual rules, weakening warnings in Review/Dry Run and audit log |
| **1.5.2** | DLP rules shown in Review step, wizard state resets between runs for multi-deploy sessions, DLP engines/dictionaries in Bulk Rule Manager |
| **1.5.1** | Multi-user sessions (50 concurrent, 1hr TTL), Policy Catalog browser, ZCC rewrite to PATCH/POST edit workflow |
| **1.5.0** | DLP module (dictionary-first, 14 rule defs, 9 compliance frameworks, custom engine creation) |
| **1.4.0** | UI restructure, ZeroTrustPanda branding, firewall nwApplications fix, About page |
| **1.3.0** | Mobile Admin Portal (ZCC), OneAPI-only auth, bulk rule manager |
| **1.2.x** | Sandbox, DNS Security, File Type Control, Cloud App Control |
| **1.0–1.1** | URL Filtering, Firewall, SSL Inspection, Malware Protection |

## License

Internal use. Not for redistribution without permission.
