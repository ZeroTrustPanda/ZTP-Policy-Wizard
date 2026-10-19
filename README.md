# 🐼 ZeroTrustPanda — ZTP Policy Wizard v2.1.0

Proof-of-value automation for Zscaler SEs: Zscaler Internet Access (ZIA), Zscaler Client Connector (ZCC), Zscaler Private Access (ZPA) and Zscaler Digital Experience (ZDX), all with one set of OneAPI (ZIdentity) client credentials.

## ⬇️ Standalone edition (this branch)

No Node.js, no npm, nothing to install. Click your download, unzip it, and double-click `ZTP-Wizard`:

| Computer | Download (click to download) |
|---|---|
| **Mac with Apple silicon (M1–M4)** | [**ZTP-Wizard-2.1.0-macos-arm64.zip**](https://github.com/ZeroTrustPanda/ZTP-Policy-Wizard/raw/standalone/standalone/release/ZTP-Wizard-2.1.0-macos-arm64.zip) |
| Windows 10/11 (64-bit) | [ZTP-Wizard-2.1.0-windows-x64.zip](https://github.com/ZeroTrustPanda/ZTP-Policy-Wizard/raw/standalone/standalone/release/ZTP-Wizard-2.1.0-windows-x64.zip) |
| Intel Mac | [ZTP-Wizard-2.1.0-macos-x64.zip](https://github.com/ZeroTrustPanda/ZTP-Policy-Wizard/raw/standalone/standalone/release/ZTP-Wizard-2.1.0-macos-x64.zip) |

The wizard starts on `http://127.0.0.1:3000` (or the next free port), opens your browser, and keeps your API credentials on your computer. Logs go to `ZTP-Wizard/logs` in your home folder.

**The builds are not code-signed yet**, so the first launch needs one extra click:
- **Mac:** right-click `ZTP-Wizard` → *Open* → *Open*. If macOS still refuses, run `xattr -d com.apple.quarantine ZTP-Wizard` in the unzipped folder. If it then reports "killed", also run `codesign --force --sign - ZTP-Wizard`.
- **Windows:** SmartScreen → *More info* → *Run anyway*.

These are the same features as the v2.1.0 server version on `main`. The UI is compiled ahead of time, with React and fonts built in, so it works without reaching any CDN; only the Zscaler API calls need the network.

Release notes: [v2.1.0](docs/release-notes/v2.1.0.md) · [v2.0.0](https://github.com/ZeroTrustPanda/ZTP-Policy-Wizard/releases/tag/v2.0.0) · Full history: [CHANGELOG.md](CHANGELOG.md)

## What's new in 2.1

More policies are built into the existing templates, so each one can be shown during a POV:
- **ZIA:** the SSL rule that inspects all remaining traffic is always last, below *Zscaler Recommended Exemptions*, and requires TLS 1.2. DNS over HTTPS is inspected (risky DoH lookups blocked), DNS is answered by the Zscaler Trusted Resolver even when a device uses 8.8.8.8, and SSH / RDP / FTP to and from high-risk countries is dropped.
- **ZPA:** timeout (re-authentication), AppProtection inspection and browser isolation policies for the application segments, plus optional Privileged Remote Access RDP / SSH consoles.
- **ZCC:** tamper protection passwords (logout, exit, uninstall, turning off ZIA / ZPA / ZDX), shown in the summary report.
- **ZDX:** Teams, Zoom and Webex in the POV template.

See [CHANGELOG.md](CHANGELOG.md) for details.

## What's new in 2.0

The sidebar runs in POV order: **Zscaler Client Connector → Zscaler Internet Access → Zscaler Private Access → Zscaler Digital Experience**, plus a **Summary Report**. A **global prefix** set once after signing in names every object the wizard creates in ZIA, ZCC and ZPA. Running again with the same prefix **updates** those objects instead of creating duplicates.

**Every change goes through a dry run first.** The server refuses an apply that doesn't match a dry run of exactly the same choices. The dry run and the apply run the same code, so the preview lists each object as **Create**, **Update** or **No change**, and the apply does exactly that. After an apply, ZIA changes are activated automatically. One failed object never stops the rest: each failure is listed with its reason, and anything that depends on it is skipped.

### Zscaler Internet Access: Policy Wizard
1. **Scope:** pick what the POV covers.
   - Inline DLP, either Monitor or Block.
   - Endpoint Data Protection.
   - Cloud Sandbox, either Standard or Advanced.
   - AI Prompt Capture.
   - The core areas: URL Filtering, Cloud App Control, File Type Control, ATP, Cloud Firewall, DNS Security and SSL Inspection.
   - Licensing is read from the tenant. Features the tenant isn't licensed for are greyed out ("Not licensed on this tenant"). When the licence can't be confirmed, the feature stays available with a warning.
   - The Endpoint DLP prerequisite in Mobile Admin is checked and reported.
2. **Baseline Framework:** pick one baseline.
   - The compliance frameworks: HIPAA, HITRUST, NIST 800-53, NIST 800-171, PCI DSS, CJIS, SOX, FERPA, GDPR.
   - Or a non-mapped level: Strict, Balanced, Permissive, or Zero Trust Hospital.
   - Each definition is a JSON file in `server/frameworks/`, with sources cited for each control and the research date.
3. **Rules:** every rule and setting for the scope, grouped by category.
   - Select all / Deselect all per category and for the whole page.
   - Allow all / Block all per category, with per-rule Allow / Block. The last action wins.
   - Isolate for URL rules, with the isolation profile and SSL certificate pickers from 1.9.
   - Choices survive Back / Next.
   - *Save selections* / *Load selections* reuse a configuration with another customer.
4. **Dry run → Apply and activate → Results**, then the summary report.

New policy areas:
- **Inline DLP Monitor:** Allow-only rules on Zscaler's predefined engines, e.g. the HIPAA and PCI engines.
- **Inline DLP Block:** custom dictionaries (ICD-10, MBI, MRN, card track data, CUI markings and others, each citing its source) and engines, reusing Zscaler's predefined dictionaries where they exist. The rules block by default, and each can be switched to Allow.
- **Endpoint DLP:** USB, personal cloud storage and printing, in Monitor mode.
- **Sandbox Standard:** .exe and .dll, Allow and Scan.
- **Sandbox Advanced:** AI Instant Verdict on every rule. One rule per file-type group; high-risk types are quarantined and lower-risk types are allowed and scanned. The groups use only file types Cloud Sandbox accepts (probed live). DMG needs the Sandbox macOS subscription and is left out with a note.
- **AI Prompt Capture:** 14 GenAI apps, all on by default and each switchable.
- **UCaaS:** Zoom, GoTo, RingCentral, Webex and Talkdesk (Advanced Settings → Unified communications as a service) are enabled on every Zscaler Internet Access run and shown as their own group on the rule review page.
- **Granular Cloud App Control:** app-specific rules sit above the category-wide rules and show what URL filtering can't:
  - Google Drive, Dropbox and Box: view-only (no upload).
  - Facebook and X: view but no posting.
  - LinkedIn: read-only (no posting, commenting, sharing or uploading).
  - ChatGPT, Gemini and Copilot: allowed, with prompts captured, but no file uploads.
  - Slack: chat but no file uploads.
- **Isolate Miscellaneous / Unknown:** a URL Filtering rule opens these categories in Cloud Browser Isolation with the tenant's profile. With no profile it falls back to Caution and says so.
- **ATP defaults.**

### ZCC (Mobile Admin)
- Every setting is a switch, for Windows and macOS.
- **Automatically Attempt ZPA Reauthentication** is on by default, set per app profile. It is stored in `policyExtension` (verified live on both platforms).
- **Forwarding profile IPv6:** two separate switches, *Drop IPv6 Traffic (dual-stack networks)* and *Drop IPv6 Traffic in IPv6-only networks*.
- **Predefined IP App Bypasses:** the list is read live from the tenant and shown directly under the *Bypass IP-based Applications* switch, behind a warning. All apps are checked by default.
- **VPN Gateway Bypasses, IP Inclusions / Exclusions, DNS Inclusions / Exclusions:** each shows its description and the current default. Entries are validated inline. IP lists take an IP address or CIDR only: ZCC rejects the whole profile if an IP list holds a domain name.
- A profile with the same name is updated in place, and the dry run says what will change.
- The ZCC and ZDX APIs allow about **100 calls per hour**. The wizard caches repeated reads and reports a rate-limit message instead of waiting.

### ZPA wizard
The wizard creates, in order:
1. `<prefix>-appconnector-group`: Connector certificate, San Jose, CA. Change the location in the portal afterwards; the wizard reminds you in a banner and in the report.
2. `<prefix>-provisioning-key`: App Connector, max usage 5. The key is shown masked with reveal and copy, and it is never logged.
3. `<prefix>-segment-group`
4. `<prefix>-server-group`: Dynamic Server Discovery on.
5. `<prefix>-app-segment`: one mixed field for domains and IPs.
   - TCP and UDP ports 1-52 and 54-65535.
   - Closer to User, Pingable on, CNAME on, and the other §5.2 defaults. Each setting can be changed.

**Bulk upload (optional):** switch on *Bulk upload application segments from a CSV* to create one segment per application instead of the wildcard segment. Steps 1–4 are unchanged.
- **CSV columns:** `Application Name, Destinations, Ports`. Put several values in one cell, separated by `;`. Ports are TCP unless written as `udp:53`. *Download CSV template* gives an example file.
- **Review:** every application is listed and gets its own *Settings* button, which overrides the shared segment settings for that app only.
- **Validation:** problems are named by row: bad hosts or ports, duplicate names, the same destination in two apps on overlapping ports, and Continuous health checks on subnet destinations. ZPA refuses the last two.
- **Naming:** segments are named `<prefix>-<application name>`, so the ZPA Bulk Manager lists and removes them with the rest.

### Bulk managers and report
- **ZPA Bulk Manager:** lists the wizard's objects by prefix and deletes them in dependency order (application segment → server group → segment group → provisioning key → App Connector Group), after a preview.
- **ZDX Bulk Manager:** custom applications (with their probes) and collections, after a preview.
- **Summary Report:** Markdown and printable HTML (save as PDF). It lists:
  - the scope and baseline
  - every object by product (Created / Updated / Unchanged / Failed / Skipped)
  - the rule decisions, warnings and manual follow-ups
  - the ZPA provisioning key, with the file clearly marked as sensitive

All new user-facing text is in `server/v2/copy.js`.

The 1.9 framework-file flow (load a saved framework, or capture a tenant's policies) is still available under ZIA › Framework Files (1.9).

## 1.9 flows (still available)

### Rules Step (v1.6.0, extended in v1.9.0)

After **Customize**, the wizard lists every policy type (URL Filtering, Cloud Firewall, SSL Inspection, Sandbox, DNS Security, File Type Control, Cloud App Control, DLP).

- **On/off switch for every rule** (v1.9.0), plus *All on / All off* per policy type. Switched-off rules are not created.
- **Tier default / Allow all / Block all** where the policy type supports it, with per-rule overrides. Rules set to Allow that the tier would restrict are flagged as WEAKENED in Review and the dry run, and logged as `ACTION_OVERRIDES` at apply time. `ZTP-Allow-Web` and `ZTP-Allow-NTP` are locked so baseline internet access can't be blocked by accident.
- **Isolate** (v1.9.0): any URL rule can be set to Isolate. It opens those categories in Cloud Browser Isolation with the profile chosen on Customize (HTTP/HTTPS, GET + CONNECT, browser types copied from an existing Isolate rule).

## Isolation Profile, Certificate and Frameworks (v1.9.0)

- **Isolation profile** (Customize): the tenant's *Default Isolation Profile* unless you pick another; **↻ Refresh** picks up profiles created in the Isolation portal since the page loaded (the ZIA API can only read profiles). Used by URL rules set to Isolate and by Sandbox *Quarantine & Isolate*.
- **SSL interception certificate** (Customize): choose the certificate the Inspect rules this run creates sign with, instead of the Zscaler default. Certificates come from `GET /intermediateCaCertificate/readyToUse`, plus any already used by SSL rules, or enter an ID by hand.
- **SSL Certificate Manager** (ZIA › SSL Certificate Manager): every SSL rule and the certificate it uses. Select Inspect rules (for example "rules on the default certificate"), preview, then move them to another certificate (or back) and activate in one step.
- **Frameworks**: on the Rules step, **Save framework** downloads a `.ztp-framework.json` with tier, compliance, modules, rule switches, Allow / Block / Isolate choices, isolation profile and certificate (by name). On the Security Tier step, **Load a saved framework** applies it in any tenant, and **Capture this tenant's policies** reads URL Filtering (with custom categories), Cloud Firewall, SSL, Sandbox, DNS and File Type rules into a framework (read-only) that can be saved and applied elsewhere. User / group / location scoping, firewall network objects, Cloud App Control and DLP are not captured.

**Live-tenant fixes in v1.9.0:** rule names are kept within ZIA's 31-character limit; URL categories and deprecated firewall network applications the tenant doesn't have are left out (a firewall rule left with none is skipped); new SSL rules go right after Zscaler's predefined rules; Sandbox rules name their file types and protocols instead of `ANY`; the isolation profile lookup uses `/browserIsolation/profiles`.

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
| **2.1.0** | Policies built into the templates for POV test cases: SSL catch-all last (below Zscaler exemptions) with TLS 1.2, DoH inspection, Zscaler Trusted Resolver, high-risk country firewall block, ZPA timeout / inspection / isolation policies and PRA consoles, ZCC tamper protection passwords, Teams / Zoom / Webex in ZDX. |
| **2.0.0** | POV release built on the 2.0 requirements spec. Global prefix and a server-enforced dry run (Create / Update / No change), with re-runs that update instead of duplicating. Licensing detection, summary report. **ZIA:** scope screen, baseline frameworks, DLP Monitor / Block with custom dictionaries, Endpoint DLP, Sandbox Standard / Advanced, AI Prompt Capture, UCaaS, granular app-specific Cloud App Control, Isolate for Misc / Unknown. **ZCC:** live bypass list, VPN / IP / DNS lists, ZPA reauthentication, separate IPv6 switches. **ZPA:** new wizard with CSV bulk upload of application segments. **ZPA and ZDX** bulk managers. Live-tested end to end on a Zscaler tenant. |
| **1.9.0** | Rules step: on/off switch for every rule, Isolate for URL rules. Isolation profile picker (default + refresh) for Isolate and Sandbox Quarantine & Isolate. SSL certificate picker and SSL Certificate Manager (bulk certificate change). Frameworks: save, load, capture from tenant. Live-tenant fixes (31-character names, missing categories / deprecated firewall apps, SSL rule order, Sandbox file types, isolation profile endpoint) |
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
