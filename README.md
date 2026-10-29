# 🐼 ZeroTrustPanda — ZTP Policy Wizard v2.7.0

Proof-of-value automation for Zscaler SEs: Zscaler Internet Access (ZIA), Zscaler Client Connector (ZCC), Zscaler Private Access (ZPA) and Zscaler Digital Experience (ZDX), all with one set of OneAPI (ZIdentity) client credentials.

## ⬇️ Standalone edition (this branch)

No Node.js, no npm, nothing to install. Click your download, unzip it, and double-click `ZTP-Wizard`:

| Computer | Download (click to download) |
|---|---|
| **Mac with Apple silicon (M1–M4)** | [**ZTP-Wizard-2.7.0-macos-arm64.zip**](https://github.com/ZeroTrustPanda/ZTP-Policy-Wizard/raw/standalone/standalone/release/ZTP-Wizard-2.7.0-macos-arm64.zip) |
| Windows 10/11 (64-bit) | [ZTP-Wizard-2.7.0-windows-x64.zip](https://github.com/ZeroTrustPanda/ZTP-Policy-Wizard/raw/standalone/standalone/release/ZTP-Wizard-2.7.0-windows-x64.zip) |
| Intel Mac | [ZTP-Wizard-2.7.0-macos-x64.zip](https://github.com/ZeroTrustPanda/ZTP-Policy-Wizard/raw/standalone/standalone/release/ZTP-Wizard-2.7.0-macos-x64.zip) |

The wizard starts on `http://127.0.0.1:3000` (or the next free port), opens your browser, and keeps your API credentials on your computer. Logs go to `ZTP-Wizard/logs` in your home folder.

**The builds are not code-signed yet**, so the first launch needs one extra click:
- **Mac:** right-click `ZTP-Wizard` → *Open* → *Open*. If macOS still refuses, run `xattr -d com.apple.quarantine ZTP-Wizard` in the unzipped folder. If it then reports "killed", also run `codesign --force --sign - ZTP-Wizard`.
- **Windows:** SmartScreen → *More info* → *Run anyway*.

These are the same features as the v2.7.0 server version on `main`. The UI is compiled ahead of time, with React and fonts built in, so it works without reaching any CDN; only the Zscaler API calls need the network.

**Release notes (2.0 → 2.7.0):** [docs/release-notes/v2.7.0.md](docs/release-notes/v2.7.0.md) · **Change log:** [CHANGELOG.md](CHANGELOG.md) · **Releases:** [GitHub releases](https://github.com/ZeroTrustPanda/ZTP-Policy-Wizard/releases)

## What's in 2.x (2.0 → 2.7.0)

- **AI Guard (2.5):**
  - A fourth product toggle; it needs ZIA, so turning it on turns ZIA on.
  - Sends ChatGPT, Microsoft 365 Copilot, Claude, Gemini and other AI apps through ZIA inspection to AI Guard with proxy chaining.
  - Blocks QUIC, and puts an SSL Inspect rule above every bypass (including Office 365 One Click).
  - Turns on Gen AI prompt capture when licensed, and checks the AI Guard ("zguard") API.
  - Reuses an AI Guard proxy and gateway already in ZIA. The gateway itself is a portal step, because the API can't create it.

- **Compliance profiles (2.7):**
  - Chosen once on Customer intake; a Federal vertical adds FedRAMP Moderate and High, CMMC 2.0 Level 2, Federal Zero Trust, IRS Pub 1075 and GovRAMP.
  - Every rule maps to the profile's controls or states why not.
  - A compliance pack per POV: profile DLP test files, control mapping report, policy export and test plan by control.

- **Licence-aware POVs (2.6.1):**
  - Readiness fails any core ZIA feature the tenant is not licensed for.
  - The scope marks what is not licensed (Sandbox Advanced, AI prompt capture, Advanced Cloud Firewall, DNS tunnel detection).
  - Cloud Firewall Standard tenants get a standard rule set.
  - ZDX templates fit the ZDX tier.

- **Several POVs at once, Prove it and a POV test kit (2.6):**
  - Each POV page takes its tenant's API key (memory only) and opening a POV switches tenant.
  - Prove it for URL filtering, threat, cloud apps, firewall and DNS, with built-in test destinations or your own, on every runbook test.
  - A test kit that follows the POV: DLP files for its vertical plus generic PII, EICAR / AMTSO threat tests, a unique sandbox file.
  - ZPA bulk delete in the order ZPA requires, with unselected dependencies flagged.
  - Readiness shows the API client's permissions per product and every SKU on the tenant.

- **AI compliance profile and Allow in ZIA (2.5.1):**
  - A compliance profile (HIPAA, PCI, GDPR, …) becomes an AI Guard detection policy and control, in Monitor or Block mode.
  - The AI apps you pick are allowed above ZIA Block / Caution / Isolate rules, so they reach AI Guard.

- **Light theme, About page and icons (2.5):** green-on-white by default with a dark-mode toggle, an About page, and line icons.

- **Active POVs (2.4):**
  - Every POV is saved on this computer with its plan, the exact step you left off, what the wizard did (runs, restore points, drift), tests and customer success criteria, a timeline, notes and follow-ups.
  - Pick a POV in the sidebar, sign in to its tenant and press *Resume*. A POV never opens against a different tenant, and no credentials or other secrets are saved.
  - Saved templates, export / import, and a quiet-POV flag.

- **Guided POV (POV Start):** one step at a time.
  1. Tenant readiness, including licensing cautions.
  2. Build the POV: ZIA / ZPA / ZDX.
  3. Customer intake: name, generated prefix, internal domain, preset, baseline.
  4. Client Connector.
  5. Internet Access.
  6. Private Access.
  7. Digital Experience.
  8. One dry run and one apply, with live progress.
- **Presets** (Healthcare, Financial services, General enterprise, Education):
  - ZPA gets a `*.domain` wildcard, the common apps and the vertical's apps. Every name, destination and port stays editable.
  - ZDX gets apps for the market segment.
- **Safe by design:**
  - A mandatory dry run with field-level differences.
  - Re-runs update in place instead of duplicating.
  - Automatic ZIA activation.
  - Snapshots with restore, and a drift check.
  - Rate-limit countdowns.
  - Secrets never logged.
- **Zscaler Internet Access:**
  - Compliance baselines (HIPAA, HITRUST, NIST, PCI DSS, CJIS, SOX, FERPA, GDPR) or Strict / Balanced / Permissive / Zero Trust Hospital.
  - Rule review with on / off, Allow / Block / Isolate, search and saved selections.
  - DLP, Endpoint DLP, Sandbox, AI Prompt Capture, UCaaS and granular Cloud App Control.
  - SSL catch-all always last with TLS 1.2, DoH inspection, Trusted Resolver and geo-blocking.
- **Zscaler Client Connector:**
  - Windows / macOS forwarding and app profiles.
  - Tamper password.
  - Live bypass apps and validated lists.
  - Devices with one-time passwords.
  - The install command / script builder.
- **Zscaler Private Access:**
  - Connector group, provisioning key, segment / server groups and application segments (wildcard, preset or CSV).
  - Access, timeout, inspection and isolation policies, with a POV isolation profile.
  - Optional Browser Access and PRA consoles.
- **Zscaler Digital Experience:** Microsoft Login, Teams, Zoom, Webex and custom apps, with Web and CloudPath probes.
- **POV Tests:** a runbook, *Prove it* for URLs and a DLP test kit, all feeding the summary report.
- **Interface:**
  - One Bulk Rule Manager for ZIA / ZPA / ZDX.
  - A layout that fits any window size.
  - An update badge.

The full feature list, by product and by version, is in the [release notes](docs/release-notes/v2.7.0.md).

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
| **2.7.0** | One compliance pane; Federal vertical and six federal profiles; every rule mapped or a stated reason; compliance pack per POV. |
| **2.6.1** | Core ZIA prerequisites; Not licensed in the scope; Cloud Firewall Standard rule set; DNS tunnel rules need Advanced Firewall; ZDX tier choice. |
| **2.6.0** | API keys per POV in memory with tenant switching; Prove it for every web test type; test kit by POV scope and vertical; ZPA bulk delete order and dependency flags; API permissions and SKU printout in readiness. |
| **2.5.2** | Allow in ZIA includes Claude / Anthropic, OpenAI, Grok and Glean (ZIA accepts them although its action lookup lists none). |
| **2.5.1** | AI compliance profile → AI Guard detection policy + control (Monitor / Block); Allow in ZIA for the picked AI apps (Cloud App Control, URL Filtering when needed); Caution-AI targets AI_ML_APPS. |
| **2.5.0** | AI Guard (needs ZIA): CA, proxy or reuse, wildcard AI app group, QUIC block, SSL Inspect at the top, prompt capture, Proxy Chaining forwarding, zguard API check; light theme with dark toggle; About page; line icons. |
| **2.4.0** | Active POVs: saved workspaces per POV with resume, plan, runs / restore / drift, tests and success criteria, timeline, notes and follow-ups; tenant guard; no secrets saved; templates; export / import. |
| **2.3.1** | ZPA application table editable (name, destinations, TCP / UDP ports) and + Add application. |
| **2.3.0** | Guided POV (readiness → scope → intake → Client Connector → ZIA → ZPA → ZDX → one dry run and apply), presets fill ZPA (wildcard + common apps) and ZDX (market apps), Education preset, licensing cautions in readiness, prefix from the intake (no global prefix bar), one Bulk Rule Manager for ZIA / ZPA / ZDX. |
| **2.2.0** | POV Start (readiness, intake presets, combined dry run / apply with live progress), POV Tests (runbook, prove it, DLP kit), Client Connector devices / one-time passwords / install builder, ZPA access policy, Browser Access and POV isolation profile, snapshot restore, drift check, field-level diffs, rate-limit countdowns, rule search, update check. |
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
