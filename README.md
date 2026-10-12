# 🐼 ZeroTrustPanda — ZTP Policy Wizard v1.7.0

Automated Zscaler Internet Access (ZIA) and Zscaler Client Connector (ZCC) policy configuration for healthcare and enterprise environments.

## ⬇️ Standalone edition (this branch)

No Node.js, no npm, nothing to install. Download the zip for your computer from [`standalone/release/`](standalone/release/), unzip, double-click:

| Computer | Download |
|---|---|
| Windows 10/11 (64-bit) | [`ZTP-Wizard-1.7.0-windows-x64.zip`](standalone/release/ZTP-Wizard-1.7.0-windows-x64.zip) |
| Mac with Apple Silicon (M1–M4) | [`ZTP-Wizard-1.7.0-macos-arm64.zip`](standalone/release/ZTP-Wizard-1.7.0-macos-arm64.zip) |
| Intel Mac | [`ZTP-Wizard-1.7.0-macos-x64.zip`](standalone/release/ZTP-Wizard-1.7.0-macos-x64.zip) |

The wizard starts on `http://127.0.0.1:3000` (or the next free port), opens your browser, and keeps your API credentials on your computer. Logs go to `ZTP-Wizard/logs` in your home folder.

**The builds are not code-signed yet**, so the first launch needs one extra click:
- **Windows:** SmartScreen → *More info* → *Run anyway*.
- **Mac:** right-click `ZTP-Wizard` → *Open* → *Open*. If macOS still refuses, run `xattr -d com.apple.quarantine ZTP-Wizard` in the unzipped folder (and, if it reports "killed", `codesign --force --sign - ZTP-Wizard`).

Same features as the v1.7.0 server version on `main`. The UI is compiled ahead of time with React and fonts built in, so it works without reaching any CDN; only the Zscaler API calls need the network.

**Build it yourself** (any OS, needs Node 18+, python3 and zip):
```
npm ci
cd standalone && npm ci && cd ..
npm run build:standalone          # all three targets -> standalone/release/
node standalone/build.js linux-x64   # or a single target
```
`standalone/build-ui.js` compiles the UI, `standalone/main.js` is the launcher, `standalone/build.js` compiles with Bun, and `standalone/adhoc-sign.py` re-signs the macOS builds ad-hoc (Bun's cross-compiled macOS signature doesn't match the final file, and Apple Silicon refuses to run it).

Running from source still works exactly as before: `npm ci && npm start`.

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

## Allow / Block Step (v1.6.0)

After **Customize**, the wizard lists each policy type (URL Filtering, Cloud Firewall, DNS Security, File Type Control, Cloud App Control, DLP) with **Tier default / Allow all / Block all**. Expand a type to flip individual rules. Rules set to Allow that the tier would restrict are flagged as WEAKENED in Review and the dry run, and logged as `ACTION_OVERRIDES` at apply time. `ZTP-Allow-Web` and `ZTP-Allow-NTP` are locked so baseline internet access can't be blocked by accident.

## Mobile Admin: Create Forwarding + App Profile (v1.7.0)

Mobile Admin → **Create from template** walks through the same flow as the ZIA wizard, with the forwarding profile first because the app profile has to point at it:

**Platform → Forwarding Profile → App Profile → Customize → Review → Dry Run → Apply**

**Forwarding Profile step**: create a new one or pick an existing one (Windows defaults to new, macOS to the existing MAC profile). The *ZTP Best Practice (Windows)* template is the 8 settings the tenant's "Windows" forwarding profile (ID 36531) has beyond a portal-default forwarding profile:

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

1. **App Profile**: *ZTP Best Practice* or *Portal Default* (blank). Windows Best Practice = the 12 settings enabled in the PerfectPolicy reference profile. macOS Best Practice = the 17 settings enabled in the MAC reference profile, with the MAC forwarding profile preselected.
2. **Customize**: name, description, forwarding profile, enable-after-create (off by default), and a toggle for each template setting.
3. **Review**: every setting with its new value, the portal default, and what it does.
4. **Dry Run**: read-only checks against the tenant (name unique, forwarding profile exists, bypass apps exist, placement above Default) and the resulting rule order.
5. **Apply**: creates the profile with `PUT /zcc/papi/public/v1/web/policy/edit`, reads it back and verifies each setting. Logged as `ZCC_DRY_RUN` / `ZCC_APPLY`.

macOS Best Practice (MAC): SSL certificate, block iCloud Private Relay, fail-close on tunnel exit off, recommended PAC URL, domain inclusions `*`, prioritize DNS exclusions off, flow-based tunnel, reconnect on wake, Teams/Zoom/W365-AVD IP bypass, notification framework, switch focus, notification template 2221, re-enable Internet Security after 60 min, Modern UI, local packet capture, automatic packet capture extras off, all users.

**Manual step:** the public API ignores the macOS *Modern UI* setting on create, update and PATCH, so the wizard marks it MANUAL and reminds you to set it in the portal after creation.

The create body is the full payload the Mobile Admin portal sends (`server/zcc-windows-profile-template.json`, `server/zcc-mac-profile-template.json`); minimal bodies are rejected by ZCC with HTTP 200 + `success:"false"`. Template settings live in `server/zcc-app-profile-templates.js`.

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
| **1.7.0** | Mobile Admin: forwarding profile step before the app profile (Best Practice from the "Windows" forwarding profile, 8 settings), created first and linked, with rollback; forwarding profile delete with in-use guard |
| **1.6.1** | Mobile Admin: macOS app profile create from the MAC Best Practice template (platform picker, MAC forwarding profile preselected, Modern UI as a manual step), macOS profiles listed for delete |
| **1.6.0** | Mobile Admin: Windows app profile create from the PerfectPolicy template; Allow / Block step: pick Allow or Block per policy type (URL, Firewall, DNS, File Type, Cloud App Control, DLP), flip individual rules, weakening warnings in Review/Dry Run and audit log |
| **1.5.2** | DLP rules shown in Review step, wizard state resets between runs for multi-deploy sessions, DLP engines/dictionaries in Bulk Rule Manager |
| **1.5.1** | Multi-user sessions (50 concurrent, 1hr TTL), Policy Catalog browser, ZCC rewrite to PATCH/POST edit workflow |
| **1.5.0** | DLP module (dictionary-first, 14 rule defs, 9 compliance frameworks, custom engine creation) |
| **1.4.0** | UI restructure, ZeroTrustPanda branding, firewall nwApplications fix, About page |
| **1.3.0** | Mobile Admin Portal (ZCC), OneAPI-only auth, bulk rule manager |
| **1.2.x** | Sandbox, DNS Security, File Type Control, Cloud App Control |
| **1.0–1.1** | URL Filtering, Firewall, SSL Inspection, Malware Protection |

## License

Internal use. Not for redistribution without permission.
