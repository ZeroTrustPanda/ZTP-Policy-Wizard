# ZTP Policy Wizard

**Automated ZIA policy deployment for Zscaler Zero Trust environments — compliance-mapped, tier-aware, and auditable.**

ZTP Policy Wizard is a self-hosted web application that generates and deploys production-ready Zscaler Internet Access (ZIA) policy configurations through the ZIA API. It eliminates the manual, error-prone process of configuring ZIA from scratch by providing opinionated, compliance-aligned templates across nine regulatory frameworks and three security tiers.

Built for security engineers who need repeatable, defensible ZIA deployments.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage Guide](#usage-guide)
- [Policy Modules](#policy-modules)
- [Security Tiers](#security-tiers)
- [Compliance Frameworks](#compliance-frameworks)
- [DLP Rules](#dlp-rules)
- [ZCC Mobile Admin Portal](#zcc-mobile-admin-portal)
- [Bulk Rule Manager](#bulk-rule-manager)
- [Audit Logging](#audit-logging)
- [API Reference](#api-reference)
- [Security Model](#security-model)
- [Deployment Options](#deployment-options)
- [Known Limitations](#known-limitations)
- [Contributing](#contributing)

---

## Features

- **One-click ZIA deployment** — generates and applies a complete policy baseline via the ZIA API
- **Nine policy modules** — URL Filtering, Cloud Firewall, SSL Inspection, Sandbox, DNS Security, File Type Control, Cloud App Control, DLP, and ZCC Mobile Admin
- **Three security tiers** — Strict, Balanced, and Permissive, calibrated for different risk tolerances
- **Nine compliance frameworks** — HIPAA, HITRUST CSF, NIST 800-53, NIST 800-171, PCI DSS v4.0, CJIS, SOX, FERPA, and GDPR with accurate regulatory control citations
- **13 DLP rule types** — mapped to specific regulatory controls (PCI Req 3.3/3.4/4.2, HIPAA §164.312(e), GDPR Art.4/5/44, etc.)
- **Dry run / plan / apply / rollback** — review exactly what will be created before touching the tenant
- **Bulk Rule Manager** — load and selectively delete rules across all policy categories including DLP engines and dictionaries
- **ZCC module** — generates Zscaler Client Connector forwarding and app profiles via the Mobile Admin API
- **Policy Catalog** — browse all available tier × framework combinations before connecting to any tenant
- **Multi-user sessions** — 50 concurrent sessions, 1-hour TTL, oldest-session eviction
- **Full audit logging** — every API call, apply operation, and bulk delete logged to disk as JSONL
- **No database** — stateless by design; credentials never touch disk

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│                  Web Browser                     │
│  ┌───────────────────────────────────────────┐  │
│  │  Single-Page Application (React/Babel)    │  │
│  │  Wizard: Connect → Configure → Review     │  │
│  │          → Apply → Audit                  │  │
│  │  Sidebar: Policy Catalog, Bulk Manager    │  │
│  └───────────────────────────────────────────┘  │
└───────────────────┬─────────────────────────────┘
                    │ HTTP (localhost:3000)
┌───────────────────┴─────────────────────────────┐
│              Express.js Server                   │
│  ┌──────────┐ ┌──────────┐ ┌────────────────┐  │
│  │ ZIA API  │ │ Template │ │ Audit Logger   │  │
│  │ Client   │ │ Engine   │ │ (JSONL)        │  │
│  └─────┬────┘ └──────────┘ └────────────────┘  │
│        │                                         │
│  ┌─────┴──────────────────────────────────────┐  │
│  │ In-Memory Session Store                    │  │
│  │ 50 sessions max · 1hr TTL · LRU eviction  │  │
│  │ Credentials never persisted to disk        │  │
│  └────────────────────────────────────────────┘  │
└───────────────────┬─────────────────────────────┘
                    │ HTTPS
┌───────────────────┴─────────────────────────────┐
│  Zscaler Cloud                                   │
│  ┌──────────────────────┐  ┌─────────────────┐  │
│  │ OneAPI (api.zsapi.net)│  │ Mobile Admin    │  │
│  │ OAuth2 via ZIdentity  │  │ (ZCC profiles)  │  │
│  │ zth.zslogin.net       │  └─────────────────┘  │
│  └──────────────────────┘                        │
└─────────────────────────────────────────────────┘
```

---

## Requirements

- **Node.js 18+** (LTS recommended)
- **npm** (included with Node.js)
- **Network access** to `api.zsapi.net` and `zth.zslogin.net` (OneAPI)
- **OAuth2 client credentials** — Client ID and Secret from ZIdentity

For Windows Server deployment:
- Windows Server 2016 or later
- (Optional) `node-windows` for running as a Windows Service

---

## Installation

### Windows (Quick Start)

1. Install [Node.js 18+](https://nodejs.org/)
2. Extract the `ztp-wizard` folder to your target location (e.g., `C:\ZTP-Wizard`)
3. Run `install.bat` — installs npm dependencies
4. Start with `npm start`
5. Open `http://localhost:3000` in a browser

### Windows Service (Production)

```cmd
npm install -g node-windows
node service-install.js
```

### Linux / Docker

```bash
cd ztp-wizard
npm install
npm start
```

---

## Configuration

Environment variables (all optional):

| Variable | Default | Description |
|----------|---------|-------------|
| `ZTP_PORT` | `3000` | HTTP listening port |
| `ZTP_HOST` | `0.0.0.0` | Bind address (`127.0.0.1` for local-only) |

```cmd
set ZTP_PORT=8080
set ZTP_HOST=127.0.0.1
npm start
```

---

## Usage Guide

### Step 1 — Connect

ZTP Wizard uses **OneAPI (OAuth2)** exclusively. Legacy API is not supported in current versions.

Required credentials:
- **Vanity domain** — your ZIdentity domain (e.g., `yourcompany.zslogin.net`)
- **Client ID** — from your ZIdentity OAuth2 app registration
- **Client Secret** — from your ZIdentity OAuth2 app registration
- **Cloud override** — optional, for non-production or partner tenants

Credentials are stored in process memory only, scoped to your session UUID. Never written to disk.

### Step 2 — Module Selection

Select which policy domains to configure. ZIA modules are active. ZPA is reserved for a future release.

### Step 3 — Security Tier

| Tier | Summary |
|------|---------|
| **Strict** | Maximum enforcement. Default-deny firewall, full SSL inspection, all DLP rules active. |
| **Balanced** | Recommended for most organizations. Caution on bandwidth/productivity. Selective SSL bypass for healthcare and finance. Core DLP rules. |
| **Permissive** | Minimal blocking. Security and legal liability blocks only. Useful for initial rollouts or low-sensitivity environments. |

### Step 4 — Compliance Framework

Optionally select a compliance framework to map every generated rule to specific regulatory controls. When selected, the Review step includes a Compliance Evidence tab with full control-to-rule mapping for auditors.

### Step 5 — Customize

- Set a **naming prefix** (default: `ZTP`) — all created objects are named `{PREFIX}-RuleName`
- Toggle individual modules on or off
- Preview rule counts per category before applying

### Step 6 — Review Plan

Before touching the tenant, the Review step provides four views:

- **Policy Rules** — all rules that will be created with full configuration details
- **Checklist** — manual tasks for features not yet API-automatable (e.g., enabling Sandbox AI Instant Verdict in the console)
- **Compliance Evidence** — control-to-rule mapping for export to auditors
- **Diff View** — live dry-run comparing current tenant state to proposed changes

### Step 7 — Apply

Confirms changes and calls the ZIA API to create all rules, then activates the configuration. Results display per-rule success/failure/warning status. A pre-change snapshot is stored for rollback.

### Step 8 — Audit Log

Full session log with timestamps, API calls, and apply results. Exportable as CSV or JSON from the UI. Log files persist on disk in `./logs/` across server restarts.

---

## Policy Modules

### URL Filtering

| Rule | Tiers | Action |
|------|-------|--------|
| Block Legal Liability | All | BLOCK — adult content, gambling, drugs, hacking, violence, weapons |
| Block Privacy Risk | All | BLOCK — spyware, adware, dynamic DNS, newly revived domains |
| Block Security Risk | All | BLOCK — newly registered domains, P2P, unknown, remote access tools |
| Block Bandwidth Loss | Strict: BLOCK · Balanced: CAUTION | Streaming, radio/TV, music, entertainment, news |
| Block Productivity Loss | Strict: BLOCK · Balanced: CAUTION | Games, social networking, shopping, auctions |

### Cloud Firewall

| Rule | Description |
|------|-------------|
| Block QUIC | UDP 443/80 blocked; ICMP unreachable sent for fast client fallback to TCP |
| Allow Web | HTTPS/HTTP recommended allow rule |
| Allow NTP | UDP 123 outbound for time synchronization |
| Allow DNS | UDP/TCP 53 outbound |
| Block All | Default-deny with logging (Strict tier only) |

### SSL Inspection

| Rule | Strict | Balanced | Permissive |
|------|--------|----------|------------|
| Inspect All HTTPS | ✅ | ✅ (with bypasses) | ❌ |
| Bypass Healthcare | — | ✅ | — |
| Bypass Finance/Banking | — | ✅ | — |

SSL DECRYPT rules use plain string arrays for `urlCategories`. Catch-all DECRYPT rules omit `urlCategories` entirely per confirmed ZIA API behavior on this tenant.

### Cloud Sandbox

Sandboxes Office documents (DOCX, XLSX, PPTX), executables (EXE, MSI, DLL), ZIP/RAR archives, and a catch-all for remaining file types. Enables AI Instant Verdict where available on the tenant (requires manual activation in ZIA console after apply).

### DNS Security

Blocks malware and phishing at the DNS layer. Works alongside URL Filtering for defense-in-depth.

### File Type Control

Blocks or flags high-risk file types by category. Tier-sensitive — Strict blocks password-protected and unscannable files; Balanced and Permissive allow them.

### Cloud App Control

Cloud App Control policy must be managed directly in the ZIA admin console. The wizard generates configuration guidance and checklist items but does not create Cloud App Control rules via API.

---

## Security Tiers

| Feature | Strict | Balanced | Permissive |
|---------|--------|----------|------------|
| Legal Liability | BLOCK | BLOCK | BLOCK |
| Privacy Risk | BLOCK | BLOCK | BLOCK |
| Security Risk | BLOCK | BLOCK | BLOCK |
| Bandwidth Loss | BLOCK | CAUTION | — |
| Productivity Loss | BLOCK | CAUTION | — |
| SSL Inspection | Full | Selective | None |
| Firewall | Default-deny | Standard | Standard |
| Password-protected files | BLOCK | ALLOW | ALLOW |
| Unscannable files | BLOCK | ALLOW | ALLOW |
| DLP | All 13 rules | Core rules | Core rules |

---

## Compliance Frameworks

Each framework maps specific regulatory controls to ZIA policy rules. Control IDs are sourced from official regulatory texts — not approximations.

| Framework | Key Controls Covered |
|-----------|----------------------|
| **HIPAA** | 164.312(a)(1), 164.312(e)(1), 164.312(e)(2) — access control, transmission security |
| **HITRUST CSF** | 09.j (malicious code), 01.v (IP protection), 09.ab (monitoring) |
| **NIST 800-53** | SC-7, SC-8, AC-4, SI-3, IA-5, PM-12 — boundary, transmission, malware |
| **NIST 800-171** | 3.1.3, 3.5.3, 3.13.8 — CUI transmission and access |
| **PCI DSS v4.0** | Req 3.3, 3.4, 4.2, 5.2, 5.3, 8.4, 8.6, 12.10 — cardholder data, malware, auth |
| **CJIS** | §5.4 (biographic data), §5.6.2 (no credential sharing), §5.10.1.2 (audit) |
| **SOX** | §302 (disclosures), §404 (internal controls), §802 (record destruction) |
| **FERPA** | §99.31 (disclosure conditions), §99.35 (enforcement) |
| **GDPR** | Art.4 (personal data), Art.5 (minimization), Art.32 (security), Art.44 (transfers) |

---

## DLP Rules

DLP rules use `action=ALLOW` with Zscaler Incident Receiver — they monitor and alert rather than block. This is the recommended approach for initial DLP deployment. Rules can be converted to BLOCK in the ZIA console after baselining alert volume.

### Rule Definitions

| Rule Name | Data Detected | Primary Regulatory Anchor |
|-----------|---------------|--------------------------|
| `HIPAA-SSN-Medical` | SSN, ePHI, medical records | HIPAA §164.312(e)(1) |
| `PCI-Cardholder-Data` | Credit cards, ABA routing, IBAN | PCI DSS Req 3.3, 3.4, 4.2 |
| `GLBA-NPI` | SSN, credit cards, ABA routing, IBAN | GLBA Safeguards Rule (16 CFR §314) |
| `Medical-Information` | Medical diagnoses, drugs, treatments, medical imaging | HIPAA §164.312(e)(2) |
| `PII-Core-Identifiers` | SSN, driver's license, US passport, ITIN | GDPR Art.4/5, CJIS §5.4 |
| `PII-Tax-Financial-IDs` | ITIN, ABA routing, IBAN | FERPA (FAFSA context), GLBA |
| `Financial-Documents` | Financial statements, invoices, tax docs, corporate finance | SOX §302, §404, §802 |
| `Credentials-Secrets` | API keys, tokens, private keys, OAuth credentials | NIST 3.5.3, PCI Req 8.4, 8.6 |
| `Source-Code-IP` | Source code files | NIST AC-4, HITRUST 01.v, SOX §302 |
| `Legal-Documents` | Legal, court, and immigration documents | SOX §802, CJIS §5.10.1.2, GDPR Art.44 |
| `GDPR-EU-Personal-Data` | EU national IDs, passports, IBAN, credit cards | GDPR Art.4, Art.5, Art.32, Art.44 |
| `Offensive-Language` | Adult content, offensive language | FERPA §99.31, NIST PM-12 |
| `Self-Harm-Cyberbullying` | Self-harm and cyberbullying content | FERPA §99.31/99.35, HITRUST 09.j |

### DLP Engine Behavior

The ZIA `webDlpRules` API requires a `dlpEngines` reference (`{id, name}` objects in IDNameExtensions format) on every rule. ZTP Wizard uses a dictionary-first hybrid approach:

1. **Preferred engine lookup** — searches the tenant for a named engine matching the framework (e.g., `HIPAA`, `PCI`)
2. **Dictionary fallback** — if no matching engine is found, the rule falls back to the first available named engine on the tenant and surfaces a warning in the apply results

Rules created with a fallback engine should be reviewed in the ZIA console and reassigned to the appropriate engine.

> **Note:** Custom DLP engine creation via API requires a structured `engineExpression` referencing specific dictionary IDs (format: `((D{id}.S> 1) OR (D{id}.S> 1))`). ZTP Wizard does not auto-create custom engines. Create engines in the ZIA admin console before applying DLP templates if you need engine-specific matching.

---

## ZCC Mobile Admin Portal

The ZCC module generates Zscaler Client Connector configuration objects via the Mobile Admin API. It operates against a separate ZCC OAuth2 credential set from ZIA.

**Forwarding Profile generated:**
- Z-Tunnel 2.0 for both ZIA and ZPA traffic
- Transparent redirection of all web traffic
- IPv6 traffic dropped (prevents bypass)
- TLS fallback disabled

**App Profile generated (Windows, `deviceType: 3`):**
- SSL certificate auto-installation enabled
- WFP (Windows Filtering Platform) driver enabled
- V8 PAC parser
- IPv6 disabled at OS level
- Windows Firewall rules for ZCC processes
- Debug logging enabled
- Notification framework configured

**API behavior notes:**
- `GET /mobileAdmin/v1/forwardingProfiles/{id}` returns 404 on some tenants — the module works around this by fetching the full forwarding profile list and finding by ID
- App profile fields use integer toggles (`0`/`1`), not booleans
- `deviceType: 3` (Windows) is required on all app profile operations

---

## Bulk Rule Manager

Accessible from the sidebar at any time after connecting. Loads all rules across every policy category from the live tenant and allows selective deletion with text-filter search.

| Category | Deletable | Notes |
|----------|-----------|-------|
| URL Filtering | All non-default rules | — |
| Cloud Firewall | All non-default rules | — |
| SSL Inspection | All non-default rules | — |
| Sandbox | All non-default rules | — |
| DNS Security | All non-default rules | — |
| File Type Control | All non-default rules | — |
| DLP Rules | All rules | No predefined DLP rules exist |
| DLP Engines | Custom only | Predefined engines shown but non-deletable |
| DLP Dictionaries | Custom only | ~110 predefined shown as reference; custom are selectable |

Use the filter box to search by name — e.g., type `ZTP` to select only wizard-created objects. Deletion activates changes automatically.

Load time is approximately 10–15 seconds due to ZIA API rate limiting across multiple category fetches.

---

## Audit Logging

Every session action is logged automatically. Three log streams:

| File | Format | Content |
|------|--------|---------|
| `./logs/ztp-http-YYYY-MM-DD.log` | Plain text | All HTTP requests with status, duration, source IP |
| `./logs/ztp-audit-YYYY-MM-DD.jsonl` | JSONL | Policy applies, API calls, template generations, bulk deletes |
| `./logs/ztp-errors-YYYY-MM-DD.log` | Plain text | Server errors and exceptions |

Audit logs are exportable from the UI as CSV or JSON. Logs persist across server restarts and rotate daily by date.

---

## API Reference

All endpoints require an active session established via `/api/auth/oneapi`. The session token is stored in a browser cookie.

### Authentication

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/auth/oneapi` | Authenticate with OAuth2 client credentials |
| POST | `/api/auth/logout` | Destroy session |
| GET | `/api/auth/status` | Check session validity |

### Policy Catalog (No Auth Required)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/catalog` | Return all tier × framework policy combinations with full rule hierarchy |

### Templates

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/templates/frameworks` | List compliance frameworks |
| GET | `/api/templates/clouds` | List ZIA cloud instances |
| POST | `/api/templates/generate` | Generate a policy template |

### Plan & Apply

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/plan/dryrun` | Dry run — compare template against current tenant state |
| POST | `/api/apply` | Apply template to tenant |
| POST | `/api/rollback` | Best-effort rollback using pre-change snapshot |

### Current State

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/state/url-rules` | URL filtering rules |
| GET | `/api/state/firewall-rules` | Cloud firewall rules |
| GET | `/api/state/ssl-rules` | SSL inspection rules |
| GET | `/api/state/dlp-rules` | DLP web rules |
| GET | `/api/state/dlp-engines` | DLP engines (predefined + custom) |
| GET | `/api/state/dlp-dictionaries` | DLP dictionaries (predefined + custom) |
| GET | `/api/state/all-rules` | All of the above in a single call |
| GET | `/api/state/url-categories` | Available URL categories |
| GET | `/api/state/activation` | Current activation status |

### Bulk Operations

| Method | Path | Description |
|--------|------|-------------|
| DELETE | `/api/bulk/delete` | Delete selected rules by category and ID list |

### ZCC

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/zcc/auth` | Authenticate against Mobile Admin API |
| GET | `/api/zcc/profiles` | List ZCC app profiles |
| PATCH | `/api/zcc/profiles/:id` | Update app profile fields |
| GET | `/api/zcc/forwarding-profiles` | List forwarding profiles |
| POST | `/api/zcc/forwarding-profiles` | Create or update forwarding profile |

### Audit

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/audit/logs` | Session audit entries |
| GET | `/api/audit/export/csv` | Download audit log as CSV |
| GET | `/api/audit/export/json` | Download audit log as JSON |

---

## Security Model

- **Credentials** — never persisted to disk; held in Node.js process memory scoped to session UUID
- **Sessions** — UUID-based in-memory Map; 50 concurrent max with 1-hour TTL; oldest session evicted on overflow; destroyed on logout or server restart
- **No RBAC** — single-tenant tool; network/OS-level access control is the operator's responsibility
- **No deletion by default** — the wizard only creates and updates objects; it never deletes existing ZIA configuration outside of the explicit Bulk Rule Manager
- **Audit logging** — every API call, apply, and bulk delete is logged; logs do not contain credentials
- **Rule ordering** — new rules are ordered to take precedence above conflicting existing rules
- **Rollback** — best-effort; stores a pre-change snapshot, but since the tool only creates (not modifies existing rules), rollback means deleting the wizard-created rules

---

## Deployment Options

### Single User (Local)

Run on your workstation with `ZTP_HOST=127.0.0.1`. Access at `http://localhost:3000`.

### Shared (Internal Network)

Run on a Windows Server or Linux VM accessible to your team. Use `ZTP_HOST=0.0.0.0`. For HTTPS, place behind a reverse proxy (IIS, nginx) with TLS termination.

### Airgapped

The server has no external dependencies at runtime. The browser UI uses CDN links for React/Babel — for fully airgapped deployment:

1. Download `react.production.min.js`, `react-dom.production.min.js`, and `babel.min.js`
2. Place in `public/lib/`
3. Update script `src` paths in `public/index.html` to `./lib/...`

---

## Known Limitations

- **ZIA API tenant variance** — confirmed quirks on the `zth` Zscaler tenant are baked in as workarounds. Other tenants may behave differently on edge cases (e.g., `fileTypes`, `zscalerIncidentReceiver`, SSL rule `urlCategories`). Check apply results carefully on first run against a new tenant.
- **DLP engine fallback** — if no matching named engine is found on the tenant, DLP rules fall back to the first available engine. Review and reassign in the ZIA console.
- **DLP dictionary matching** — uses exact internal name mapping (`SSN`, `CREDIT_CARD`, `MEDICAL`, etc.). If a dictionary was renamed on the tenant, matching will fail silently.
- **Custom DLP engines** — cannot be auto-created via API without pre-known dictionary IDs. Create manually in ZIA console before applying DLP templates.
- **Forwarding profile GET by ID** — returns 404 on some tenants; worked around via list-and-find.
- **Bulk Manager load time** — ~10–15 seconds due to rate limiting across multiple sequential API fetches.
- **No ZPA support** — ZPA module is a placeholder; not yet implemented.
- **No multi-tenant batch** — one tenant at a time per session.

---

## Contributing

Issues and pull requests are welcome.

For compliance control mapping changes, open an issue first with citations to the specific regulatory section being mapped (e.g., HIPAA §164.312(e)(1), PCI DSS Req 3.4). Compliance mappings without citations will not be merged.

For ZIA API behavior changes, include the raw request/response that demonstrates the behavior, and which cloud/tenant type it was observed on.

---

## License

MIT License — see [LICENSE](LICENSE) for details.
