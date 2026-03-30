# 🐼 ZeroTrustPanda — ZTP Policy Wizard v1.5.2

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
| GET | `/api/diag/dlp` | DLP diagnostic (engines, dictionaries, rules) |

## Version History

| Version | Changes |
|---------|---------|
| **1.5.2** | DLP rules shown in Review step, wizard state resets between runs for multi-deploy sessions, DLP engines/dictionaries in Bulk Rule Manager |
| **1.5.1** | Multi-user sessions (50 concurrent, 1hr TTL), Policy Catalog browser, ZCC rewrite to PATCH/POST edit workflow |
| **1.5.0** | DLP module (dictionary-first, 14 rule defs, 9 compliance frameworks, custom engine creation) |
| **1.4.0** | UI restructure, ZeroTrustPanda branding, firewall nwApplications fix, About page |
| **1.3.0** | Mobile Admin Portal (ZCC), OneAPI-only auth, bulk rule manager |
| **1.2.x** | Sandbox, DNS Security, File Type Control, Cloud App Control |
| **1.0–1.1** | URL Filtering, Firewall, SSL Inspection, Malware Protection |

## License

Internal use. Not for redistribution without permission.
