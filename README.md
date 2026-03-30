# ZTP Policy Wizard v1.5.0

**Zscaler Template Policy Configuration Tool**

A web-based wizard for configuring Zscaler Internet Access (ZIA) policies using compliance-aligned templates. Supports both Legacy API and OneAPI (OAuth2) authentication, with guided flows for URL Filtering, Cloud Firewall, SSL Inspection, Cloud Sandbox, DNS Security, File Type Control, Cloud App Control, **Data Loss Prevention (DLP)**, Malware Protection, and Advanced Settings. Includes a Bulk Delete utility for test cleanup.

### What's New in v1.5.0: Data Loss Prevention Module

- **DLP Policy Rules**: Automatically maps compliance frameworks (HIPAA, PCI-DSS, GDPR, SOX, FERPA, CJIS, NIST, HITRUST) to Zscaler predefined DLP engines
- **Healthcare Focus**: Zero Trust Hospital (ZTH) ebook tier includes HIPAA, Medical, PII, PCI, CCPA, and Finance DLP engines
- **Safe-by-Default**: All DLP rules use `Action=ALLOW` with Zscaler Incident Receiver for monitoring (no blocking on initial deployment)
- **Auditor Hosted Notifications**: DLP notification templates use auditor-hosted type to avoid errors
- **Engine Auto-Resolution**: DLP engine names are resolved to tenant-specific IDs at apply time with partial-match fallback
- **Source Code Protection**: Strict and ZTH tiers include source code upload/download detection
- **Tiered Engine Selection**: Strict tiers enable low-volume (more sensitive) DLP engines; Permissive tiers use high-volume thresholds
- **26 Predefined DLP Engines Supported**: HIPAA, GLBA, PCI, CCPA, GDPR, FISMA, NIST, PDPA, PII, PIPEDA, LGPD, DPDPA, Medical, Legal, Finance, Credentials, Offensive Language, Self-Harm & Cyberbullying

---

## Table of Contents

- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage Guide](#usage-guide)
- [API Reference](#api-reference)
- [Security Model](#security-model)
- [Template Details](#template-details)
- [Compliance Frameworks](#compliance-frameworks)
- [Deployment Options](#deployment-options)
- [Roadmap](#roadmap)

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│                  Web Browser                     │
│  ┌───────────────────────────────────────────┐  │
│  │  Single-Page Application (React)          │  │
│  │  Wizard Steps: Connect → Configure →      │  │
│  │  Review → Apply → Audit                   │  │
│  └───────────────────────────────────────────┘  │
└───────────────────┬─────────────────────────────┘
                    │ HTTP (localhost:3000)
┌───────────────────┴─────────────────────────────┐
│              Express.js Server                   │
│  ┌──────────┐ ┌──────────┐ ┌────────────────┐  │
│  │ ZIA API   │ │ Template │ │ Audit Logger   │  │
│  │ Client    │ │ Engine   │ │ (JSON Lines)   │  │
│  └─────┬─────┘ └──────────┘ └────────────────┘  │
│        │                                         │
│  ┌─────┴──────────────────────────────────────┐  │
│  │ In-Memory Session Store                    │  │
│  │ (credentials never persisted to disk)      │  │
│  └────────────────────────────────────────────┘  │
└───────────────────┬─────────────────────────────┘
                    │ HTTPS
┌───────────────────┴─────────────────────────────┐
│  Zscaler Cloud                                   │
│  ┌─────────────────┐  ┌──────────────────────┐  │
│  │ Legacy API       │  │ OneAPI (api.zsapi.net)│  │
│  │ admin.zs*.net    │  │ OAuth2 via ZIdentity  │  │
│  │ /api/v1/*        │  │ /zia/api/v1/*         │  │
│  └─────────────────┘  └──────────────────────┘  │
└─────────────────────────────────────────────────┘
```

---

## Requirements

- **Node.js 18+** (LTS recommended)
- **npm** (included with Node.js)
- **Network access** to your Zscaler cloud instance (or api.zsapi.net for OneAPI)
- **ZIA Admin credentials** (Legacy) or **OAuth2 client credentials** (OneAPI)

For Windows Server deployment:
- Windows Server 2016 or later
- (Optional) `node-windows` for running as a Windows Service

---

## Installation

### Windows Server (Quick Start)

1. Install [Node.js 18+](https://nodejs.org/) on the server
2. Extract the `ztp-wizard` folder to your desired location (e.g., `C:\ZTP-Wizard`)
3. Run `install.bat` — this installs npm dependencies
4. Start with `npm start`
5. Open `http://localhost:3000` in a browser

### Windows Service (Production)

```cmd
npm install -g node-windows
node service-install.js
```

### Linux / Docker (Alternative)

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

Set before starting:
```cmd
set ZTP_PORT=8443
set ZTP_HOST=127.0.0.1
npm start
```

---

## Usage Guide

### Step 1: Connect

Choose authentication mode:

**Legacy API** — Requires:
- ZIA Cloud instance (e.g., zscloud.net)
- Admin username (email)
- Admin password
- API Key (from ZIA Admin Portal → Administration → API Key Security)

**OneAPI (OAuth2)** — Requires:
- Vanity domain (your ZIdentity domain)
- Client ID
- Client Secret
- (Optional) Cloud override for non-production environments

Credentials are held in browser memory only. Never stored to disk.

### Step 2: Module Selection

Currently ZIA only. ZPA is a placeholder for future releases.

### Step 3: Security Tier

| Tier | URL Filtering | SSL Inspection | Firewall | Files |
|------|---------------|---------------|----------|-------|
| **Strict** | Blocks Legal Liability, Privacy Risk, Security Risk, Bandwidth Loss, Productivity Loss | Full inspection | Default deny | Block pw-protected & unscannable |
| **Balanced** | Blocks Legal/Privacy/Security; Caution for Bandwidth/Productivity | Inspect except health & finance | Standard | Allow pw-protected |
| **Permissive** | Blocks Legal/Privacy/Security only | No inspection | Standard | Allow all |

### Step 4: Compliance Framework

Optional. Maps each policy rule to specific regulatory controls for audit evidence:

HIPAA, HITRUST CSF, NIST 800-53, NIST 800-171, PCI DSS, CJIS, SOX, FERPA, GDPR

### Step 5: Customize

- Set naming prefix (default: `ZTP`). All objects created will be named like `ZTP-Block-Legal-Liability`
- Toggle individual policy modules on/off

### Step 6: Review Plan

- **Policy Rules tab**: View all rules that will be created
- **Checklist tab**: Implementation checklist including manual tasks
- **Compliance Evidence tab**: Control-to-policy mapping for auditors
- **Diff View tab**: Runs dry-run against your tenant showing current vs. proposed state

### Step 7: Apply

- Confirm understanding of changes
- Creates rules via ZIA API
- Activates changes
- Shows results with any errors

### Step 8: Audit Log

- Full session log with timestamps
- Export to CSV or JSON
- Logs stored on server in `./logs/` as JSONL files

---

## API Reference

All API endpoints are prefixed with `/api`.

### Authentication

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/auth/legacy` | Authenticate with Legacy API credentials |
| POST | `/api/auth/oneapi` | Authenticate with OneAPI OAuth2 credentials |
| POST | `/api/auth/logout` | End session |
| GET | `/api/auth/status` | Check authentication status |

### Templates

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/templates/frameworks` | List compliance frameworks |
| GET | `/api/templates/clouds` | List ZIA cloud instances |
| POST | `/api/templates/generate` | Generate a policy template |

### Plan & Apply

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/plan/dryrun` | Dry run — compare template against current state |
| POST | `/api/apply` | Apply template to tenant |
| POST | `/api/rollback` | Best-effort rollback using stored snapshot |

### Current State

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/state/url-rules` | Get current URL filtering rules |
| GET | `/api/state/firewall-rules` | Get current firewall rules |
| GET | `/api/state/ssl-rules` | Get current SSL inspection rules |
| GET | `/api/state/url-categories` | Get URL categories |
| GET | `/api/state/activation` | Get activation status |

### Audit

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/audit/logs` | Get session audit entries |
| GET | `/api/audit/export/csv` | Download audit log as CSV |
| GET | `/api/audit/export/json` | Download audit log as JSON |

---

## Security Model

- **Credentials**: Never persisted. Stored in Node.js process memory only, scoped to the session.
- **Sessions**: UUID-based, stored in-memory Map. Destroyed on logout or server restart.
- **No RBAC**: Single-user tool. Access control should be handled at the network/OS level.
- **Audit Logging**: Every API call, template generation, and policy application is logged to `./logs/`.
- **No deletion**: The tool only creates and updates objects. It never deletes existing ZIA configuration.
- **Rule ordering**: New rules are ordered to take precedence above any conflicting existing rules.
- **Rollback**: Best-effort. Stores a pre-change snapshot, but since the tool only creates (never deletes), rollback involves manual removal of created rules.

---

## Template Details

### URL Filtering Rules Created

| Rule | Strict | Balanced | Permissive |
|------|--------|----------|------------|
| Block Legal Liability class | ✅ | ✅ | ✅ |
| Block Privacy Risk class | ✅ | ✅ | ✅ |
| Block Security Risk categories | ✅ | ✅ | ✅ |
| Block Bandwidth Loss class | ✅ BLOCK | ⚠️ CAUTION | ❌ |
| Block Productivity Loss class | ✅ BLOCK | ⚠️ CAUTION | ❌ |
| Custom Block Category | ✅ | ✅ | ✅ |

### Firewall Rules Created

- Block QUIC Protocol (with ICMP unreachable for fast switchover)
- Recommended Firewall Allow (DNS, HTTP, HTTPS)
- Allow NTP
- Block Malicious IPs/Domains
- Default Block All (Strict only)

### SSL Inspection Rules Created

- **Strict**: Inspect all traffic
- **Balanced**: Bypass healthcare & finance, inspect everything else
- **Permissive**: No inspection (with risk warning)

---

## Compliance Frameworks

Each framework maps specific controls to ZIA policies:

| Framework | Example Control → ZIA Policy |
|-----------|------------------------------|
| HIPAA | 164.312(a)(1) Access Control → URL Filtering, Firewall |
| HITRUST CSF | 09.j Malicious Code → Malware Protection |
| NIST 800-53 | SC-7 Boundary Protection → Firewall rules |
| PCI DSS | 5.2 Malware Prevention → Malware Protection |
| GDPR | Art.32 Security of Processing → SSL Inspection |

Evidence is viewable in the Review step and exportable via the audit log.

---

## Deployment Options

### Self-Contained (Airgapped)

Copy the entire `ztp-wizard` folder to the target server. The only external dependency is Node.js itself. The web UI uses CDN links for React/Babel, but these can be downloaded and served locally for fully airgapped deployment:

1. Download `react.production.min.js`, `react-dom.production.min.js`, and `babel.min.js`
2. Place in `public/lib/`
3. Update `public/index.html` script src paths to `./lib/...`

### Web Server (Internal Network)

Run on a Windows Server accessible to your team. Use `ZTP_HOST=0.0.0.0` to listen on all interfaces.

For HTTPS, place behind a reverse proxy (IIS, nginx) with TLS termination.

---

## Roadmap

### MVP (Current)
- ✅ ZIA URL Filtering, Cloud Firewall, SSL Inspection
- ✅ Malware Protection & Advanced Settings configuration
- ✅ Legacy API + OneAPI authentication
- ✅ Three security tiers (Strict / Balanced / Permissive)
- ✅ 9 compliance framework mappings
- ✅ Dry run / Plan / Apply / Rollback
- ✅ Full audit logging with CSV/JSON export
- ✅ Plain-English explanations for each setting

### v1.1 (Planned)
- 🔲 ZPA module with wildcard policy support
- 🔲 ZPA App Segments in ZTPCreated group
- 🔲 DLP policy templates
- 🔲 Sandbox rule templates
- 🔲 Cloud App Control templates
- 🔲 PDF evidence report export

### v1.2 (Planned)
- 🔲 Custom template editor (save/load)
- 🔲 Batch operations for multi-tenant
- 🔲 Webhook notifications on apply
- 🔲 SAML/SSO for wizard access
