# Changelog

## v2.0.0 → v2.5.2 — 2026-10-19 to 2026-10-22

Release notes for the whole 2.x line: [docs/release-notes/v2.5.2.md](docs/release-notes/v2.5.2.md).

### 2.5.2
- **Fix: Allow in ZIA now includes Claude (CLAUDE_AI, ANTHROPIC_AI), OpenAI, Grok AI and Glean.** On ZTH, `availableActions` returns an empty list for these apps, but ZIA accepts them with `ALLOW_AI_ML_WEB_USE` (verified live). An empty list is no longer treated as "no Allow"; an app is left out only when ZIA lists actions and Allow is not among them.

### 2.5.1
- **AI compliance profile** for AI Guard: HIPAA, HITRUST, PCI DSS, GDPR, CJIS, FERPA, SOX, NIST 800-171, NIST 800-53 or General. The default comes from the POV baseline.
  - It creates detection policy `<prefix>-AIG-Compliance` with prompt and response detectors and the profile's PII entities.
  - It creates policy control `<prefix>-AIG-Compliance-Apps` for the LLM providers of the apps sent to AI Guard, placed after the existing controls.
  - Monitor (the default) or Block per POV. Prompt injection, malicious URLs and hidden text are always blocked.
- **Allow in ZIA:** you pick the AI apps to allow above Block / Caution / Isolate rules.
  - `<prefix>-AIG-Allow-AI` (Cloud App Control, AI & ML, order 1). Apps are checked against ZIA's available actions first.
  - When a URL rule would stop the apps, `<prefix>-AIG-Allow-URL` (a custom URL category and an Allow rule at order 1).
  - The dry run names the rules it overrides for those apps.
- **Fix:** the ZTH tier's `Caution-AI` URL rule targeted `OTHER_INFORMATION_TECHNOLOGY`, which also cautioned `*.cloud.microsoft`. It now targets `AI_ML_APPS`.
- **Restore** handles AI Guard objects (`/aiguard/v1`) as well as ZIA ones.
- **POV Tests:** added *AI compliance profile catches sensitive data* and *Sanctioned AI apps allowed*.
- **Verified live on ZTH:**
  - a policy create needs both detector lists
  - accepted detectors and actions
  - the order of policy controls
  - the full create, re-run, Monitor → Block and cleanup cycle

### 2.5.0
- **AI Guard** (a licensed SKU that needs ZIA):
  - It is a fourth product on *Build the POV*. Turning it on turns ZIA on; ZIA can run without it.
  - The guided step comes after Internet Access, and also has its own page under ZIA.
- **Checks:**
  - The AI Guard API is reachable (`GET /aiguard/v1/detections/policies`, the "zguard" check).
  - The Gen AI Security subscription (`ZS_DP_GEN_AI`).
  - The existing Proxy Chaining certificates, AI Guard proxies and gateways.
- **Builds:**
  - the AI Guard CA (upload a `.pem` or reuse)
  - the proxy (`forward.prod.zsaiguard.net:9443` by default, `forward.zseclipse.net` accepted)
  - a `DSTN_DOMAIN` wildcard group of the AI apps
  - a QUIC Block/ICMP firewall rule
  - an SSL **Inspect** rule at order 1, above every Do Not Decrypt rule (including *Office 365 One Click*)
  - Gen AI prompt capture for the chosen apps
  - a Proxy Chaining forwarding rule to the gateway
- **Manual gateway step:** proxy gateways are read-only in the API, so the gateway is shown as a *Manual step* with the portal settings, and the forwarding rule follows on the next run.
- **Reuse:** if ZIA already has an AI Guard proxy and gateway, choosing its certificate reuses them.
- **Records and follow-ups:**
  - Runs, the summary report, POV Tests (chain, Copilot, QUIC) and Restore include AI Guard.
  - The uploaded certificate is never logged and is kept in the POV only as "uploaded".
  - Follow-ups added: AI Guard portal settings, WebSocket inspection for Copilot, `NODE_EXTRA_CA_CERTS` for Claude Code.
- **Light theme:** green on white is the default; dark mode is a toggle in the sidebar.
- **About page:** the tool, the author (Steven Hajny, Zscaler Distinguished Sales Engineer, linkedin.com/in/stevenzhajny) and the version history.
- **Line icons** replace the emoji in the sidebar and on the product cards.
- **New API:** `GET /api/v2/aiguard/context`, `POST /api/v2/aiguard/plan`, `POST /api/v2/aiguard/apply`.

### 2.4.0
- **Active POVs** (sidebar): each POV is a local folder (`ZTP-Wizard/povs/<id>/pov.json`). It holds:
  - the plan
  - the exact resume point of the guided flow
  - every run (ledger, restore point)
  - test results and customer success criteria
  - the timeline (kickoff, check-ins, end), notes and follow-ups (the wizard adds its own).
- **Status:** moves on by itself (Planning → Built after the first apply → Testing after the first test result) and can be set by hand. A POV untouched for 7 days is flagged quiet.
- **POV home:** Overview, What the tool did, Tests & success criteria, Timeline & notes, with export, Save as template and Archive.
- **Tenant guard:**
  - A POV stores only its vanity domain and cloud.
  - Opening it while signed in to another tenant is refused.
  - When signed out, picking a POV pre-fills that tenant's sign-in.
- **No secrets are written:** credentials, provisioning keys, tamper / one-time passwords and tokens are scrubbed. A resumed POV gets a new tamper password and says so.
- **Saved templates** of a POV's choices (no customer, tenant, prefix, host names or secrets), and New POV from a template.
- **New API:**
  - `/api/v2/povs`: list, create, open, close, update, archive, export, import.
  - `/api/v2/pov-templates`.
  - On this computer, the POV list can be read before signing in.
- **Fix:** date fields follow the dark theme.

### 2.3.1
- **Private Access:** the application name, destinations and TCP / UDP ports are editable in the ZPA table, for preset apps and CSV uploads. Validation runs as you type. **+ Add application** adds a row by hand.
- **Layout:** the interface adapts to the window size:
  - The content column fills the window.
  - Wide tables scroll inside their card instead of spilling past it.
  - The ZPA table's fields shrink to fit.
  - Fields stack on narrow windows.
  - Checked at 1024, 1366 and 1920 px.

### 2.3.0
- **Guided POV:** Tenant readiness → Build the POV (ZIA / ZPA / ZDX) → Customer intake → Client Connector → Internet Access → Private Access → Digital Experience → one dry run and apply. The existing wizards run in guided mode.
- **Customer intake:** name, prefix (generated from the name, editable), internal domain (saved for ZPA), preset and baseline. The global prefix bar has been removed.
- **Presets:**
  - ZPA gets a `*.domain` wildcard plus Active Directory, file shares, intranet and an RDP jump host, then the vertical's apps.
  - ZDX gets apps for the market segment, plus Outlook Online.
  - New Education preset.
- **Licensing:** the whole tenant is compared with a fully licensed POV tenant.
  - Missing core licences are cautions; optional ones are info.
  - Trials ending within 21 days are flagged.
  - ZPA AppProtection / PRA flags are checked.
- **One Bulk Rule Manager** for ZIA, ZPA and ZDX, above Policy Catalog.

### 2.2.0
- **POV Start:**
  - Tenant readiness.
  - Customer intake with presets.
  - One dry run / one apply across the products in scope.
  - Live progress.
- **POV Tests:** a runbook with Pass / Fail / Skip, *Prove it* for URLs, and a synthetic DLP test kit.
- **Client Connector:** a Devices & Install page with one-time passwords and the Deployment Toolkit install builder (MSI / EXE / macOS parameters, `.bat` / `.command` scripts).
- **Private Access:**
  - access policy for everyone
  - Browser Access
  - POV isolation profile (copy / paste, upload / download, printing, watermark).
- **Restore & Drift:** snapshots of every ZIA / ZPA apply, restore after a dry run, and a drift check with before / after values.
- **Also:** field-level differences in dry runs, rate-limit countdowns with automatic retry, rule search / filter / shortcuts, and an update badge.

### 2.1.0
- **ZIA:**
  - The SSL inspect-remaining rule is always last (below *Zscaler Recommended Exemptions*) with TLS 1.2 minimum.
  - DoH is inspected, with risky lookups blocked.
  - DNS goes to the Zscaler Trusted Resolver.
  - SSH / RDP / FTP to and from high-risk countries is dropped.
- **ZPA:**
  - timeout policy
  - AppProtection inspection (OWASP CRS, tenant's current version)
  - browser isolation policy
  - optional PRA RDP / SSH consoles.
- **Client Connector:** a tamper protection password for logout, exit, uninstall and turning off ZIA / ZPA / ZDX.
- **ZDX:** Teams, Zoom and Webex in the POV template (Zoom / Webex are skipped without a prefix).

### 2.0.0
- **Everywhere:**
  - A global prefix, with update-in-place re-runs.
  - A mandatory dry run (Create / Update / No change); an apply that doesn't match it is refused.
  - Automatic ZIA activation.
  - Licensing read from the tenant.
  - A summary report.
- **ZIA:**
  - Scope → Baseline Framework (9 compliance frameworks or Strict / Balanced / Permissive / Zero Trust Hospital) → Rules → Dry run → Apply.
  - DLP Monitor / Block with custom dictionaries, Endpoint DLP, Sandbox Standard / Advanced, AI Prompt Capture and UCaaS.
  - Granular Cloud App Control.
  - Isolate for Miscellaneous / Unknown.
  - ATP defaults.
- **Client Connector:**
  - Predefined bypass apps read live.
  - VPN / IP / DNS lists validated.
  - ZPA reauthentication on.
  - Two IPv6 switches.
- **ZPA (new):** a wizard creating the connector group, provisioning key, segment and server groups, and application segment(s). Optional CSV bulk upload.
- **Bulk managers** for ZPA and ZDX.
- **Standalone builds** for Windows x64, macOS Apple silicon and macOS Intel.

### Fixed during live testing (2.x)
- **ZIA:**
  - ZIA API sessions that end before the token are renewed.
  - A failed rule gives back its order.
  - Timed-out reads and writes are retried once.
  - Descriptions are clamped to 255 bytes.
  - Cloud App Control actions and Cloud Sandbox file types match what ZIA accepts.
  - DNS gateway redirects use `REDIR_REQ_KEEP_SENDER`.
- **ZCC:**
  - A domain in an IP list is refused in the dry run.
  - Re-runs report No change correctly.
  - Rate-limit waits are capped with a clear message.
- **ZPA:**
  - Subnet + Continuous health checks are refused in the dry run.
  - Policy rules are read through `/policySet/rules/policyType/…` (no duplicates on re-run).
  - Inspection profiles use the tenant's current OWASP version.
  - Isolation profiles are created through the Cloud Browser Isolation API.
- **Standalone:** the first Mac build crashed at start because of the build machine's log folder.

## v1.9.0 — 2026-10-14

### ✨ New
- **Rules step (was Allow / Block):** every rule in every ZIA policy type has an on/off switch, with *All on / All off* per type. Switched-off rules are not created, and the plan lists them.
- **Isolate for URL rules:** next to Allow / Block, any URL rule can be set to Isolate (Cloud Browser Isolation).
- **Isolation profile picker** on Customize. It defaults to the tenant's Default Isolation Profile; **↻ Refresh** loads profiles created later in the Isolation portal. It is used by Isolate rules and Sandbox *Quarantine & Isolate*. 1.8 picked a profile on its own, through an endpoint that returns 404, so Quarantine & Isolate always fell back to Quarantine.
- **SSL interception certificate picker** on Customize, for the Inspect rules the run creates. The list comes from the tenant's intermediate CA certificates, plus certificates already used by rules, plus manual ID entry.
- **SSL Certificate Manager** (new ZIA page): shows each SSL rule's certificate. Select rules, preview, then move them between certificates in bulk and activate.
- **Frameworks:**
  - *Save framework* downloads `.ztp-framework.json`.
  - *Load a saved framework* applies it in another tenant; isolation profile and certificate are matched by name.
  - *Capture this tenant's policies* reads the tenant's rules (URL with custom categories, Firewall, SSL, Sandbox, DNS, File Type) into a framework (read-only).

### 🐛 Fixed (found on live tenants)
- Rule names longer than 31 characters were rejected; names are now shortened.
- A URL category the tenant doesn't have failed the whole rule; missing categories are now left out with a warning.
- Deprecated firewall network applications were rejected ("Deprecated network applications are not allowed"); they are dropped, and a rule left with no applications is skipped rather than created as match-all.
- SSL rules failed with "Rule with rank 7 is not allowed at order 1"; they now go right after Zscaler's predefined rules, or at the end if the tenant refuses that spot.
- Sandbox rules failed with "ANY/NONE/null are not valid entries"; file types and protocols are now named explicitly.
- A Do Not Inspect rule left with no categories is skipped (it would have exempted all traffic).

## v1.8.2 — 2026-10-12

### 🐛 Fixed
- **ZDX wizard failed on brand-new ZDX tenants:** the dry run stopped with `Custom app "zscaler.com": collection — No "Custom Apps Collection" in this tenant`. A new ZDX tenant only has the *Unified Communication* and *Predefined Apps* collections; ZDX creates the *Custom Apps Collection* when the first custom app is added in the portal, and the API requires every custom app to belong to a collection. The wizard now plans a **ZDX tenant setup** step that creates the missing collection first (`POST /zdx/v1/config/collections`), then creates the apps in it. If the setup step fails, the apps are skipped so nothing half-built is left behind. The same applies to a missing *Predefined Apps Collection*. Verified live on a fresh tenant.

## v1.8.1 — 2026-10-12

### 🐛 Fixed
- **macOS profiles failed on every tenant except ZTH:** creating a macOS app profile, and with it the forwarding profile created in the same run, failed on other tenants. The macOS *Zscaler POV Best Practice* template set notification template ID 2221, which exists only in the ZTH lab tenant. ZCC rejects the whole profile (`{"success":"false"}`) when the ID doesn't exist, and the wizard then rolled back the new forwarding profile, so both looked broken. The setting is removed, and new macOS profiles keep the portal default (Legacy Notification Settings). The macOS template now has 16 settings. Reproduced and verified on a second tenant.

## v1.8.0 — 2026-10-12

### ✨ New: Digital Experience (ZDX) module
- **Set up probes:** a guided Template → Applications & Probes → Review → Dry Run → Apply flow, the same as the ZIA and Mobile Admin wizards.
- **Zscaler POV Best Practice template:** Microsoft Login (Zscaler predefined app) and zscaler.com (custom app), each with a Web probe and a CloudPath probe, for all users.
- **Predefined apps:** turn on any Zscaler-maintained app (Microsoft 365, Teams, SharePoint, OneDrive, Zoom, Okta, Box, Salesforce, ServiceNow, Webex). Apps not yet set up are created with the customer's tenant prefix, and ZDX adds its own probes.
- **Custom apps:** add any URL with a Web probe and an optional CloudPath probe; choose the interval and CloudPath protocol.
- **Dry run:** shows the tenant's current state and the exact steps in order; anything already on is skipped.
- **Apply:** reads every app and probe back to verify it, and removes a custom app again if any of its steps fail.
- **Manage apps & probes:** turn apps and probes on or off, delete custom apps and probes (name confirmation, CloudPath before Web).
- **API routes:** `/api/zdx/catalog`, `/api/zdx/dryrun`, `/api/zdx/apply`, `/api/zdx/overview`, plus app and probe activate / deactivate / delete.

Requires the ZDX scope on the OneAPI client.

## v1.7.1 — 2026-10-12

### Changed
- **Wording follows the Zscaler POV best practice guide:** the Mobile Admin create wizard is now titled *Create Zscaler Client Connector App Profile and Forwarding Profile* and describes what it builds as the common Mobile Admin settings for Client Connector.
- **Templates renamed:** the Best Practice templates (forwarding profile, Windows and macOS app profiles) are now called **Zscaler POV Best Practice**. No screen refers to the lab reference profiles any more.
- **Steps explain the concepts:** the Forwarding Profile step explains what a forwarding profile is, and the App Profile step explains what an app profile is.
- **macOS creates its own forwarding profile:** macOS now also defaults to creating a new forwarding profile instead of linking an existing one named "MAC", so it works the same on any tenant.
- **Notification template flagged:** the macOS notification template setting (ID 2221) is marked **REVIEW**, because template IDs differ per tenant.

## v1.7.0 — 2026-10-11

This release covers everything since **v1.5.2**: the Allow / Block step for ZIA policies (v1.6.0), and a Mobile Admin (Zscaler Client Connector) wizard that creates forwarding profiles and Windows / macOS app profiles from best-practice templates (v1.6.0 – v1.7.0). Every ZCC write path was verified against a live tenant.

### Upgrade
1. Stop the running wizard.
2. Pull this release (or download the source zip) over your existing folder. Your `logs/` folder is kept.
3. Run `npm start`, then hard-refresh the browser (Ctrl+Shift+R). The header should show **v1.7.0**.

No new dependencies.

---

### ✨ New

#### Mobile Admin: create a forwarding profile first, then the app profile (v1.7.0)
- **The create flow is now:** Platform → **Forwarding Profile** → App Profile → Customize → Review → Dry Run → Apply. The forwarding profile comes first because every app profile has to point at one.
- **New or existing:** on the forwarding step you can **create a new forwarding profile** or **link an existing one**.
  - Windows defaults to creating a new one.
  - macOS defaults to the existing **MAC** forwarding profile.
- **Best Practice forwarding template:** built from the reference **"Windows"** forwarding profile. It has 8 settings, each of which can be switched off:
  - ZIA: Tunnel on every network type (On-Trusted, VPN-Trusted, Off-Trusted, Split VPN-Trusted). The portal default is Tunnel with Local Proxy.
  - Redirect web traffic to the Client Connector listening proxy.
  - Use Z-Tunnel 2.0 for proxied web traffic.
  - Drop IPv6 traffic, including on IPv6-only networks. Flagged **REVIEW**.
  - Latency-based ZEN selection.
  - No automatic configuration script (PAC) in the system proxy.
  - ZPA: Tunnel on VPN-Trusted networks.
  - ZPA latency-based server selection.
- **Portal Default (blank) forwarding template:** creates exactly what the portal creates with defaults.
- **What Apply does:**
  1. Creates the forwarding profile and reads back every setting.
  2. Creates the app profile, links it to the new forwarding profile and confirms the link.
  3. If the app profile fails, deletes the new forwarding profile again, so a failed run leaves nothing behind.
- **Dry run and review show both profiles:** the dry run lists separate pre-flight checks for each (name valid, name not already used, template) and the create order. Review shows both profiles and every setting with its portal default.
- **Delete forwarding profiles** from *Edit existing profiles*. The delete is refused while any Windows or macOS app profile still uses the forwarding profile.

#### Mobile Admin: macOS app profiles (v1.6.1)
- **Platform picker:** choose Windows or macOS in the create wizard.
- **macOS Best Practice template:** built from the reference **MAC** app profile. It has 17 settings:
  - SSL certificate, block iCloud Private Relay, fail-close on tunnel exit off.
  - Recommended PAC URL, domain inclusions `*`, prioritize DNS exclusions off.
  - Flow-based tunnel, reconnect on wake.
  - Teams / Zoom / Windows 365-AVD IP bypass.
  - Notification framework, switch focus to notifications, notification template.
  - Re-enable Internet Security after 60 minutes.
  - Modern UI.
  - Local packet capture on, extra automatic packet capture settings off.
  - Applies to all users.
- **Manual settings:** settings the public API does not accept are marked **MANUAL**. Today that is macOS *Modern UI*. After create, the wizard tells you exactly what to set in the portal.
- **macOS profiles listed for delete** in *Edit existing profiles*.

#### Mobile Admin: create Windows app profiles from a template (v1.6.0)
- **New flow:** *Create from template* follows the same Template → Customize → Review → Dry Run → Apply flow as the ZIA wizard.
- **Windows Best Practice template:** built from the reference **PerfectPolicy** app profile. It has 12 settings:
  - SSL certificate, WFP driver, Zscaler CLI.
  - Prioritize IPv4, parallel IPv4/IPv6 setting.
  - Domain profile detection, domain inclusions `*`.
  - Microsoft 365 / Teams / Zoom / SharePoint / Exchange / Windows 365-AVD IP bypass.
  - Notification framework, switch focus to notifications.
  - ZPA re-authentication notice 30 minutes before expiry.
  - Applies to all users.
- **Portal Default (blank) app profile template:** creates exactly what the portal creates with defaults.
- **Customize:** set the name and description, choose whether the profile is enabled after creation (off by default), and switch each template setting on or off.
- **Review:** every setting with its new value, the portal default, and what it does.
- **Dry run** (read-only):
  - Checks the name is valid and not already used.
  - Checks the forwarding profile exists.
  - Checks the bypass app definitions exist in your tenant.
  - Shows where the new profile lands in the rule order, directly above Default.
- **Apply:** creates the profile, reads it back and verifies every setting. Logged as `ZCC_DRY_RUN` / `ZCC_APPLY` in the audit log.
- **Delete app profiles** from *Edit existing profiles*. You have to confirm the exact profile name, and Default is protected.

#### ZIA: Allow / Block step (v1.6.0)
- **New step after Customize:** choose **Tier default / Allow all / Block all** for each policy type: URL Filtering, Cloud Firewall, DNS, File Type Control, Cloud App Control and DLP.
- **Per-rule overrides:** expand a policy type to flip individual rules between Allow and Block.
- **Weakening warnings:** rules set to Allow that the tier would restrict are flagged **WEAKENED** in Review and in the Dry Run, and logged as `ACTION_OVERRIDES` at apply time.
- **Locked baseline rules:** `ZTP-Allow-Web` and `ZTP-Allow-NTP` are locked, so baseline internet access can't be blocked by accident.

#### New API routes
| Method | Route | Purpose |
|---|---|---|
| GET | `/api/zcc/fwd-templates` | Forwarding profile templates |
| POST | `/api/zcc/forwarding-profiles/dryrun` | Plan a forwarding profile (read-only) |
| POST | `/api/zcc/forwarding-profiles` | Create + verify a forwarding profile |
| DELETE | `/api/zcc/forwarding-profiles/:id?confirmName=` | Delete (refused while in use) |
| GET | `/api/zcc/templates/:platform` | App profile templates (`windows` / `macos`) |
| GET | `/api/zcc/app-profiles/:platform` | List app profiles for a platform |
| POST | `/api/zcc/app-profiles/:platform/dryrun` | Plan an app profile (and optional new forwarding profile) |
| POST | `/api/zcc/app-profiles/:platform` | Create + verify (forwarding profile first when `newForwardingProfile` is set) |
| DELETE | `/api/zcc/app-profiles/:id?confirmName=&platform=` | Delete an app profile |

---

### 🐛 Fixed
- **App profile PATCH was rejected:** *Edit existing profiles* sent flat keys, and ZCC answered HTTP 400 "No valid fields". It now sends settings nested in `policyExtension` with the required `policyId` and `deviceType`.
- **Silent ZCC failures were reported as success:** ZCC write endpoints answer HTTP 200 with `{"success":"false"}` when they reject a body. All ZCC writes now check this and show a real error:
  - app profile create, update, PATCH, activate and delete
  - forwarding profile edit, create and delete
- **App profile create never worked:** minimal or SDK-shaped create bodies were always rejected. Creates now send the full body the Mobile Admin portal sends, captured from the console for Windows and macOS.
- **Forwarding profile create returned HTTP 400:** ZCC only creates when the body carries `id: "-1"`. The client now sends it.
- **Linked forwarding profile was read from the wrong field:** ZCC returns the link as `onNetPolicy`, not `forwardingProfileId`. The app profile list, verification and the in-use check now read `onNetPolicy`.
- **Alert banners cut off bold text:** banners with bold words wrapped badly. They now render correctly.

### ⚠️ Known limitations
- **macOS Modern UI can't be set through the API:** the public ZCC API ignores it on create, update and PATCH. The wizard marks it MANUAL and reminds you to set it in the portal.
- **Notification template ID is tenant-specific:** the macOS template uses ID 2221 from the reference tenant. Change it, or switch the setting off, for other tenants.
- **Reference profile IDs come from the ZTH lab tenant:** PerfectPolicy, MAC, "Windows" forwarding profile and the MAC forwarding profile (39325). Templates are matched by setting, not by ID. The only ID-based link is the recommended MAC forwarding profile, which falls back to matching by name.

## Earlier releases

See the Version History table in README.md for v1.5.2 and earlier.
