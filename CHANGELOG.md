# Changelog

## v2.3.1 — 2026-10-20

### Private Access
- **Editable application table:** each row in the ZPA application table now has editable fields for:
  - the application name
  - destinations (FQDN, `*.domain`, IP or CIDR)
  - TCP ports
  - UDP ports
- This applies to applications from a preset and from an uploaded CSV. The segment name updates as you type, and mistakes are flagged immediately and block *Next* until fixed.
- **+ Add application** adds a row by hand.

## v2.3.0 — 2026-10-20

POV Start is now a guided flow, one step at a time.

### Guided POV (POV Start)
- **Steps, in order:** Tenant readiness → Build the POV → Customer intake → Client Connector → Internet Access → Private Access → Digital Experience → Dry run & apply.
  - A stepper at the top shows where you are. Only one step is on screen at a time; earlier steps stay clickable and keep what you entered.
  - Steps for products that are not in scope are left out.
- **Build the POV:** pick what is in scope: Zscaler Internet Access, Zscaler Private Access and Zscaler Digital Experience. Client Connector is set up first whenever Internet Access or Private Access is in scope.
- **Customer intake:** customer name, prefix, internal domain, preset and baseline policies.
  - The prefix is generated from the customer name and can be edited.
  - The internal domain is saved for Private Access.
- **Client Connector:** the existing forwarding and app profile wizard, guided. The review step saves the profile for the final dry run. *Save and also set up macOS / Windows* covers both platforms; *Skip Client Connector* leaves it out.
- **Internet Access:** the existing scope → baseline → rules flow, with the baseline from the intake preselected. All the rule toggles work as before.
- **Private Access:** the existing ZPA wizard, pre-filled from the preset, with:
  - a wildcard segment for `*.<internal domain>`
  - common apps found in every vertical: Active Directory, file shares, intranet and a remote desktop jump host
  - the vertical's own apps (Healthcare: Epic, Imprivata, PACS, Cerner).
- **Digital Experience:** the existing ZDX wizard, pre-filled with apps for the market segment:
  - Healthcare: UpToDate, Epic UserWeb, Doximity
  - Financial services: Bloomberg, Workday, DocuSign
  - General enterprise: Salesforce, Workday, DocuSign
  - Education: Canvas, Google Classroom, PowerSchool
  - Outlook Online is added for every segment, on top of the Microsoft Login, Teams, Zoom and Webex probes the template already includes.
- **Dry run & apply:** one dry run starts automatically for everything the steps collected. One apply follows, with live progress. Each product has an *Edit* button that goes back to its step.
- **New preset:** Education.

### Tenant readiness: licensing
- Checks the whole tenant's subscriptions against a fully licensed POV tenant.
- **Missing core licences are cautions:**
  - URL Filtering, Cloud App Control, SSL Inspection, Advanced Threat Protection, Antivirus
  - Cloud Sandbox, web DLP, Cloud Firewall, DNS Security, Client Connector, Cloud Browser Isolation
- **Missing optional licences are listed for information:**
  - Advanced Cloud Firewall, IPS, CASB, Gen AI security, EDM / IDM, Bandwidth Control, Deception, log streaming, Z-API
- Also flagged:
  - subscriptions that end within 21 days
  - ZPA tenants without AppProtection (inspection) or Privileged Remote Access

### Navigation
- **The global prefix bar is gone.** The prefix comes from the customer intake. Product modules show which prefix they use, and point to POV Start when there is none yet.
- **Bulk Rule Manager** is one sidebar item above Policy Catalog, with tabs for ZIA, ZPA and ZDX. It replaces the per-product Bulk Manager sub-items.

## v2.2.0 — 2026-10-19

Faster POV kick-off and more to show once the POV is running.

### POV Start (new, first page after sign-in)
- **Tenant readiness:** read-only checks right after sign-in, so blockers show up before the customer sees them:
  - ZIA pending changes, SSL rules placed above *Zscaler Recommended Exemptions*, isolation profiles, the Zscaler Trusted Resolver, identity-provider groups and licensing.
  - ZPA App Connectors online, PRA portal, web certificates and ZPA isolation profiles.
  - Client Connector enrolled devices and ZDX reachability.
- **Customer intake:** customer name, internal domain, preset (Healthcare, General enterprise, Financial services, or empty), VPN gateways, private applications and ZDX web apps.
  - The Healthcare preset fills Epic Hyperspace and Interconnect, Imprivata, PACS, Cerner and the intranet for the customer's domain, with HIPAA as the baseline.
  - The prefix is suggested from the customer name.
- **One dry run, one apply** across the products in scope:
  - Product toggles: Client Connector (Windows, macOS), Internet Access, Private Access, Digital Experience.
  - Runs in order: Client Connector → Internet Access → Private Access → ZDX.
  - A product whose dry run fails is skipped; the others still apply.
- **Live progress:** each object appears as it is created or updated, instead of a spinner until the end.

### POV Tests (new)
- **Runbook:** one test for each policy created in this session, covering about 25 policy areas. Each test has its steps, the expected result and Pass / Fail / Skip with a note. Results go into the summary report, and the runbook downloads as Markdown.
- **Prove it:** for a URL, shows its categories and the first URL Filtering rule that matches, plus the Z-Insights totals for the last hour.
  - API clients can't read individual log lines (Zscaler refuses client-credential tokens for that), so the page points to Web Insights › Logs for the exact transaction.
- **DLP test kit:** three synthetic, clearly labelled files:
  - PHI with MRN, Medicare MBI and ICD-10 codes.
  - Card-network test card numbers.
  - Social Security numbers.

### Client Connector
- **Devices & Install** (new page):
  - Lists enrolled devices and issues **one-time passwords** per device. One-time passwords are shown on screen only and never logged.
  - The **install builder** comes from the ZTP Deployment Toolkit's Client Connector installer. It covers every documented MSI, EXE and macOS parameter with validation (cloud name, strict enforcement requirements, Business Continuity pairs and more).
  - The policy token is picked from the tenant's app profiles.
  - It builds the masked command and a ready-to-run script: `.bat` for Windows, `.command` for macOS.

### Private Access
- **Access policy** for everyone signed in to ZPA, covering the wizard's segments, Browser Access and PRA apps. It's on by default, so the first call works end to end.
- **Browser Access** (optional): publish one internal web app with no client, using a web certificate picked from the tenant. The wizard warns when the certificate does not cover the domain.
- **POV isolation profile:** copy / paste, upload / download, printing and watermark, set in the wizard and used by the ZPA isolation policy. It is created through the Cloud Browser Isolation API and appears as a ZPA isolation profile.

### Refining the process
- **Restore:** every ZIA and ZPA apply saves a snapshot of what it changed (no secrets) next to the logs. Restore deletes what the run created and puts back what it updated, newest first, then activates ZIA. A dry run is required first.
- **Drift check:** re-plans the last applied runs and lists anything changed or deleted since, with before / after values.
- **Field-level differences:** dry runs show the old and new value for every changed field, not just the field name.
- **Client Connector / ZDX rate limits:** about 100 calls per hour are counted and shown. When Zscaler asks the wizard to wait, a countdown appears and POV Start retries the step on its own.

### Interface
- **Rule review:** search, *Changed from default* filter, Expand all / Collapse all, and keyboard shortcuts (`/` search, `E` expand, `C` collapse, `Esc` clear).
- **Update check:** a badge in the header when a newer version is on GitHub.

## v2.1.0 — 2026-10-19

More policies are built into the existing templates, so each one can be shown during a POV. They are ordinary template rules, on by default like the others, with plain names and descriptions.

### Zscaler Internet Access
- **SSL inspection order:** the catch-all rule that inspects all remaining traffic (Strict *Inspect-All*, Balanced *Inspect-Remaining*, Zero Trust Hospital *Catch-All*, Permissive *No-Inspection*) is now always placed **last**, below Zscaler's predefined rules. Before, it could land above *Zscaler Recommended Exemptions* and override it. A catch-all left in the wrong place by an earlier run is moved to the bottom on the next run, and the dry run shows the move. The bypass rules (Health, Finance) still go right after the predefined rules.
- **Minimum TLS 1.2** on the inspect-remaining rule (Strict and Balanced; Zero Trust Hospital already had it).
- **DNS over HTTPS is inspected** (`<prefix>-DNS-DoH-Block-Risky`): DoH lookups of newly registered or revived domains, dynamic DNS and spyware domains are blocked. Other DoH lookups resolve and are logged, so 1.1.1.1/help still works. The Cloud App Control *Block-DoH* rule is now off by default; turn it on to block DoH apps outright instead.
- **DNS resolver control** (`<prefix>-DNS-Trusted-Resolver`): DNS sent to any resolver (for example 8.8.8.8) is answered by the Zscaler Trusted Resolver. The ZPA resolver rules above it still apply. This rule can't be flipped to Block by the Allow / Block all buttons.
- **High-risk countries** (`<prefix>-FW-Geo-Block-Out` / `-In`): SSH, RDP and FTP to and from China, Russia, North Korea and Iran are dropped. These rules sit above the rule that allows SSH and RDP.
- Cloud Sandbox *Office / PDF* keeps **Quarantine & Isolate** with the tenant's isolation profile (confirmed live). The report now reminds you to set copy/paste, upload/download and watermark controls in that isolation profile.

### Zscaler Private Access
New, on by default for the wizard's application segment(s), wildcard or bulk:
- **Timeout policy** (`<prefix>-timeout-policy`): re-authenticate every 8 hours, or after 1 hour idle.
- **AppProtection inspection:** an OWASP Core Rule Set profile (`<prefix>-inspection-profile`, paranoia level 1, all predefined controls) and an INSPECT rule (`<prefix>-inspection-policy`).
- **Browser isolation** (`<prefix>-isolation-policy`): Browser Access users get an isolated session, using the tenant's default ZPA isolation profile.
- **Privileged Remote Access (optional):** enter an RDP and/or SSH server. The wizard creates the PRA application (`<prefix>-pra-rdp` / `-pra-ssh`) and a console in the tenant's existing PRA portal. When the tenant has no portal, creating one (domain and certificate) is listed as a manual step.
- The ZPA bulk manager also lists and deletes these policy rules, the inspection profile and the PRA consoles, in dependency order.

### Zscaler Client Connector
- **Tamper protection passwords** (Windows and macOS Best Practice): one password protects logout, exit and uninstall, and turning off ZIA, ZPA or ZDX. The wizard generates it in your browser (masked, with Show / Copy / Generate new). It is checked on read-back and listed in the summary report, which is then marked sensitive. It is never written to logs. The report also explains how to issue one-time passwords per device.

### Zscaler Digital Experience
- The **Zscaler POV Best Practice** template adds Microsoft Teams, Zoom and Webex. Zoom and Webex need the customer's account prefix; left blank, they are skipped with a note instead of failing the run.

## v2.0.0 — 2026-10-19

Implements the *Policy Wizard 2.0 Requirements Specification* plus the review feedback below. Live-tested end to end on a Zscaler tenant (ZIA, ZCC Windows and macOS, ZPA): every run creates, re-runs, updates and cleans up its objects.

### Everywhere
- **Global prefix** (GLB-02): set once after sign-in, it names every object the wizard creates. Running again with the same prefix **updates** objects instead of duplicating them, across ZIA, ZCC and ZPA (GLB-05).
- **Mandatory dry run** (GLB-03): the server refuses an apply that doesn't match a dry run of exactly the same choices. Each object is listed as Create / Update / No change, and the apply does exactly that.
- **Automatic ZIA activation** (GLB-04). One failed object never stops the rest: failures are listed with their reason, and anything that depends on them is skipped.
- **Licensing detection** (GLB-08): features the tenant isn't licensed for are greyed out.
- **Summary report** (GLB-07): Markdown and printable HTML, marked *sensitive* when it holds a ZPA provisioning key.
- **No secrets in logs** (GLB-09): request bodies are redacted, and the provisioning key is never logged.
- **Sidebar in POV order:** Zscaler Client Connector → Zscaler Internet Access → Zscaler Private Access → Zscaler Digital Experience → Summary Report.

### Zscaler Internet Access
- Renamed from "ZIA POV Policy Wizard" to **Zscaler Internet Access**.
- **Scope screen** (§1), then a **Baseline Framework** step (§2):
  - Compliance baselines: HIPAA, HITRUST, NIST 800-53, NIST 800-171, PCI DSS, CJIS, SOX, FERPA, GDPR.
  - Non-mapped baselines: Strict, Balanced, Permissive, Zero Trust Hospital.
  - Each framework is a data file with cited sources.
- **Rule review:** Select / Deselect all and Allow / Block all, per category and for the whole page. Isolate is available for URL rules. Choices persist across Back / Next. Selections can be saved and loaded.
- **New policy areas:**
  - **Inline DLP Monitor:** Zscaler's predefined engines.
  - **Inline DLP Block:** custom dictionaries (ICD-10, MBI, MRN and others, with cited sources) and custom engines.
  - **Endpoint DLP:** USB, personal cloud storage and printing.
  - **Cloud Sandbox:** Standard and Advanced tiers. AI Instant Verdict on every Advanced rule.
  - **AI Prompt Capture:** 14 GenAI apps.
  - **ATP defaults.**
- **UCaaS:** Zoom, GoTo, RingCentral, Webex and Talkdesk are their own settings group, enabled on every Zscaler Internet Access run and shown on the rule review page.
- **Granular Cloud App Control:** app-specific rules sit above the category-wide rules, with app IDs and actions read live from the tenant:
  - Google Drive, Dropbox and Box: view-only.
  - Facebook and X: view but no posting.
  - LinkedIn: read-only.
  - ChatGPT, Gemini and Copilot: allowed, but no file uploads.
  - Slack: chat but no file uploads.
  If a tenant refuses the first action set, the wizard uses a fallback set, and re-runs accept either.
- **Isolate Miscellaneous / Unknown:** a URL rule opens these categories in Cloud Browser Isolation with the tenant's profile, and falls back to Caution when the tenant has none. Those categories were removed from the Security-Risk block rule.
- **Cloud Sandbox file types:** groups list only types the sandbox accepts. JavaScript, IMG, LNK, GZIP, text, CSV and image types are rejected by ZIA for sandbox rules, and DMG needs Sandbox macOS.

### Zscaler Client Connector
- The predefined IP-based bypass apps are read live and shown directly under the *Bypass IP-based Applications* switch, behind a warning.
- New inputs for **VPN Gateway Bypasses, IP Inclusions / Exclusions and DNS Inclusions / Exclusions**, validated before anything is sent. IP lists take an IP address or CIDR only.
- **ZPA reauthentication** is on by default, stored in `policyExtension` on Windows and macOS.
- **Two IPv6 switches** in the forwarding profile: *Drop IPv6 Traffic (dual-stack networks)* and *Drop IPv6 Traffic in IPv6-only networks*.
- Same-name profiles are updated in place; customer profiles and Default are never overwritten.

### Zscaler Private Access (new)
- **Wizard:** App Connector Group (San Jose, CA) → Provisioning Key (max 5; masked, with reveal and copy) → Segment Group → Server Group (dynamic discovery) → Application Segment, with the recommended defaults.
- **CSV bulk upload of application segments** (optional): columns Application Name, Destinations, Ports. Separate several values with `;`, and write UDP ports as `udp:53`. The screen offers a template download, per-application settings overrides and row-numbered validation. Each application becomes `<prefix>-<name>`, in place of the wildcard segment.
- **Bulk Manager:** deletes prefixed objects in dependency order.

### Zscaler Digital Experience
- **Bulk Manager** for prefixed custom apps and collections.

### Standalone builds
- Windows x64, macOS Apple silicon and macOS Intel. Logs go to `ZTP-Wizard/logs` in the home folder.

### Found and fixed during live testing
- **ZIA:**
  - The ZIA API session can end before the OAuth token does (403 "Resource Access Blocked"); the client signs in again and retries.
  - A failed rule create gives back its rule order, so later rules don't fail with "not allowed at order N".
  - A timed-out GET or PUT is retried once.
  - Descriptions are clamped to 255 bytes (DLP dictionaries).
  - Cloud App Control: Caution needs browsers named. Category-wide rules accept web-use actions only.
- **ZCC:**
  - A domain name in an IP list makes ZCC reject the whole app profile. The dry run now refuses it; this deviates from ZCC-08.
  - Re-runs compare bypass apps with the apps that were picked, so they report No change.
  - The Mobile Admin page could show a render error when the bypass-app list arrived early.
  - Long rate-limit waits are capped with a clear message (about 100 calls per hour for ZCC and ZDX).
- **ZPA:**
  - Continuous health checks aren't allowed on subnet destinations; the dry run refuses them.
  - Re-runs no longer report a false update.
- **Standalone:** the first Mac build crashed at start because it tried to create the build machine's log folder.

### Not live-tested
- Endpoint DLP rule creation. The test tenant isn't licensed, and the wizard correctly reports it as not licensed.

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
