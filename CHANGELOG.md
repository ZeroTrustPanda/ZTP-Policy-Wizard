# Changelog

## v1.7.1-standalone — 2026-10-12 (branch `standalone`)

- Standalone downloads rebuilt as **1.7.1** with the Zscaler POV best practice wording below. No other changes.

## v1.7.1 — 2026-10-12

### Changed
- **Wording follows the Zscaler POV best practice guide:** the Mobile Admin create wizard is now titled *Create Zscaler Client Connector App Profile and Forwarding Profile* and describes what it builds as the common Mobile Admin settings for Client Connector.
- **Templates renamed:** the Best Practice templates (forwarding profile, Windows and macOS app profiles) are now called **Zscaler POV Best Practice**. No screen refers to the lab reference profiles any more.
- **Steps explain the concepts:** the Forwarding Profile step explains what a forwarding profile is, and the App Profile step explains what an app profile is.
- **macOS creates its own forwarding profile:** macOS now also defaults to creating a new forwarding profile instead of linking an existing one named "MAC", so it works the same on any tenant.
- **Notification template flagged:** the macOS notification template setting (ID 2221) is marked **REVIEW**, because template IDs differ per tenant.

## v1.7.0-standalone — 2026-10-12 (branch `standalone`)

Same features as v1.7.0, packaged to run without Node.js or npm.

- **Single executables** for Windows x64, macOS Apple Silicon and macOS Intel (`standalone/release/`), built with Bun.
- **UI compiled ahead of time:** React, ReactDOM and the IBM Plex fonts are embedded; no cdnjs, no in-browser Babel, no Google Fonts. Faster page load and works where CDNs are blocked.
- **Launcher:** binds to `127.0.0.1` only, picks port 3000 or the next free one, opens the default browser, logs to `~/ZTP-Wizard/logs`.
- **Fewer dependencies:** `uuid` and `cors` removed (built-in `crypto.randomUUID`, same-origin UI). Express is the only runtime package and is bundled into the executable.
- **macOS builds re-signed ad-hoc** so Apple Silicon runs them; they are not Developer ID signed or notarized.
- Server mode (`npm start`) is unchanged apart from the dependency cleanup; `ZTP_LOG_DIR` can move the log folder.

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
