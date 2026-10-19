/**
 * Zscaler Client Connector install parameters, validation and command / script builders.
 * Ported from the ZTP Zscaler Deployment Toolkit 2.0.0 (ZCC Install Helper merge).
 * Windows: MSI (PROPERTY=value) and EXE (--name value) forms; macOS: installbuilder.sh --name value.
 * Secrets (anything with "password" in the name) are masked in every displayed command and in scripts' echo lines.
 */
'use strict';
var VALID_CLOUD_NAMES = ['zscaler', 'zscalertwo', 'zscalerthree', 'zscloud', 'zscalerbeta', 'zscalerten', 'zscalergov'],
  WIN_PARAMETERS = [
    {
      msi: 'USERDOMAIN',
      exe: 'userDomain',
      type: 'text',
      cat: 'Core Enrollment',
      ph: 'e.g. safemarch.com',
      desc: 'Organization domain for SSO redirect and IWA silent enrollment. Enter the exact domain from your SAML NameID field.',
    },
    {
      msi: 'CLOUDNAME',
      exe: 'cloudName',
      type: 'text',
      cat: 'Core Enrollment',
      ph: 'e.g. zscaler, zscalertwo, zscloud',
      desc: 'Zscaler cloud name. Do NOT include .net. Required with STRICTENFORCEMENT.',
    },
    {
      msi: 'POLICYTOKEN',
      exe: 'policyToken',
      type: 'text',
      cat: 'Core Enrollment',
      ph: 'e.g. 123456677754',
      desc: 'App profile policy applied before enrollment. Required with STRICTENFORCEMENT. Also required for machine tunnel + ZPA pre-login access.',
      fromTenant: 'policyToken',
    },
    {
      msi: 'DEVICETOKEN',
      exe: 'deviceToken',
      type: 'text',
      cat: 'Core Enrollment',
      ph: 'e.g. 123456677754',
      desc: 'Device token when using ZCC Portal as IdP (ZIA only). Generate the token in ZCC Portal before use.',
    },
    {
      msi: 'UNAME',
      exe: 'userName',
      type: 'text',
      cat: 'Core Enrollment',
      ph: 'e.g. j.doe (no domain suffix)',
      desc: 'Username for enrollment. Supports MDM macros. Requires USERDOMAIN.',
    },
    {
      msi: 'EXTERNALDEVICEID',
      exe: 'externalDeviceId',
      type: 'text',
      cat: 'Core Enrollment',
      ph: 'e.g. 123456677754 or MDM macro',
      desc: 'Associates MDM device record with ZCC Portal. Not supported on ZCC v4.0 and earlier.',
    },
    {
      msi: 'STRICTENFORCEMENT',
      exe: 'strictEnforcement',
      type: 'toggle',
      cat: 'Enforcement & Security',
      desc: 'Block internet until user enrolls. Requires CLOUDNAME + POLICYTOKEN.',
    },
    {
      msi: 'ENABLEANTITAMPERING',
      exe: 'enableAntiTampering',
      type: 'toggle',
      cat: 'Enforcement & Security',
      desc: 'Prevent users from stopping or modifying Zscaler services.',
    },
    {
      msi: 'ENABLEFIPS',
      exe: 'enableFips',
      type: 'toggle',
      cat: 'Enforcement & Security',
      desc: 'Use FIPS-compliant libraries. Enable only if your org requires FIPS.',
    },
    {
      msi: 'MTAUTHREQUIRED',
      exe: 'mtAuthRequired',
      type: 'toggle',
      cat: 'Enforcement & Security',
      desc: 'Require IdP auth before machine tunnel starts (ZPA machine tunnel only).',
    },
    {
      msi: 'HIDEAPPUIONLAUNCH',
      exe: 'hideAppUIOnLaunch',
      type: 'toggle',
      cat: 'UI & Behavior',
      desc: 'Keep app window hidden before enrollment. Disable for Citrix + Strict Enforcement.',
    },
    {
      msi: 'LAUNCHTRAY',
      exe: 'launchTray',
      type: 'toggle_on',
      cat: 'UI & Behavior',
      desc: 'Auto-start ZCC after install (default ON). Toggle OFF to suppress auto-start.',
    },
    {
      msi: 'EXTERNALREDIRECT',
      exe: 'externalRedirect',
      type: 'toggle',
      cat: 'UI & Behavior',
      desc: 'Use system browser for authentication instead of embedded view.',
    },
    {
      msi: 'CONFIGTIMEOUT',
      exe: 'configTimeout',
      type: 'text',
      cat: 'UI & Behavior',
      ph: 'Seconds, e.g. 300 (default: 0)',
      desc: 'Seconds to wait for config file. Useful for VDI where config delivery is delayed.',
    },
    {
      msi: 'INSTALLLWFDRIVER',
      exe: 'installLWFDriver',
      type: 'toggle',
      cat: 'Driver & Networking',
      desc: 'Install NDIS 6 Lightweight Filter driver. Recommended for VDI / high-performance.',
    },
    {
      msi: 'USELWFDRIVER',
      exe: 'useLWFDriver',
      type: 'toggle',
      cat: 'Driver & Networking',
      desc: 'Enable packet-filter driver. Overrides Tunnel Driver Type in forwarding profiles.',
    },
    {
      msi: 'LWFBOOTSTART',
      exe: 'LWFBootStart',
      type: 'toggle',
      cat: 'Driver & Networking',
      desc: 'Set LWF driver start type to Boot so it loads before user login.',
    },
    {
      msi: 'REINSTALLDRIVER',
      exe: 'reinstallDriver',
      type: 'toggle',
      cat: 'Driver & Networking',
      desc: 'Force reinstall of network driver even if already present.',
    },
    {
      msi: 'ENABLECUSTOMPROXYDETECTION',
      exe: 'enableCustomProxyDetection',
      type: 'toggle',
      cat: 'Driver & Networking',
      desc: 'Parse PAC file directly for proxy detection instead of Microsoft APIs.',
    },
    { msi: 'VDI', exe: 'vdi', type: 'toggle', cat: 'VDI & Special', desc: 'Flag install as VDI (Citrix, Horizon, AVD, etc.).' },
    {
      msi: 'ENABLEIMPRIVATAINTEGRATION',
      exe: 'enableImprivataIntegration',
      type: 'toggle',
      cat: 'VDI & Special',
      desc: 'Enable Imprivata OneSign silent login integration. ZCC v4.4+ Windows only.',
    },
    {
      msi: 'ENABLESSO',
      exe: 'enableSSO',
      type: 'dropdown',
      cat: 'SSO & Authentication',
      options: [
        ['Based on policy (default)', '2'],
        ['Force Enable', '1'],
        ['Force Disable', '0'],
      ],
      desc: 'SSO via Windows Primary Account in Azure AD. 2=policy, 1=force on, 0=force off.',
    },
    {
      msi: 'INSTALLWEBVIEW2',
      exe: 'installWebView2',
      type: 'toggle',
      cat: 'SSO & Authentication',
      desc: 'Install WebView2 for testing SSO. Testing only - enable WebView2 for users first.',
    },
    {
      msi: 'UNINSTALLPASSWORDCMDLINE',
      exe: 'uninstallPasswordCmdLine',
      type: 'password',
      cat: 'Passwords & Maintenance',
      ph: 'Must match Uninstall Password in app profile',
      desc: 'Enable silent uninstall via GPO. Must match app profile Uninstall Password. ZCC v4.2.1+.',
    },
    {
      msi: 'UPGRADEPASSWORDCMDLINE',
      exe: 'upgradePasswordCmdLine',
      type: 'password',
      cat: 'Passwords & Maintenance',
      ph: 'Must match Upgrade Password in app profile',
      desc: 'Enable silent upgrade. Must match app profile Upgrade Password.',
    },
    {
      msi: 'REVERTPASSWORDCMDLINE',
      exe: 'revertPasswordCmdLine',
      type: 'password',
      cat: 'Passwords & Maintenance',
      ph: 'Must match Revert Password in app profile',
      desc: 'Enable silent revert to previous version. ZCC v4.2.1+.',
    },
    {
      msi: 'BCPCONFIGFILEPATH',
      exe: 'bcpConfigFilePath',
      type: 'file',
      cat: 'Business Continuity (v4.6+)',
      ph: 'Path to BCP config file',
      desc: 'Predownloaded Business Continuity config from ZPA Admin Portal. Requires BCPMAPUBKEYHASH.',
    },
    {
      msi: 'BCPMAPUBKEYHASH',
      exe: 'bcpMAPublicKeyHash',
      type: 'text',
      cat: 'Business Continuity (v4.6+)',
      ph: 'e.g. sYxSOjkj9DP1Ksw3LQ/FrPsBPfcsURrM5vNuH7Kmf1A=',
      desc: 'Public key for BCP config verification. Requires BCPCONFIGFILEPATH.',
    },
    {
      msi: 'IMPORTSEFAILCLOSECONFIG',
      exe: 'importSEFailCloseConfig',
      type: 'file',
      cat: 'Business Continuity (v4.6+)',
      ph: 'Path to fail-close config file',
      desc: 'Fail-close config for strict enforcement. Requires STRICTENFORCEMENT + SEFAILCLOSECONFIGTHUMBPRINT.',
    },
    {
      msi: 'SEFAILCLOSECONFIGTHUMBPRINT',
      exe: 'failCloseConfigThumbprint',
      type: 'text',
      cat: 'Business Continuity (v4.6+)',
      ph: 'e.g. GjqjzPQ3Vk35+o3Yo2EsPOSV3rOJaeYTpcBmotISts=',
      desc: 'Public key for fail-close config. Requires STRICTENFORCEMENT + IMPORTSEFAILCLOSECONFIG.',
    },
    {
      msi: null,
      exe: 'mode',
      type: 'dropdown',
      cat: 'EXE-Only Options',
      options: [
        ['Normal GUI install (default)', ''],
        ['Silent / Unattended', 'unattended'],
      ],
      desc: 'Installation mode for EXE installs. MSI equivalent: /qn flag.',
    },
    {
      msi: null,
      exe: 'unattendedmodeui',
      type: 'dropdown',
      cat: 'EXE-Only Options',
      options: [
        ['None - fully silent (default)', 'none'],
        ['Minimal progress bar', 'minimal'],
        ['Minimal with Dialogs', 'minimalWithDialogs'],
        ['Not set', ''],
      ],
      desc: 'UI shown during unattended EXE install. Requires mode=unattended.',
    },
    {
      msi: null,
      exe: 'revertzcc',
      type: 'toggle',
      cat: 'EXE-Only Options',
      desc: 'Silently revert ZCC to previous version. Use installer of version BEFORE upgrade.',
    },
    {
      msi: null,
      exe: 'installer-language',
      type: 'dropdown',
      cat: 'EXE-Only Options',
      options: [
        ['English (default)', 'en'],
        ['French', 'fr'],
        ['Not set', ''],
      ],
      desc: 'Installer UI language. Does not change ZCC app language. ZCC v4.5+.',
    },
  ],
  MAC_PARAMETERS = [
    {
      mac: 'cloudName',
      type: 'text',
      cat: 'Core Enrollment',
      seen: !0,
      ph: 'e.g. zscaler, zscalertwo, zscloud',
      desc: 'Zscaler cloud name. Do NOT include .net. Required with strictEnforcement.',
    },
    {
      mac: 'userDomain',
      type: 'text',
      cat: 'Core Enrollment',
      seen: !0,
      ph: 'e.g. safemarch.com',
      desc: 'Organization domain so users skip the domain prompt and go straight to SSO.',
    },
    {
      mac: 'policyToken',
      type: 'text',
      cat: 'Core Enrollment',
      seen: !0,
      ph: 'From the macOS app profile',
      desc: 'App profile policy applied before enrollment. Required with strictEnforcement.',
      fromTenant: 'policyToken',
    },
    {
      mac: 'deviceToken',
      type: 'text',
      cat: 'Core Enrollment',
      seen: !1,
      ph: 'ZCC Portal device token',
      desc: 'Device token when using ZCC Portal as IdP (ZIA only).',
    },
    {
      mac: 'userName',
      type: 'text',
      cat: 'Core Enrollment',
      seen: !1,
      ph: 'e.g. j.doe (no domain suffix)',
      desc: 'Username for enrollment. Requires userDomain.',
    },
    {
      mac: 'externalDeviceId',
      type: 'text',
      cat: 'Core Enrollment',
      seen: !1,
      ph: 'MDM device ID',
      desc: 'Associates an MDM device record with the ZCC Portal.',
    },
    {
      mac: 'strictEnforcement',
      type: 'toggle',
      cat: 'Enforcement & Security',
      seen: !0,
      desc: 'Block internet until the user enrolls. Requires cloudName + policyToken. Uninstall any existing ZCC first.',
    },
    { mac: 'hideAppUIOnLaunch', type: 'toggle', cat: 'UI & Behavior', seen: !0, desc: 'Keep the app window hidden before enrollment.' },
    {
      mac: 'launchTray',
      type: 'toggle_on',
      cat: 'UI & Behavior',
      seen: !0,
      desc: 'Start ZCC after install (default ON). Toggle OFF to suppress auto-start.',
    },
    {
      mac: 'externalRedirect',
      type: 'toggle',
      cat: 'UI & Behavior',
      seen: !0,
      desc: 'Use the default browser for authentication instead of the embedded view.',
    },
    {
      mac: 'mode',
      type: 'dropdown',
      cat: 'Installer Mode',
      seen: !0,
      options: [
        ['Silent / Unattended (default)', 'unattended'],
        ['Normal installer windows', ''],
      ],
      desc: 'Unattended installs without the installer wizard.',
    },
    {
      mac: 'unattendedmodeui',
      type: 'dropdown',
      cat: 'Installer Mode',
      seen: !0,
      options: [
        ['None - fully silent (default)', 'none'],
        ['Minimal progress bar', 'minimal'],
        ['Minimal with Dialogs', 'minimalWithDialogs'],
        ['Not set', ''],
      ],
      desc: 'UI shown during an unattended install. Requires mode=unattended.',
    },
  ],
  SECRET_RE = /password/i,
  isSecret = (a) => SECRET_RE.test(a);
function collectParams(a, e, n = {}) {
  let t = {},
    c = a === 'macos' ? MAC_PARAMETERS : WIN_PARAMETERS;
  for (let i of c) {
    let l = a === 'macos' ? i.mac : i.msi || i.exe,
      o = a === 'macos' ? i.mac : e === 'msi' ? i.msi : i.exe;
    if (!o) continue;
    let r = n[l];
    if (i.type === 'toggle') {
      if (r === !0 || r === '1') t[o] = '1';
    } else if (i.type === 'toggle_on') {
      if (r === !1 || r === '0') t[o] = '0';
    } else if (i.type === 'dropdown') {
      let s = r === void 0 ? i.options[0][1] : String(r);
      if (s && i.options.some((u) => u[1] === s)) t[o] = s;
    } else {
      let s = r === void 0 || r === null ? '' : String(r).trim();
      if (s) t[o] = s;
    }
  }
  if (t.unattendedmodeui !== void 0 && t.mode !== 'unattended') delete t.unattendedmodeui;
  return t;
}
function validateCloudName(a) {
  if (!a) return null;
  let e = a.trim().toLowerCase();
  if (e.includes('.')) {
    let n = e.split('.')[0];
    return `Invalid cloud name "${a}": do NOT include .net or any domain suffix.${VALID_CLOUD_NAMES.includes(n) ? ` Use "${n}".` : ''} Valid: ${VALID_CLOUD_NAMES.join(', ')}`;
  }
  if (!VALID_CLOUD_NAMES.includes(e)) return `Invalid cloud name "${a}". Valid: ${VALID_CLOUD_NAMES.join(', ')}`;
  return null;
}
function validateParams(a, e, n) {
  let t = [],
    c = a === 'macos',
    i = (d, m, f) => n[c ? f : e === 'msi' ? d : m] || '',
    l = i('STRICTENFORCEMENT', 'strictEnforcement', 'strictEnforcement'),
    o = i('CLOUDNAME', 'cloudName', 'cloudName'),
    r = i('POLICYTOKEN', 'policyToken', 'policyToken'),
    s = i('UNAME', 'userName', 'userName'),
    u = i('USERDOMAIN', 'userDomain', 'userDomain'),
    p = validateCloudName(o);
  if (p) t.push(['ERROR', p]);
  if (l === '1') {
    if (!o) t.push(['ERROR', `${c ? 'strictEnforcement' : 'STRICTENFORCEMENT'} requires ${c ? 'cloudName' : 'CLOUDNAME'}.`]);
    if (!r) t.push(['ERROR', `${c ? 'strictEnforcement' : 'STRICTENFORCEMENT'} requires ${c ? 'policyToken' : 'POLICYTOKEN'}.`]);
  }
  if (s && !u) t.push(['ERROR', `${c ? 'userName requires userDomain' : 'UNAME/userName requires USERDOMAIN/userDomain'}.`]);
  if (!c) {
    let d = i('BCPCONFIGFILEPATH', 'bcpConfigFilePath'),
      m = i('BCPMAPUBKEYHASH', 'bcpMAPublicKeyHash'),
      f = i('IMPORTSEFAILCLOSECONFIG', 'importSEFailCloseConfig'),
      b = i('SEFAILCLOSECONFIGTHUMBPRINT', 'failCloseConfigThumbprint'),
      v = i('CONFIGTIMEOUT', 'configTimeout');
    if (d && !m) t.push(['ERROR', 'BCPCONFIGFILEPATH requires BCPMAPUBKEYHASH.']);
    if (m && !d) t.push(['ERROR', 'BCPMAPUBKEYHASH requires BCPCONFIGFILEPATH.']);
    if (f && !b) t.push(['ERROR', 'IMPORTSEFAILCLOSECONFIG requires SEFAILCLOSECONFIGTHUMBPRINT.']);
    if (b && !f) t.push(['ERROR', 'SEFAILCLOSECONFIGTHUMBPRINT requires IMPORTSEFAILCLOSECONFIG.']);
    if (f && l !== '1') t.push(['ERROR', 'IMPORTSEFAILCLOSECONFIG requires STRICTENFORCEMENT=1.']);
    if (v && !/^\d+$/.test(v)) t.push(['ERROR', `CONFIGTIMEOUT must be a number (got '${v}').`]);
  }
  for (let [d, m] of Object.entries(n))
    if (/["\r\n\0]/.test(m)) t.push(['ERROR', `${d}: double quotes and line breaks can't be passed to the installer.`]);
  if (!u && !o)
    t.push(['WARN', `No ${c ? 'userDomain or cloudName' : 'USERDOMAIN or CLOUDNAME'} set. Users will see the full enrollment wizard.`]);
  return t;
}
function winQuote(a) {
  return ((a = String(a)), /[\s&|<>^()]/.test(a) || a === '' ? `"${a}"` : a);
}
function shQuote(a) {
  return `'${String(a).replace(/'/g, "'\\''")}'`;
}
var maskIfSecret = (a, e) => (isSecret(a) ? '********' : e);
function buildCommand({ platform: a, installerType: e, installerPath: n, params: t, silent: c = !0, debug: i = !0, logPath: l = null }) {
  if (a === 'macos') {
    let u = `${String(n).replace(/\/+$/, '')}/Contents/MacOS/installbuilder.sh`,
      p = [];
    for (let [f, b] of Object.entries(t)) p.push([`--${f}`, b]);
    let d = ['/bin/sh', shQuote(u), ...p.map(([f, b]) => `${f} ${shQuote(b)}`)].join(' '),
      m = ['/bin/sh', shQuote(u), ...p.map(([f, b]) => `${f} ${shQuote(maskIfSecret(f, b))}`)].join(' ');
    return { file: '/bin/sh', shell: d, display: d, displayMasked: m };
  }
  if (e === 'msi') {
    let u = ['/i', winQuote(n)];
    if (c) u.push('/qn');
    if (i) u.push('/L*V', winQuote(l || '%TEMP%\\ZCC_Install_Debug.log'));
    let p = Object.entries(t),
      d = [...u, ...p.map(([f, b]) => `${f}=${winQuote(b)}`)].join(' '),
      m = [...u, ...p.map(([f, b]) => `${f}=${winQuote(maskIfSecret(f, b))}`)].join(' ');
    return { file: 'msiexec.exe', args: d, display: `msiexec ${d}`, displayMasked: `msiexec ${m}` };
  }
  let o = Object.entries(t),
    r = o.map(([u, p]) => `--${u} ${winQuote(p)}`).join(' '),
    s = o.map(([u, p]) => `--${u} ${winQuote(maskIfSecret(u, p))}`).join(' ');
  return { file: n, args: r, display: `${winQuote(n)} ${r}`.trim(), displayMasked: `${winQuote(n)} ${s}`.trim() };
}
var batEscape = (a) => String(a).replace(/%/g, '%%');
function buildBat({ installerType: a, installerName: e, params: n, silent: t = !0, debug: c = !0, version: i }) {
  let l = new Date().toISOString().replace('T', ' ').substring(0, 19),
    o = [
      '@echo off',
      `REM ZCC Install Script - Generated by ZTP Policy Wizard v${i}`,
      `REM Date: ${l}  ^|  Type: ${a.toUpperCase()}`,
      'REM ' + '='.repeat(60),
      '',
      'echo ============================================================',
      'echo   ZTP Policy Wizard - Client Connector install',
      'echo ============================================================',
      'echo.',
      '',
      'net session >nul 2>&1',
      'if %errorlevel% neq 0 (',
      '    echo [ERROR] Administrator privileges required.',
      '    echo         Right-click and select "Run as administrator".',
      '    pause & exit /b 1',
      ')',
      'echo [OK] Running as Administrator.',
      '',
      `if not exist "%~dp0${batEscape(e)}" (`,
      `    echo [ERROR] Installer not found: ${batEscape(e)}`,
      '    pause & exit /b 1',
      ')',
      `echo [OK] Found installer: ${batEscape(e)}`,
      '',
      `set "INSTALLER=%~dp0${batEscape(e)}"`,
    ];
  if (c) o.push('set "LOGFILE=%TEMP%\\ZCC_Install_Debug.log"');
  o.push('', 'echo.', 'echo --- Configuration ---');
  for (let [r, s] of Object.entries(n)) o.push(`echo   ${r}=${isSecret(r) ? '********' : batEscape(s).replace(/([&|<>^])/g, '^$1')}`);
  if ((o.push('echo.', 'echo [%DATE% %TIME%] Starting installation...', ''), a === 'msi')) {
    let r = ['msiexec /i "%INSTALLER%"'];
    if (t) r.push('/qn');
    if (c) r.push('/L*V "%LOGFILE%"');
    for (let [s, u] of Object.entries(n)) r.push(`${s}="${batEscape(u)}"`);
    o.push(r.join(' '));
  } else {
    let r = ['"%INSTALLER%"'];
    for (let [s, u] of Object.entries(n)) r.push(`--${s} "${batEscape(u)}"`);
    o.push(r.join(' '));
  }
  if (
    (o.push(
      '',
      'set RESULT=%errorlevel%',
      'echo.',
      'echo [%DATE% %TIME%] Install complete.',
      '',
      'if %RESULT% equ 0    echo [SUCCESS] Installed successfully.',
      'if %RESULT% equ 3010 echo [SUCCESS] Installed - reboot required.',
      'if %RESULT% equ 1602 echo [WARN] Cancelled by user.',
      'if %RESULT% equ 1603 echo [ERROR] Fatal error (1603).',
      'if %RESULT% equ 1618 echo [ERROR] Another installation in progress.',
      'if %RESULT% equ 1619 echo [ERROR] Installer package is corrupt.',
      '',
    ),
    c && a === 'msi')
  )
    o.push(
      'if %RESULT% neq 0 if %RESULT% neq 3010 (',
      '    echo --- Last 30 lines of %LOGFILE% ---',
      '    powershell -NoProfile -Command "Get-Content -Path $env:LOGFILE -Tail 30"',
      ')',
      '',
    );
  return (
    o.push(
      'reg query "HKLM\\SOFTWARE\\Zscaler Inc.\\Zscaler" /v Version >nul 2>&1',
      'if %errorlevel% equ 0 (echo [VERIFIED] ZCC installed.) else (echo [INFO] ZCC key not found - may need reboot.)',
      'sc query ZSATunnel | find "RUNNING" >nul 2>&1',
      'if %errorlevel% equ 0 (echo [VERIFIED] ZSATunnel service is running.) else (echo [INFO] ZSATunnel service not running yet.)',
      '',
      'echo.',
      'echo ============================================================',
      'echo   Complete. Exit code: %RESULT%',
      'echo ============================================================',
      'pause',
      'exit /b %RESULT%',
    ),
    o.join(`\r
`) +
      `\r
`
  );
}
function buildMacScript({ installerName: a, params: e, version: n }) {
  let t = new Date().toISOString().replace('T', ' ').substring(0, 19),
    c = Object.entries(e).map(([l, o]) => `  --${l} ${shQuote(o)} \\`).join(`
`),
    i = Object.entries(e).map(([l, o]) => `echo "  ${l}=${isSecret(l) ? '********' : String(o).replace(/(["$`\\])/g, '\\$1')}"`).join(`
`);
  return `#!/bin/bash
# ZCC macOS install script - generated by ZTP Policy Wizard v${n}
# Date: ${t}
# Put this file next to ${a} (the .app or the .zip it came in), then double-click it.
# If macOS says it can't be opened: right-click > Open, or run:  bash "<this file>"
set -u
cd "$(dirname "$0")"
INSTALLER=${shQuote(a)}
echo "============================================================"
echo "  ZTP Policy Wizard - Client Connector install"
echo "============================================================"
if [[ "$INSTALLER" == *.zip ]]; then
  [ -f "$INSTALLER" ] || { echo "[ERROR] Not found: $INSTALLER"; read -r -p "Press Enter to close"; exit 1; }
  TMP=$(mktemp -d /tmp/zcc-install.XXXXXX)
  /usr/bin/ditto -x -k "$INSTALLER" "$TMP" || { echo "[ERROR] Could not unzip $INSTALLER"; exit 1; }
  APP=$(/usr/bin/find "$TMP" -maxdepth 2 -name "*.app" -type d | head -1)
else
  APP="$(pwd)/$INSTALLER"
fi
[ -x "$APP/Contents/MacOS/installbuilder.sh" ] || [ -f "$APP/Contents/MacOS/installbuilder.sh" ] || { echo "[ERROR] installbuilder.sh not found in $APP"; read -r -p "Press Enter to close"; exit 1; }
/usr/bin/xattr -dr com.apple.quarantine "$APP" 2>/dev/null
echo "--- Configuration ---"
${i || 'echo "  (no options)"'}
echo
echo "[$(date)] Starting installation (you will be asked for an administrator password)..."
sudo /bin/sh "$APP/Contents/MacOS/installbuilder.sh" \\
${c}${
    c
      ? `
`
      : ''
  }  ; RESULT=$?
echo
if [ $RESULT -eq 0 ]; then echo "[SUCCESS] Installer finished (exit 0)."; else echo "[ERROR] Installer exit code $RESULT"; fi
if [ -d "/Applications/Zscaler/Zscaler.app" ]; then
  echo "[VERIFIED] /Applications/Zscaler/Zscaler.app present, version $(/usr/bin/defaults read /Applications/Zscaler/Zscaler.app/Contents/Info.plist CFBundleShortVersionString 2>/dev/null)"
else
  echo "[INFO] /Applications/Zscaler/Zscaler.app not found yet."
fi
/usr/bin/systemextensionsctl list 2>/dev/null | grep -i zscaler
echo "============================================================"
echo "  Complete. Exit code: $RESULT"
echo "============================================================"
read -r -p "Press Enter to close"
exit $RESULT
`;
}
var EXIT_CODES = {
  0: ['SUCCESS', 'Installed successfully'],
  3010: ['SUCCESS', 'Installed - reboot required'],
  1602: ['WARN', 'Cancelled by user'],
  1603: ['ERROR', 'Fatal error during installation (1603) - see the MSI log'],
  1618: ['ERROR', 'Another installation is already in progress (1618)'],
  1619: ['ERROR', 'Installer package could not be opened / is corrupt (1619)'],
  1624: ['ERROR', 'Error applying transforms (1624)'],
  1625: ['ERROR', 'Installation prohibited by system policy (1625)'],
  1223: ['WARN', 'UAC prompt was declined (1223)'],
};
function describeExit(a, e) {
  if (a === 'windows') return EXIT_CODES[e] || [e === 0 ? 'SUCCESS' : 'WARN', `Exit code ${e}`];
  return e === 0 ? ['SUCCESS', 'Installer finished (exit 0)'] : ['ERROR', `Installer exit code ${e}`];
}
function catalog() {
  return {
    cloudNames: VALID_CLOUD_NAMES,
    windows: WIN_PARAMETERS.map((a) => ({ ...a, key: a.msi || a.exe })),
    macos: MAC_PARAMETERS.map((a) => ({ ...a, key: a.mac })),
  };
}
module.exports = {
  VALID_CLOUD_NAMES: VALID_CLOUD_NAMES,
  WIN_PARAMETERS: WIN_PARAMETERS,
  MAC_PARAMETERS: MAC_PARAMETERS,
  catalog: catalog,
  collectParams: collectParams,
  validateParams: validateParams,
  validateCloudName: validateCloudName,
  buildCommand: buildCommand,
  buildBat: buildBat,
  buildMacScript: buildMacScript,
  describeExit: describeExit,
  winQuote: winQuote,
  shQuote: shQuote,
  isSecret: isSecret,
};
