ZTP Policy Wizard - standalone edition
======================================

Nothing to install. No Node.js, no npm.

WINDOWS
  1. Unzip.
  2. Double-click ZTP-Wizard.exe.
     Windows SmartScreen may say "Windows protected your PC" because the app is not
     code-signed yet: click "More info" -> "Run anyway".
  3. Your browser opens the wizard. Keep the black console window open while you use it;
     close it to stop the wizard.

MAC
  1. Unzip. Use the build for your Mac:
       ZTP-Wizard-*-macos-arm64.zip  Apple Silicon (M1/M2/M3/M4)
       ZTP-Wizard-*-macos-x64.zip    Intel Macs
  2. The app is not signed by Apple yet, so the first time:
       right-click ZTP-Wizard -> Open -> Open.
     If macOS still refuses ("cannot be opened" / "damaged"), open Terminal in the
     unzipped folder and run:
       xattr -d com.apple.quarantine ZTP-Wizard
     then double-click it again. If it says "killed", re-sign it locally (free,
     built into macOS):
       codesign --force --sign - ZTP-Wizard
  3. A Terminal window starts the wizard and your browser opens it. Keep the Terminal
     window open while you use it; close it (or press Ctrl+C) to stop.

DETAILS
  - The wizard listens on http://127.0.0.1 only (this computer), port 3000 or the next
    free port. Your Zscaler API credentials stay on this computer.
  - Logs: ZTP-Wizard/logs in your home folder.
  - Options (environment variables): ZTP_PORT=4000 to pick a port,
    ZTP_NO_BROWSER=1 to not open a browser, ZTP_LOG_DIR=<folder> for logs.
