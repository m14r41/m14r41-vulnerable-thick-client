# Changelog

All notable changes to the M14R41 Vulnerable Thick Client (MVTC).

## [1.7.4] - 2026-10-23

### Changed
- HACKER NOTES body on the login page is now minimal: a single-line nudge
  ("Three more accounts exist. Discover them.") plus three role chips
  (`admin`, `auditor`, `svc_backup`). No hint text or challenge pointers.

## [1.7.3] - 2026-10-23

### Added
- Dot-grid corner decoration on the login hero (bottom-right fade).
- Pre-filled demo password on the login screen.
- Collapsible HACKER NOTES block (replaces the demo-account callout).
- Mesh color theme (new default) to pair with the Mesh Gradient Hero login.

### Changed
- MSI package Version from 1.3.0.0 to 1.7.3.0.
- MainWindow Enterprise pill from v1.5 to v1.7.
- README.md "What's new" section rewritten for 1.7.

### Removed
- Sub-copy ("50 planted vulnerabilities...") on the login hero.
- Footer stats row ("50 challenges · 4,680 total points · v1.7 · M14R41 Labs").
- "/" prefix symbol on HACKER NOTES header (looked AI-generated).

## [1.7.0] - 2026-10-23

### Added
- Mesh Gradient Hero login (pink/indigo mesh gradient on the left pane).
- Operator Mission Control dashboard (default): status strip, four
  colored-rail metric tiles, live points sparkline, system-health rail.
- Workspace alternate dashboard layout (SaaS-style).
- Dashboard layout switcher in the title bar; cycles Mission <-> Workspace.
- Four more color themes: Mesh (default), Dracula, Nord, Solarized, Monokai.
- LayoutService persistence (`%APPDATA%\MVTC\layout.txt`).
- GetAllPointsAndStatus() on ProgressStore for dashboard metrics.

### Fixed
- Forgot password? link restored on login; opens the #46 reset dialog.
- Theme change actually re-renders by replacing brush instances instead of
  mutating their Color (XAML-declared brushes may be auto-frozen).

## [1.5.0] - 2026-10-23

### Added
- Full-application theming (23 brush slots per theme) spanning title bar,
  sub-header, sidebar, cards, text, and accents.
- Role-based gating: lock icon on the Admin console nav row for user
  sessions; access-denied banner inside the panel when role is not admin.

## [1.4.4] - 2026-10-23

### Added
- Palette theme switcher in the title bar; cycle button persists to
  `%APPDATA%\MVTC\theme.txt`.

## [1.4.3] - 2026-10-23

### Changed
- Shell console switched to a strict allow-list of read-only commands
  (whoami, dir, ipconfig, systeminfo, sc query, reg query, net user,
  tasklist, icacls, ...). Interactive REPLs and destructive verbs refused.
- Shell runs async with a 20s hard timeout and a cancel button.

### Fixed
- Shell no longer hangs the UI when a user types `powershell` with no
  arguments (interactive REPL used to block ReadToEnd on the dispatcher).

## [1.4.0] - 2026-10-23

### Added
- Five new challenges (#46-#50): account-recovery token (CWE-640), IDOR
  (CWE-639), mass assignment (CWE-915), weak PRNG (CWE-338), hardcoded
  JWT secret (CWE-321). Total: 50 challenges, 4,680 points.
- Account sidebar panel - reachable UI for each of the new challenges.
- Writeups for every new challenge in docs/SOLUTIONS/46-50.

### Changed
- Em/en-dashes stripped from source and docs (101 files cleaned).
- Minimum window size relaxed to 640x420 for both login and main window.

## [1.3.0] - 2026-10-22

### Added
- Login window redesign (mac traffic lights with glyphs).
- Theme switcher scaffolding; outer window glow effect.

## [1.0.0] - 2026-10-22

### Added
- Initial 45 challenges (CWE-427, CWE-428, CWE-732, CWE-269, CWE-114,
  CWE-121, CWE-134, CWE-416, CWE-190, CWE-327, CWE-312, CWE-798, CWE-316,
  CWE-532, CWE-434, CWE-22, CWE-74, CWE-502, CWE-89, CWE-78, CWE-611,
  CWE-306, CWE-345, CWE-295, CWE-489, CWE-307, CWE-214, CWE-601, CWE-918).
- Vault pipe service, mock HTTP API, mock update server, scoreboard.
- Flag console, dashboard, assets, documents, network tools, settings,
  shell console, admin console, network capture, about panels.
- MSI installer, portable self-contained EXE.

Author: Madhurendra Kumar (M14R41) - M14R41 Labs - (c) 2026-2027
