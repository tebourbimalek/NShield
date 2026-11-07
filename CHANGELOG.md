# Changelog

All notable changes to NetGuard are documented here.
This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Brand identity: Concept 2 "N + Shield" mark (favicon, header, splash, app icon).
- Dark & light themes with header toggle.
- Speed sparkline beside watched devices.
- Daily data budgets with auto-cutoff.
- Usage history + CSV export (7/30 days).
- Phone access (passcode gate, QR code, firewall rule toggle).
- New-device alerts (Windows balloon + in-app banner).
- Start-with-Windows autostart.
- Friendly rename + auto-recognition (mDNS/SSDP/NetBIOS/web).
- Phone-gate rate limiting (5 attempts / minute).
- `HOW_TO_USE.md` quick-start guide.

### Changed
- Project published as open source (MIT).
- Branch protection: 1 approving review required, no force pushes.

## [1.0.0] - 2026-11-07

### Added
- Initial public release.
- Dual-stack ARP + NDP blocking with auto-restore on exit.
- Consent modal, allow-listed subnets, compliance watch.
- RotatingFileHandler logging (5 MB × 3).
- Per-device metering (checkpoint mode), speed caps (Windows QoS).
- Rename + icon whitelist.
- Web UI with no technical jargon.
