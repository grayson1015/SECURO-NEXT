# Securo for macOS

This directory is an isolated SwiftUI prototype for the macOS Securo checker. It does not import, package, or modify the Windows checker.

## Current prototype

- Uses the existing production PIN and report-upload endpoints.
- Requires explicit consent before scanning and again before upload.
- Saves a local JSON report under `~/Documents/Securo/Reports`.
- Parses accessible Roblox Player logs while excluding Roblox Studio logs.
- Collects running-process, Roblox integrity, quarantine download, application, file, code-signature, and persistence evidence.
- Treats MacSploit and Opiumware names as review indicators, not automatic proof.
- Generates a partial report when evidence is unavailable or a scan reaches its profile deadline.

## Privacy boundary

The Mac checker must not collect passwords, Keychain contents, authentication tokens, cookies, browser sessions, private messages, clipboard data, photos, contacts, or unrelated private documents. It must not delete, quarantine, inject, bypass security controls, or modify Roblox.

## Build on a Mac

Requirements:

- macOS 13 or newer
- Xcode 15 or newer
- Swift 5.9 or newer

Open `Package.swift` in Xcode, select the `SecuroMac` executable target, and run it. Command-line validation:

```bash
cd securo-macos
swift test
swift build
```

The current source is an alpha prototype. Before public distribution, create an Xcode macOS App project around these sources, add the Securo icon and bundle identifier, sign with a Developer ID certificate, enable hardened runtime, archive, notarize, and distribute a signed DMG.

## Next collectors

The next safe, read-only milestones are:

1. QuarantineEventsV2 metadata with permission-aware access.
2. FSEvents correlation for relevant flagged paths.
3. Unified Log collection constrained to Roblox and verified findings.
4. Roblox bundle integrity and unexpected dylib correlation.
5. Gatekeeper/notarization details and Team ID extraction.

Each collector must clearly report unavailable permissions and must not convert a filename match alone into a confirmed finding.
