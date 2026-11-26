# SignPath Foundation application — osidiag

**Application status: not submitted.** Complete the publication checklist, publish a genuine first release, then submit personally at https://signpath.org/apply.html. SignPath Foundation, not GitHub Actions, grants access.

| Field / evidence | Proposed answer |
| --- | --- |
| Project | osidiag |
| Homepage | https://networknet.nl/projects/osidiag/ |
| Source repository | https://github.com/ivanversluis/osidiag |
| License | Apache License 2.0 (OSI-approved) — `LICENSE` in repository root |
| Download page | https://github.com/ivanversluis/osidiag/releases |
| Project maintainer | Ivan Versluis, https://github.com/ivanversluis |
| Product | A portable, cross-platform Go CLI that structures network troubleshooting into OSI layers 1–7. Shows local interface, routing and neighbor states and runs explicit ping/traceroute, single-endpoint TCP, DNS, TLS, HTTP and Wi-Fi diagnostics. Windows 11 AMD64 and Linux AMD64/ARM64, with human-readable and machine-readable results. |
| Files to sign | GitHub Actions-built Windows AMD64 `osidiag.exe` inside official release ZIP. No third-party binaries. |
| Release workflow | https://github.com/ivanversluis/osidiag/blob/main/.github/workflows/release.yml |
| Code signing policy | https://github.com/ivanversluis/osidiag/blob/main/docs/CODE_SIGNING.md and https://networknet.nl/projects/osidiag/code-signing/ |
| Privacy and uninstall | See `docs/CODE_SIGNING.md`; no background telemetry, no installer and no system configuration changes by default |
| Authors / reviewers / approver | Sole maintainer Ivan Versluis: direct author, reviewer of external contributors, and manual signing approver. No independent review of own commits is claimed. SignPath makes the eligibility decision. |
| Security controls | MFA for maintainer accounts; reviewed code and workflow; GitHub-hosted runners, signed tagged releases, origin verification, SignPath-controlled certificate |

## Application description (copy-ready)

osidiag is a free, Apache-2.0-licensed command-line network troubleshooting utility written in Go. It provides an OSI-layer view of local adapters, routing, neighbor caches and connection states, plus explicitly requested ICMP, traceroute, TCP connectivity, TLS certificate/SNI, DNS and HTTP diagnostics. The Windows AMD64 executable is built from our public GitHub source and release workflow; Linux builds are also supplied. It is a general network connectivity diagnostic, not an exploitation tool or automated vulnerability scanner. The program ships as a portable executable with no service installation, no background telemetry and no system configuration changes by default. The project is maintained by Ivan Versluis at networknet.nl.

## Single-maintainer model and eligibility

osidiag has one maintainer. SignPath Foundation describes author, reviewer and approver responsibilities without explicitly requiring three distinct people. Ivan authors direct commits, reviews other contributors' pull requests, and manually approves every signing request. He cannot independently review his own commits; CI and build provenance do not substitute for an independent human reviewer. SignPath decides whether this model qualifies.

The Foundation also requires an already released project and sufficient verifiable reputation, and prohibits software designed to scan for exploitable vulnerabilities. osidiag's focused network-connectivity troubleshooting is not intended for vulnerability enumeration, but acceptance is entirely SignPath's decision. A brand-new single-commit public repository limits visible historical reputation.

## Requirements that must be confirmed before applying

- [ ] Newly created public repository has a single verified root commit (see PUBLIC_BASELINE.md); all current source and assets have been reviewed and licensed.
- [ ] First official tagged release exists and the binary has been downloaded and exercised on clean Windows 11.
- [ ] Project homepage is published and contains tool description, real downloads, installation/uninstallation and a link titled **Code signing policy**.
- [ ] GitHub and SignPath MFA is enabled for all maintainers.
- [ ] Sole-maintainer responsibilities are disclosed accurately; the Foundation accepts that role model and manual human approval and branch/tag controls exist.
- [ ] No non-open-source components are bundled in signed artifacts; SignPath's no-vulnerability-scanner rule is independently assessed.
- [ ] Signing workflow is tested in unsigned mode and SignPath configuration has been reviewed for exact build/artifact metadata, timestamp and origin requirements.
- [ ] Owner provides application contact details, approves the SignPath conditions and submits the form.

**Do not claim Foundation acceptance, certificate ownership or completed Windows Authenticode signing until the provider has approved the application and a signed release passes Windows verification.**
