# SignPath Foundation application — osidiag

**Application status: not submitted.** The first public Windows build is available in v0.4.1 and is unsigned. Complete the open pre-application checks below before submitting at https://signpath.org/apply.html.

| Field / evidence | Proposed answer |
| --- | --- |
| Project | osidiag |
| Homepage | https://networknet.nl/projects/osidiag/ |
| Source repository | https://github.com/ivanversluis/osidiag |
| License | Apache License 2.0 (OSI-approved) — `LICENSE` in repository root |
| Download page | [v0.4.1 release](https://github.com/ivanversluis/osidiag/releases/tag/v0.4.1) (Windows AMD64 ZIP is unsigned) |
| Project maintainer | Ivan Versluis, https://github.com/ivanversluis |
| Product | A portable, cross-platform Go CLI that structures network troubleshooting into OSI layers 1–7. Shows local interface, routing and neighbor states and runs explicit ping/traceroute, single-endpoint TCP, DNS, TLS, HTTP and Wi-Fi diagnostics. Windows 11 AMD64 and Linux AMD64/ARM64, with human-readable and machine-readable results. |
| Files to sign | GitHub Actions-built Windows AMD64 `osidiag.exe` inside official release ZIP. No third-party binaries. |
| Release workflow | https://github.com/ivanversluis/osidiag/blob/main/.github/workflows/release.yml |
| Code signing policy | https://github.com/ivanversluis/osidiag/blob/main/docs/CODE_SIGNING.md and https://networknet.nl/projects/osidiag/code-signing/ |
| Privacy and uninstall | See `docs/CODE_SIGNING.md`; no background telemetry, no installer and no system configuration changes by default |
| Authors / reviewers / approver | Sole maintainer Ivan Versluis: direct author, reviewer of external contributions, and proposed manual signing approver. No independent review of own commits is claimed. SignPath makes the eligibility decision. |
| Release evidence | Annotated v0.4.1 tag, GitHub-hosted build, published SHA-256 checksums and GitHub build attestations. No Windows Authenticode signature in v0.4.1. |

## Application description (copy-ready)

osidiag is a free, Apache-2.0-licensed command-line network troubleshooting utility written in Go. It provides an OSI-layer view of local adapters, routing, neighbor caches and connection states, plus explicitly requested ICMP, traceroute, TCP connectivity, TLS certificate/SNI, DNS and HTTP diagnostics. The Windows AMD64 executable is built from our public GitHub source and release workflow; Linux builds are also supplied. It is a general network connectivity diagnostic, not an exploitation tool or automated vulnerability scanner. The program ships as a portable executable with no service installation, no background telemetry and no system configuration changes by default. The project is maintained by Ivan Versluis at networknet.nl.

## Single-maintainer model and eligibility

osidiag has one maintainer. SignPath Foundation describes author, reviewer and approver responsibilities without explicitly requiring three distinct people. Ivan authors direct commits and reviews other contributors' pull requests. If approved, he would manually approve each signing request, subject to the Foundation's acceptance of this role model. He cannot independently review his own commits; CI and build provenance do not substitute for an independent human reviewer. SignPath decides whether this model qualifies.

The Foundation also requires an already released project and sufficient verifiable reputation, and prohibits software designed to scan for exploitable vulnerabilities. osidiag's focused network-connectivity troubleshooting is not intended for vulnerability enumeration, but acceptance is entirely SignPath's decision. The new public repository has limited visible history. Include verifiable adoption or community references if available.

## Requirements that must be confirmed before applying

- [x] Public Apache-2.0 repository with a clean starting point. GitHub reports Apache-2.0, the repository contains `LICENSE` and `NOTICE`, and the public `main` history starts at one root commit, `79e4a9f`.
- [ ] Confirm publication rights for all source and assets. The repository license and clean history do not establish rights to every component.
- [x] First official tagged release and downloadable Windows executable. [v0.4.1](https://github.com/ivanversluis/osidiag/releases/tag/v0.4.1) includes the unsigned Windows AMD64 ZIP, Linux AMD64/ARM64 archives and `SHA256SUMS`. All three downloaded archives matched the manifest.
- [x] Unsigned release pipeline exercised. The [release run](https://github.com/ivanversluis/osidiag/actions/runs/45800823995) verified the annotated tag, Windows metadata and unsigned status, then published checksums and build attestations. GitHub has attestations for the downloaded digests; independent attestation signature verification is not recorded here.
- [x] The published Windows ZIP contains only the project-built `osidiag.exe`, `LICENSE` and `NOTICE`. No separate third-party binary is bundled.
- [x] Windows PowerShell inspection of the extracted v0.4.1 package reported `NotSigned`, product name `osidiag`, and product and file versions `0.4.1`.
- [x] Windows smoke test: the maintainer ran `osidiag.exe l1 --output json` from the extracted v0.4.1 ZIP in PowerShell. The JSON reports version `0.4.1` and an `ok` Layer 1 result.
- [x] The public [Code signing policy](https://networknet.nl/projects/osidiag/code-signing/) is available and documents roles, privacy and portable uninstall. The v0.4.1 release notes link to the repository policy.
- [x] [Networknet PR #72](https://github.com/ivanversluis/networknet/pull/72) is live. The [project page](https://networknet.nl/projects/osidiag/) and [announcement](https://networknet.nl/notes/osidiag-network-troubleshooting/) link to v0.4.1, label the Windows ZIP unsigned and link to the policy. The project page describes portable installation and removal.
- [x] Disclose the sole-maintainer roles and the absence of independent review of the maintainer's own commits. SignPath decides whether this model qualifies.
- [x] GitHub MFA: the maintainer confirmed that an authenticator app is configured.
- [ ] Configure or verify active review and release controls for `main` and `v*` tags; GitHub's public API reported `main` unprotected and no active rules for it on 26 November 2026.
- [ ] Add a short description of osidiag's network troubleshooting functions to the GitHub download page. The v0.4.1 notes describe the packages and link to the project page, but do not directly describe the tool's functionality.
- [ ] Review the shipped diagnostic features against the [SignPath conditions](https://signpath.org/terms.html), including the vulnerability-scanning restriction. Describe the features as shipped and let SignPath decide eligibility.
- [ ] Provide a maintainer contact, review the terms, and submit the application. Do not put private contact details in this repository.

## After SignPath approval, before enabling signing

- [ ] Enable MFA for all SignPath accounts with project access and configure manual approval for each signing request.
- [ ] Configure and test GitHub build origin verification, artifact identity, PE metadata restrictions and timestamping as described in [RELEASE_SIGNING.md](RELEASE_SIGNING.md). Leave `SIGNPATH_ENABLED` unset or false until the configuration has been tested.
- [ ] Publish a new signed release only after validating the certificate chain, publisher, timestamp and metadata on Windows. Keep the unsigned v0.4.1 release unchanged.

**Do not claim Foundation acceptance, certificate ownership or completed Windows Authenticode signing until the provider has approved the application and a signed release passes Windows verification.**
