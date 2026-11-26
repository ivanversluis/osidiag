# Code signing policy

**Current status (26 November 2026): v0.4.1 is publicly released with an unsigned Windows AMD64 executable. The SignPath Foundation application is not submitted, and no Windows release is Authenticode-signed.** A repository license, build provenance or SHA256SUMS file does not constitute Microsoft-trusted code signing. Do not describe an unsigned binary as signed.

**Free code signing provided by [SignPath.io](https://signpath.io/), certificate by [SignPath Foundation](https://signpath.org/).** This wording describes the planned service; it does not imply that signing has been approved or activated.

## Scope and project ownership

- Official source: https://github.com/ivanversluis/osidiag
- Project homepage and download information: https://networknet.nl/projects/osidiag/
- Official download page: https://github.com/ivanversluis/osidiag/releases/tag/v0.4.1
- Only the **Windows AMD64 `osidiag.exe`** built from this repository's own Go source in the GitHub-hosted release workflow is eligible for Foundation signing. No third-party binaries, local rebuilds or externally supplied EXEs will be sent for signature.
- Linux tarballs are not Authenticode-signed; hashes and GitHub attestations cover their provenance.
- Publication and signing are independent: unsigned releases may be available before Foundation acceptance.

## Team responsibilities

This is a **single-maintainer project**. The same person controls direct source changes, reviews outside contributions and approves releases manually; no independent review of the maintainer's own commits is asserted. SignPath lists author, reviewer and approver roles but does not explicitly require separate individuals. Its approval is discretionary and may depend on project reputation.

- **Authors / maintainers:** [Ivan Versluis](https://github.com/ivanversluis), repository owner, controls direct writes and reviewed changes.
- **Reviewers:** Ivan Versluis reviews changes submitted by other contributors. Contributors do not self-approve their own release changes; the project requires an independent reviewer if responsibility is delegated to another author.
- **Release/signing approver:** Ivan Versluis, repository owner. Every SignPath signing request requires explicit human approval; no automatic approvals.
- All maintainers with repository or SignPath access must have MFA enabled. Protect release branches/tags and require review of changes to source, build scripts, dependencies and workflow configuration.

## Build, signing and verification

1. A maintainer creates an annotated release tag on a reviewed commit already present on `main`. The workflow tests Go code, builds the versioned Windows PE on GitHub-hosted Windows infrastructure, and uploads the **unsigned EXE** as a GitHub Actions artifact.
2. **Only when Foundation access and secure repository configuration have been granted**, the GitHub Actions SignPath connector submits that artifact for signing with origin verification and a constrained release signing policy. The authorized approver manually approves the request. The SignPath configuration must apply an RFC 3161 timestamp and check product and file version metadata.
3. Windows CI validates the returned EXE using `Get-AuthenticodeSignature` (trusted status, expected publisher and timestamp) and verifies its product/version fields before producing the signed ZIP. Any signing or validation failure blocks publication, rather than publishing a mislabeled unsigned ZIP.
4. A public release job packages only the verified files, produces SHA256SUMS **after** signing and creates GitHub artifact attestations. GitHub provenance confirms source/build provenance, **not** Windows Authenticode trust.

The signed publisher will be **SignPath Foundation**, not Ivan Versluis or Networknet. Windows SmartScreen reputation may still require time, and Smart App Control may have independent restrictions.

## Privacy policy and system changes

**osidiag does not transfer information to other networked systems unless specifically requested by the person operating it.** Local L1/L2/L4/L5/Wi-Fi/DHCP inspection reads local operating-system state. Explicit target-based checks (ICMP, traceroute, TCP, DNS, TLS, HTTP) connect to the requested host or resolver. The `speedtest` command requires an explicit site/target URL, and an optional `--download-url` fetches the operator-selected payload and `--watch` repeats downloads until stopped. These actions transfer protocol-level requests and normal network metadata to the named destination. No telemetry or background updater is shipped.

The CLI does not install services, alter system configuration, or persist user data by default. Installation is extraction or copying a single executable; uninstall by deleting that executable and any independently configured files. On Linux, remove an optional manually assigned `cap_net_raw` capability by deleting the executable or running `sudo setcap -r ./osidiag`.

SignPath Foundation disclaims liability for damage arising from software it signs for open-source projects. See [SignPath conditions](https://signpath.org/terms.html).

## Eligibility note

osidiag is a troubleshooting tool and does not implement vulnerability exploitation or automatic remote port-range vulnerability scanning. A single target-specific TCP connection and a passive listing of the user's own local sockets are diagnostic observations, not an assessment of exploitable vulnerabilities. **SignPath Foundation decides eligibility**, including its prohibition on tools that actively identify exploitable security weaknesses. Do not claim acceptance until it is granted.
