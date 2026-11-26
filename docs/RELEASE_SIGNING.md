# Windows release and verification

## Before the first public release

The new one-root-commit repository must be made public only after the [history handoff](PUBLIC_BASELINE.md) and [publication checklist](PUBLICATION_CHECKLIST.md) are complete. No public GitHub Release existed when this procedure was prepared on 11 November 2026. A release tag must point to a reviewed `main` commit and be an annotated Git tag.

```bash
git switch main && git pull --ff-only
VERSION=v0.4.1 # example: select a new, unused version after code review
git tag -a "$VERSION" -m "osidiag $VERSION"
git push origin "$VERSION"
```

Do not create this tag until CI and release preview are green and the publication audit is complete. The initial v0.4.0 tag was valid but its workflow run failed because checkout peeled the local tag reference; after merging the release-workflow fix, use a new version such as v0.4.1. Rerunning v0.4.0 still uses the old workflow from that tagged commit. Never force-move a public release tag or reuse it to replace attached artifacts.

## Unsigned initial release

With no `SIGNPATH_ENABLED=true` repository variable, the workflow creates `osidiag-windows-amd64-unsigned.zip`, plus Linux AMD64/ARM64 tarballs. Windows CI asserts the package is unsigned. Downloads, `SHA256SUMS` and public GitHub build provenance are published to GitHub Releases when the repository is public.

## SignPath onboarding after approval

1. Apply with [docs/SIGNPATH_APPLICATION.md](SIGNPATH_APPLICATION.md) and the published [Code signing policy](CODE_SIGNING.md); confirm SignPath eligibility and user access with SignPath Foundation. The SignPath Foundation certificate belongs to SignPath Foundation.
2. In SignPath, create/link the `osidiag` project to repository `https://github.com/ivanversluis/osidiag`; add **GitHub.com** as a trusted build system and enable **origin verification**, with allowed refs limited to reviewed release tags/branches. Install/authorize the SignPath GitHub App when required for auditing.
3. Create the artifact configuration for the GitHub Actions artifact ZIP containing `osidiag.exe`: root element `<zip-file>` and contained Windows PE `<pe-file>` entry. Enforce ProductName `osidiag`, version fields matching the release and the release certificate timestamping policy. Confirm tag-origin rules with SignPath (a tag push is not itself a reviewed branch).
4. Define a release signing policy with **manual approval for every request**, no automatic approval, and authorization limited to the repository and trusted GitHub-hosted Actions builds.
5. GitHub **repository secret**: `SIGNPATH_API_TOKEN` (submitter only). GitHub **repository variables**: `SIGNPATH_ORGANIZATION_ID`, `SIGNPATH_PROJECT_SLUG`, `SIGNPATH_SIGNING_POLICY_SLUG`, and optional `SIGNPATH_ARTIFACT_CONFIGURATION_SLUG`. Configure protection/rulesets for `main` and `v*` tags; do not store signing tokens in source.
6. Set repository variable `SIGNPATH_ENABLED` to exactly `true` only after a tested SignPath configuration. When enabled, a failed or untrusted signature blocks the entire release. Keep it unset or `false` beforehand.

The Windows build embeds FileVersion/ProductVersion and ProductName using the version from the release tag. The SignPath action receives the immutable uploaded unsigned workflow artifact ID; manual approval occurs on SignPath's side. No private signing key is stored in the repository or GitHub Actions.

## Independent release verification

Download a release ZIP and `SHA256SUMS` from the **same** release. Hash comparison detects byte changes relative to the manifest but is not an identity signature.

```bash
archive=osidiag-windows-amd64-unsigned.zip
awk -v archive="$archive" '$2 == archive { print; found=1 } END { if (!found) exit 1 }' SHA256SUMS > "$archive.sha256"
sha256sum -c "$archive.sha256"
gh attestation verify "$archive" -R ivanversluis/osidiag
# For a future signed release, replace the filename with osidiag-windows-amd64-signed.zip.
```

After extracting a **signed** ZIP in PowerShell:

```powershell
$signature = Get-AuthenticodeSignature .\osidiag.exe
$signature | Format-List Status,SignerCertificate,TimeStamperCertificate
if ($signature.Status -ne 'Valid') { throw 'Windows does not trust this Authenticode signature' }
(Get-Item .\osidiag.exe).VersionInfo | Format-List ProductName,ProductVersion,FileVersion
```

For an unsigned release `Get-AuthenticodeSignature` will return `NotSigned` and Windows may warn or block execution. GitHub attestations and SHA256 sums do **not** remove SmartScreen or Smart App Control warnings.

## Alternatives evaluated for issue #10

- **SignPath Foundation:** free for approved OSI-licensed, already-released OSS. It offers trusted signing only after Foundation review, with controlled release builds, manual approval and product metadata. Preferred approach for this project.
- **Microsoft Store / MSIX:** Microsoft can re-sign qualifying MSIX packages at no signing cost, but osidiag is currently a portable CLI EXE, not an MSIX package. An MSIX packaging and Store submission track would be a separate change; submitting raw EXE/MSI still requires Authenticode signing.
- **Azure Artifact Signing:** suitable for qualifying organizations in EU, but individual developers outside the US/Canada are not currently eligible according to Microsoft. It also requires identity verification and approximately USD 9.99/month; not selected.
- **Commercial OV/EV certificate:** available at a cost and subject to identity validation; neither guarantees instantaneous SmartScreen reputation. Not selected.

References: https://signpath.org/terms.html, https://docs.signpath.io/trusted-build-systems/github, https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options.
