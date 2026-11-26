# SignPath preparation: GitHub source and release controls

These are **desired-state templates**, not evidence that GitHub rulesets have been activated. The repository is owned by one maintainer. Do **not** require one or more independent PR approvals until a second trusted, write-authorized reviewer is available. CI and automated review are not independent human approval.

## Before applying

The public repository had **no repository rulesets** on 26 November 2026. The connected integration could not read classic branch protection (GitHub returned a 403). The CI job names and GitHub Actions app ID below were checked against the public `main` commit.

Authenticate **locally** as the GitHub repository owner (GitHub CLI with repository Administration write permission). Do not store or paste a PAT into this repository. Verify any existing classic branch protection before creating rules that could conflict with it.

```bash
gh auth status
gh api repos/ivanversluis/osidiag/rulesets --jq '.[] | [.id, .name, .target, .enforcement]'
```

Use [Settings → Rules → Rulesets](https://github.com/ivanversluis/osidiag/settings/rules) if you prefer the GitHub UI.

### 1. Protect `main`

`.github/rulesets/main.json` requires:
- PR-based changes to `main` (zero approvals, to avoid deadlocking the sole maintainer).
- Resolution of review conversations.
- Passing both actual GitHub Actions check contexts, pinned to GitHub Actions integration ID `15368`.
- An up-to-date branch before merging (strict status checks), with no direct pushes, force pushes or deletion.
- No bypass actors. If access or CI changes require recovery, edit the ruleset as repository administrator; do not routinely bypass the policy.

### 2. Protect `v*` release tags

`.github/rulesets/v-tags.json` permits **creation of new** `v*` tags by authorized writers but blocks updates, deletion and force pushes of existing version tags. The release workflow independently verifies an **annotated** `vMAJOR.MINOR.PATCH` tag referencing a commit on `main`. Do **not** enable the `creation` restriction without an explicitly configured release-creator bypass; that would prevent the maintainer from tagging the next version.

### Apply, once, with repository administration access

Review both JSON files and ensure no matching ruleset has already been created before running. Each POST **creates** a new ruleset; repeating it creates duplicates.

```bash
gh api -X POST repos/ivanversluis/osidiag/rulesets --input .github/rulesets/main.json
gh api -X POST repos/ivanversluis/osidiag/rulesets --input .github/rulesets/v-tags.json
```

Verify that both show `active` in GitHub Settings and the read API:

```bash
gh api repos/ivanversluis/osidiag/rulesets --jq '.[] | [.id, .name, .target, .enforcement]'
```

Open a test PR to confirm both checks are actually required and that the sole maintainer can merge after they pass. Create **no test `v*` tag**, because the release workflow would try to publish it. Existing `v0.4.1` must not be rewritten or deleted.

### 3. Improve the existing v0.4.1 GitHub download page

`docs/v0.4.1-release-notes.md` is the prepared release description. It preserves the unsigned warning and adds the direct functionality description required by SignPath. With GitHub CLI authenticated as a maintainer:

```bash
gh release edit v0.4.1 --repo ivanversluis/osidiag --notes-file docs/v0.4.1-release-notes.md
gh release view v0.4.1 --repo ivanversluis/osidiag --json body --jq .body
```

The release workflow is updated separately to add a functional description for **future** releases. Changing the template does not retroactively edit v0.4.1.

### 4. Enable immutable GitHub Releases for subsequent versions

The v0.4.1 GitHub API shows `immutable: false`. For additional supply-chain protection, visit [Settings → General → Releases](https://github.com/ivanversluis/osidiag/settings) and enable release immutability. This applies to **future** releases, not retroactively to v0.4.1. Make sure future releases attach all assets before publication.

GitHub provides the admin API alternative:

```bash
gh api -X PUT repos/ivanversluis/osidiag/immutable-releases
```

Do not rewrite the v0.4.1 tag or replace its artifacts merely to achieve immutability.

## What still requires the maintainer

Confirm copyright and publication rights for every source file, code contribution and logo; accept the SignPath terms; provide private contact details directly in SignPath's form; and explicitly disclose the one-person author/reviewer/approver model. The public CI uses tools such as govulncheck and gosec, but they are **build-time checks** and are not bundled into `osidiag.exe`. Source functionality should still be assessed honestly against the Foundation's restriction on tools designed to highlight exploitable vulnerabilities. The Foundation makes the eligibility decision.

Do not check off the protection or release-description requirements in `docs/SIGNPATH_APPLICATION.md` until the GitHub settings and public release notes have actually been verified.
