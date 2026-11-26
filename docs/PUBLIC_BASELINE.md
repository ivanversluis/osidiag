# Clean public Git baseline

**Keep the existing repository private.** Force-pushing or squash-merging main does not reliably erase old pull-request refs and caches. To start clean, replace the canonical name with a **new repository identity and a single no-parent root commit**. The original remains a private archive.

GitHub reference: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository

## 1. Merge and prepare exact reviewed baseline

After PR #19 passes CI, merge it into the **private** osidiag repository, then in WSL2 Ubuntu with Bash, Git, tar, gh and Go:

~~~bash
gh repo clone ivanversluis/osidiag
cd osidiag
git switch main
git pull --ff-only
go test ./... && go vet ./...
bash scripts/create-public-snapshot.sh "$HOME/osidiag-public-baseline"
cd "$HOME/osidiag-public-baseline"
git rev-list --count HEAD        # must be 1
git rev-list --parents -n1 HEAD  # only one SHA, no parents
git status --porcelain          # must be empty
go test ./... && go vet ./...
~~~

The script refuses unmerged PR #19, dirty or stale main, or an existing target directory. It exports **tracked files only** and compares the new root commit's tree to the reviewed source tree. It never modifies GitHub.

Inspect the snapshot for secrets, intellectual property, employer-specific material, unlicensed assets. Rotate any credentials ever leaked. A fresh history does not make unauthorized code publishable.

## 2. Rename the old private repository, create new private one

This is an intentional repository replacement. Issues, PRs, discussions, labels, Actions history, releases, attestations, settings, secrets and old GitHub Apps will not migrate. Capture any information needed before performing the cutover. Confirm the archive name is available.

~~~bash
gh repo rename osidiag-private-history-2026 -R ivanversluis/osidiag
gh repo view ivanversluis/osidiag-private-history-2026 --json visibility -q .visibility
# The original must remain PRIVATE.
gh repo create ivanversluis/osidiag --private \
  --description 'OSI-layer network troubleshooting CLI for Windows and Linux' \
  --homepage 'https://networknet.nl/projects/osidiag/' \
  --source "$HOME/osidiag-public-baseline" --push
gh repo view ivanversluis/osidiag --json visibility,defaultBranchRef
# Compare REST numeric repository ID against original 1451585475:
gh api repos/ivanversluis/osidiag --jq '.id'
~~~

The new repository ID must differ from the old ID **1451585475**, and must contain exactly one root commit. Do not import historical branches, pull requests or tags. Old PR #19 and issue #10 URLs will not refer to those original records at the new canonical name. GitHub redirects to the renamed repo can stop when the original name is reused.

## 3. Verify and publish only the new repository

Reauthorize Apps, recreate branch/tag protection and CI checks, verify access controls and Actions permissions. Keep SIGNPATH_ENABLED false or unset until approved. Do not transfer signing credentials. Verify CI including Windows on the new repository before public disclosure.

~~~bash
gh repo edit ivanversluis/osidiag --visibility public --accept-visibility-change-consequences
gh repo view ivanversluis/osidiag --json visibility -q .visibility
git clone https://github.com/ivanversluis/osidiag.git /tmp/osidiag-public-verify
git -C /tmp/osidiag-public-verify rev-list --count main   # must be 1
~~~

Use a new local clone after the switch. Never merge the archived history into the new root.

## 4. First release, Networknet and SignPath

Create an **annotated** release tag on the reviewed new main. Verify checksum and build provenance, Windows portable executable and correct **unsigned** labelling. Once the release exists, update Networknet page frontmatter public_source and release_available to true, refresh status language and publish the announcement draft.

Apply at https://signpath.org/apply.html using SIGNPATH_APPLICATION.md after the real public release. SignPath describes author, reviewer and signing approver duties without explicitly requiring three different individuals, but eligibility is at its discretion. A single maintainer must not claim independent review of their own commits; a newly created public repository may also have limited public reputation. SignPath's vulnerability-scanner eligibility restriction must be assessed honestly.

The original repository remains **private**, not destroyed. The root-snapshot script is non-destructive; the remote cutover above requires deliberate operator action.
