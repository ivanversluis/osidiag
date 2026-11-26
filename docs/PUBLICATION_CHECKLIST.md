# Public release security and publication checklist

**Do not change repository visibility until all checks are complete.** On 11 November 2026, osidiag is a private GitHub repository and has no GitHub Releases. Adding a public-facing Networknet page does not make the source public.

## Clean-history publication boundary

Merge PR #19 while the original repository stays private, then use [PUBLIC_BASELINE.md](PUBLIC_BASELINE.md) to create a separate repository with one root commit. Squash merges or force pushes do not reliably erase old GitHub PR references. The original history remains in a separately named **private** repository; the new canonical URL points to a distinct repository. Never make the original private repository public.

## Review the complete history, not only main

Review all reachable branches, tags, PR heads, GitHub Actions logs/artifacts and commit messages. Search for secrets, tokens, private keys, passwords, personal data, internal enterprise hostnames/URLs/IPs, corporate assets, copied code, and license violations. Inspect generated binaries and images too; checking only current files is insufficient.

```bash
git clone --mirror git@github.com:ivanversluis/osidiag.git osidiag-audit.git
cd osidiag-audit.git
git show-ref
git log --all --format='%H %an <%ae> %s'
git rev-list --objects --all > ../osidiag-all-objects.txt
# Use gitleaks or equivalent against the complete reachable history,
# and inspect all branches / tags / binaries / artifacts outside this command.
```

Review all source, docs, tests, generated binaries and CI artifacts before disclosure. Rotate any credentials found rather than assuming that removing them from the current tree is enough.

## Before visibility change

- [ ] Review the exported current source and all private artifacts; verify the new public repository has one root commit and no historical refs.
- [ ] Remove or replace any confidential corporate endpoints/branding and confirm software ownership.
- [ ] Confirm Apache-2.0 and authorship/licensing of all source code and artwork.
- [ ] Confirm no unapproved third-party executables are bundled; Go build uses only declared dependencies.
- [ ] Protect `main` and `v*` release tags with reviews and CI checks; enable GitHub 2FA.
- [ ] Verify `go test ./...`, `go vet ./...` and native Windows CI.
- [ ] Review publicly accessible README, policy and reporting contacts.
- [ ] Confirm `networknet.nl/projects/osidiag/` and its signing-policy subpage are publicly available.
- [ ] Rename the old repository without changing its private visibility; create a **new private** canonical osidiag repository from the verified root snapshot, then make **only the new repository** public after review.
- [ ] Create the first annotated release tag from the current reviewed `main`; inspect the Windows unsigned label and SHA256SUMS/provenance.
- [ ] Test on a clean Windows 11 VM. Record expected SmartScreen behaviour, no system changes and uninstall by deleting binary.
- [ ] Submit the Foundation application using `docs/SIGNPATH_APPLICATION.md`; set signing variables **only after approval**.

If a secret exists in historical commits, stop, rotate it and choose a safe remediation path with backups and collaborator coordination. History rewriting or creating a new clean public repository requires separate review. This checklist documents required actions; none are marked complete just because the file exists.
