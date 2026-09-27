# Contributing to mkcert

Thanks for your interest. This covers building, testing, and how changes land.

## Prerequisites

- **Go 1.26 or later.** The floor is the `go` directive in `go.mod`, and CI builds
  on exactly that version.
- **staticcheck 2026.2.1**, the version CI pins:
  `go install honnef.co/go/tools/cmd/staticcheck@2026.2.1`

## Build and test

```
go build ./...
go test -race ./...
go vet ./...
staticcheck ./...
```

CI runs all four on Linux, macOS and Windows. Run them before opening a PR.

**Never let a test create a CA in your real `CAROOT`.** Point `CAROOT` at a
temporary directory, and set `TRUST_STORES=none` so nothing is installed into
a system or browser trust store.

## Pull requests

`master` is PR-only. Direct pushes are rejected by a repository ruleset.

- **Required checks:** `build-and-test` (the Go tests matrix on all three OSes),
  `CodeQL` (code scanning for Go and Actions; it reports `neutral` on a PR it
  has nothing to scan, which still passes) and `Scorecard analysis`. With strict
  status checks, a PR that falls behind `master` has to be updated before it
  can merge.
- **Squash merge only.**
- **Signed commits only.** Unsigned commits cannot reach `master`, and `v*` tags
  must be signed.
- Keep a PR to one concern.
- Add an entry to `CHANGELOG.md` under `[Unreleased]` for any user-visible
  change. Do not add a version heading yourself.

## Workflow files

`sha_pinning_required` is on, so every `uses:` must be pinned to a full commit
SHA, including inside composite actions. Pin to the **commit**, not the
annotated-tag object, and give it a precise version comment (`# v7.0.1`, never
`# v7`) so Dependabot can see and bump it. Only GitHub-owned actions and
`ossf/scorecard-action` are allowed to run.

## Releases

Releases are plain `vX.Y.Z` tags, from `v0.1.0`. `release.yml` refuses any other
shape. Publishing a GitHub release builds the binaries for seven platforms,
writes `SHA256SUMS.txt`, attests every artefact, and uploads them.

## Reporting bugs

Open an issue with the OS and version, `mkcert -version`, the exact command,
and what went wrong. For a trust-store problem, say which browser or tool
rejected the certificate.

## Reporting security issues

Do **not** open a public issue. See [SECURITY.md](SECURITY.md).

## License

By contributing you agree that your contributions are licensed under the
project's [BSD-3-Clause](LICENSE) licence.
