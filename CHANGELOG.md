# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Releases are numbered from `v0.1.0`. The two before it, `v1.4.4-bt.1` and
`v1.4.4-bt.2`, were cut while this was still a fork, took upstream's last
version as their base, and have been withdrawn. Their entries below are kept
as history.

This project is derived from [FiloSottile/mkcert](https://github.com/FiloSottile/mkcert)
under its BSD-3-Clause licence and has been maintained independently since
2026-09-27. It does not track or contribute to the original, which has been
dormant since 2024-08. It began as a fork so that ws-scrcpy-web could vendor a
local-CA binary whose provenance we control. Entries below describe **our**
changes; the original history is unchanged beneath them.

## [Unreleased]

### Added

- **American-spelling gate** in the required `build-and-test` job: the checker
  from `bilbospocketses/american-spelling`, pinned to v1.0.2 by commit SHA,
  fails a PR whose added lines or commit messages use a British spelling.

### Fixed

- `CONTRIBUTING.md` now lists `CodeQL` among the required checks. It was made
  required after the file was written, so the list named only `build-and-test`
  and `Scorecard analysis`.

## [0.1.0] - 2026-09-27

First release as an independent project: a clean break from the original, and
the repository hardened. The code is the same as `v1.4.4-bt.2` apart from the
module path and one message string, so there is no change to certificate
output or to any flag. Every artefact carries a build-provenance attestation.

### Added

- **`build-and-test` check** in `test.yml`: one job that passes only when every
  OS in the Go tests matrix passed. It is the context the branch ruleset
  requires, so the ruleset does not have to name each matrix leg.
- **Dependabot version updates** (`.github/dependabot.yml`) for Go modules and
  for the SHA-pinned actions, weekly, minor and patch bumps grouped.
- **OpenSSF Scorecard** (`scorecard.yml`) on push, pull request, weekly and on
  ruleset changes, with SARIF uploaded to the Security tab.
- **`SECURITY.md`** (private reporting through GitHub security advisories, and
  what is in and out of scope), **`CONTRIBUTING.md`** (build, test, PR and
  release rules) and **`.github/CODEOWNERS`**.

### Changed

- **Module path is `github.com/bilbospocketses/mkcert`**, was `filippo.io/mkcert`.
  Under the old path the module could not be installed as itself: our path
  fetched a module declaring a different one, and the old path fetched the
  original. `go install github.com/bilbospocketses/mkcert@latest` now works.
- **Versioning restarts at `v0.1.0`**, plain `vX.Y.Z`. `release.yml` refuses any
  other tag shape, including the old `-bt.N` suffix, which also sorted as a
  prerelease *below* the version it was based on.
- When installing into the NSS stores fails, the message now points at this
  repository's issue tracker instead of the original's.
- README install instructions point at this project's releases and source, with
  a verified `gh release download` / `sha256sum` / `gh attestation verify`
  recipe. The package-manager instructions are gone: Homebrew, MacPorts,
  Chocolatey, Scoop and Arch all install the original v1.4.4.
- The attestation comment in `release.yml` no longer describes the repository
  as private.

### Removed

- The original project's 14 release tags, `v0.9.0` through `v1.4.4`. They
  pointed into history this repository still contains, but left two numbers
  of our own line already taken and made Go resolve `@latest` to the original's
  `v1.4.4`, which declares the old module path and so fails to install.
- Issue-template contact links that sent questions to the original project's
  Discussions.
- The two pre-break releases, `v1.4.4-bt.1` and `v1.4.4-bt.2`, are withdrawn
  and their tags deleted. Use `v0.1.0` or later.

## [1.4.4-bt.2] - 2026-09-19

Three features adopted from upstream's open backlog, each asked for repeatedly
there and none of it merged since the project went dormant in 2024-08.

### Added


- **`-name-constraints LIST`** — a comma-separated list of DNS suffixes and CIDR
  ranges the CA is permitted to sign for, e.g.
  `"example.test,192.168.0.0/16"`. Applied when the CA is created. A
  constrained CA bounds the damage if its private key is stolen, which matters
  here because the key's on-disk protection is weaker than it looks on Windows
  (see the `0400` note above).

  **Both halves are load-bearing.** X.509 applies name constraints *per name
  type*, so constraining DNS alone leaves IP addresses completely
  unconstrained. Measured against upstream PR #657, which sets only
  `PermittedDNSDomains`: a CA so constrained still signs `8.8.8.8` happily.
  mkcert now warns when only one name type is covered, because a
  half-constrained CA is more dangerous than an unconstrained one — it looks
  protected. The extension is marked critical, so a verifier that cannot
  understand it must reject rather than ignore it.

  Adopted from upstream #657, #302, #309, #487, extended with the IP half.

- **`-days INT`** — validity period for generated certificates. The default is
  unchanged at 2 years and 3 months. Warns above 825 days, the ceiling macOS
  and iOS apply to every certificate including locally-trusted ones.
  Adopted from upstream #513, #464, #339, #343.

- **`-ca-name NAME`** — the CA's name in trust stores, instead of
  `mkcert <user>@<host>`. Applied when the CA is created. The `user@host`
  provenance is kept in the organizational unit either way, since that is how
  you tell which machine minted a root you found in a store.
  Adopted from upstream #229, #260, #240.


## [1.4.4-bt.1] - 2026-09-19

First release from this fork: the review, the dependency bump, the hardening it
produced, and the pipeline that publishes it.


### Security

- **A URL-shaped argument no longer escapes the working directory.** `main.go`'s
  argument ladder accepts anything `url.Parse` reads as scheme-plus-host, and
  `fileNames` substituted only `:` and `*`, so `/` and `..` survived into the
  output path. Measured: run from `esc/a/b`,
  `mkcert "https://example.com/../../../pwned"` wrote its `.pem` and `-key.pem`
  into `esc/a`, printed the normal success banner, and exited 0 — private key
  material written outside the working directory, silently.
- **A CSR can no longer mint an intermediate CA off the local root.**
  `makeCertFromCSR` copied `csr.Extensions` into `ExtraExtensions` wholesale.
  The standard library appends `ExtraExtensions` verbatim and suppresses any
  generated extension sharing an OID, and `makeCertFromCSR` never set
  `BasicConstraintsValid` — the only gate on generating `basicConstraints` at
  all. A CSR requesting `CA:TRUE` therefore got it, unopposed. Requested
  extensions are now filtered before signing; everything other than
  `basicConstraints` still comes through.
- **Dependencies bumped off their 2022 pins**, picking up parser-hardening
  fixes in two libraries that read untrusted-ish input: `go-pkcs12` v0.2.0 →
  v0.7.3 (rejects invalid IV lengths and over-long keys) and `howett.net/plist`
  v1.0.0 → v1.0.1 (rejects bplist object lengths that overflow the parser).

### Fixed

- **An unrelated Java installation no longer aborts certificate generation.**
  `checkJava` ran keytool through `fatalIfCmdErr`, and with `JAVA_HOME` set that
  fires on *every* invocation — including a plain leaf generation with nothing
  to do with Java. A broken or partial JDK on the host killed the process. The
  check now warns and answers "no".
- **`fileNames` no longer panics on an empty host list.** `makeCertFromCSR`
  builds its host list from the generated certificate's SANs, which can
  legitimately come back empty, and `fileNames` indexed `hosts[0]`
  unconditionally.
- **`go vet` is clean on all three platforms**, for the first time in this
  codebase. The Windows trust-store code hand-rolled its crypt32 calls through
  `LazyProc`, which returns a `uintptr`, and converted that straight back to a
  pointer — `possible misuse of unsafe.Pointer`. It now uses the typed wrappers
  in `golang.org/x/sys/windows`, where a certificate context is never a
  `uintptr` at any point. The `(*[1 << 20]byte)` cast used to read certificate
  DER — which silently truncates anything larger than a megabyte — is replaced
  by `unsafe.Slice`.

### Changed

- **Go floor raised from 1.18 to 1.26.0**, set by the three `golang.org/x`
  modules' own declared minimums.
- `io/ioutil` replaced with `os` throughout, following its deprecation in
  Go 1.19.
- `pkcs12.Encode` replaced with `pkcs12.LegacyRC2.Encode`. The bare function is
  deprecated in favour of explicit encoders, and `LegacyRC2` is the
  behaviour-preserving one — verified against a generated bundle that
  certificates remain RC2-40 and the key 3DES, with no AES. Moving to `Legacy`
  (3DES) or `Modern` (AES-256) would be a deliberate behaviour change.

### Added

- **Tests, where the repository had none.** `go test -race ./...` previously
  passed because there was not a single `*_test.go` file — a green check that
  could not distinguish working from broken. There are now ten, including a
  full add/enumerate/delete round-trip against an in-memory Windows certificate
  store, which covers the one genuinely dangerous function here without
  touching the caller's real trust store.
- `go vet ./...` as a CI step, now that it can pass.
- This changelog, and a `.gitignore`.

### CI

- Every action pinned to a commit SHA; `actions/checkout` v2 → v7.0.1,
  `actions/setup-go` v2 → v7.0.0, both of which were on end-of-life Node
  runtimes.
- The test matrix no longer runs twice per commit. `on: [push, pull_request]`
  fires both events for a pull request from a branch in this repository, so
  every commit ran the full three-OS matrix twice.
- The Go version now comes from `go.mod` rather than floating `1.x`, so CI
  builds on exactly the floor the project claims to support.
- staticcheck pinned to 2026.2.1 instead of `@latest`, which recompiled it from
  source every job and changed the lint surface whenever upstream released.
- **`release.yml` rewritten.** It built with `git describe --tags` and uploaded
  through `actions/github-script@v3`. It now takes the version from the release
  tag, refuses any tag that is not `vX.Y.Z-bt.N` so our artefacts can never be
  confused with upstream's `v1.4.4`, builds seven platforms with `-trimpath`,
  publishes a `SHA256SUMS.txt` so a consumer fetching a binary at runtime has
  something to verify against, and attaches a sigstore build-provenance
  attestation. Its runner is pinned to `ubuntu-24.04`, unlike the test matrix.

## Fork history

Forked from upstream `1c1dc4e` (2024-08-13), mirroring `master` and all 14
tags. Certificate output measured before any change and unchanged since:
RSA-3072 root over RSA-2048 leaves, 3653-day CA, 822-day leaf, 128-bit serial
from `crypto/rand`, KU `DigitalSignature, KeyEncipherment`, EKU `serverAuth`.

Broke from upstream on 2026-09-27: the `upstream` remote was removed and the 14
mirrored tags were deleted. The commits they marked are still in this history.
