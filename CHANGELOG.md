# Changelog

All notable changes to this fork are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
with a fork suffix: our releases are tagged `v1.4.4-bt.N`, so an artefact can
never be confused with upstream's `v1.4.4`.

This is a private fork of [FiloSottile/mkcert](https://github.com/FiloSottile/mkcert),
maintained so that ws-scrcpy-web can vendor a local-CA binary whose provenance
we control. Upstream has been dormant since 2024-08 and its last release,
v1.4.4, is from 2022. Entries below describe **our** changes; upstream history
is unchanged beneath them.

## [Unreleased]

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
