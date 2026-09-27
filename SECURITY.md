# Security Policy

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Report them privately through GitHub's security advisory flow:

**[Report a vulnerability](https://github.com/bilbospocketses/mkcert/security/advisories/new)**

That opens a private channel with the maintainer. Nothing is disclosed publicly
until a fix is ready.

## What to include

- A description of the vulnerability and its impact
- Steps to reproduce: the exact `mkcert` command line, the `CAROOT` and
  `TRUST_STORES` values in effect, and the OS
- The affected version (`mkcert -version`)
- Any mitigation you know of

## Response expectations

- **Acknowledgement:** within **72 hours**
- **Triage and initial assessment:** within one week
- **Fix and disclosure timeline:** agreed with the reporter per issue,
  depending on severity

## Supported versions

Fixes go into the next release. Only the latest release is supported.

## Scope

mkcert creates a local certificate authority, installs it into system and
browser trust stores, and issues certificates signed by it. Anything that
weakens that is in scope, for example:

- a way to get the CA private key (`rootCA-key.pem`) read, logged, copied or
  written anywhere other than `CAROOT`
- a certificate issued with names, key usages, validity or basic constraints
  other than the ones requested, including a way around `-name-constraints`
- a way to make `mkcert` write files outside the paths it was given
- weak randomness in keys or serial numbers

Out of scope:

- Anything that requires the attacker to already hold `rootCA-key.pem`. That
  file can sign a certificate for any name, which is exactly why the README
  says never to share it.
- On Windows, `CAROOT`'s file permissions come from its parent directory. Go
  sets no ACL, so pointing `CAROOT` at a shared location such as `ProgramData`
  exposes the key. That is a configuration choice, not a bug.
- Bugs in the original [FiloSottile/mkcert](https://github.com/FiloSottile/mkcert)
  that do not reproduce here. Report those there.
- Bugs in the operating system's or a browser's trust store.
