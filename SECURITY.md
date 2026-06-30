# Security Policy

## Status

PostQuantum.LMS.Signer is **1.0** software: the public API and the on-disk/wire formats
are stable. The core LMS/HSS implementation is cross-validated against BouncyCastle and
pinned known-answer vectors, but it has **not** undergone an independent third-party audit
or a formal side-channel review. **Do not make a CNSA 2.0 / production assurance claim on
the basis of this library alone** until you have commissioned that review.

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅ security fixes |
| < 1.0 (preview) | ❌ |

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue for an
exploitable flaw.

- Preferred: open a [GitHub private security advisory](https://github.com/systemslibrarian/postquantum-lms-signer/security/advisories/new).
- Or email the maintainer (see the GitHub profile for `systemslibrarian`).

Please include: affected version/commit, a description, and a proof-of-concept or
reproduction steps if possible. We aim to acknowledge within **72 hours** and to agree a
disclosure timeline with you. We support coordinated disclosure and will credit reporters
who wish to be named.

## What we consider a vulnerability

Because this is a **stateful** signature scheme, the highest-severity class of bug is
**anything that can cause a one-time-key index to be reused.** Examples we treat as
critical:

- A code path that signs without first durably persisting the advanced index.
- A way to defeat the compare-and-swap guard in `IStateStore` and double-sign an index.
- Incorrect HSS subtree re-keying that reissues an already-used leaf.
- A wire-format/parsing flaw that lets a forged signature verify.

## Known, documented limitations (not "vulnerabilities" — by design)

Stateful hash-based signatures have a fundamental limit that **no pure-software library
can overcome**: if the entire machine state is rolled back (a restored VM snapshot or
disk backup), the monotonic counter rolls back with it and key reuse becomes possible.

This is documented in [README.md](README.md) (“⚠️ Don't do this”) and
[CLAUDE.md](CLAUDE.md). The mitigation is operational/hardware: an HSM or a hardware
monotonic counter (e.g., TPM), and never snapshotting/restoring a live signer. Reports
that amount to "I restored an old snapshot and reused a key" describe this known
limitation rather than a library defect.

## Cryptographic scope

This release implements **all NIST SP 800-208 parameter sets**: SHA-256 and SHAKE256, at both
full (n=32) and truncated (n=24) output — all 16 LM-OTS and 20 LMS typecodes. The non-SHA-256/n32
families are cross-validated byte-for-byte against BouncyCastle.

To God be the glory.
