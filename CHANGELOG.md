# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Versioning.** As of `1.0.0` this project follows [Semantic Versioning](https://semver.org/):
> no breaking API or on-disk/wire-format changes within the 1.x line. `1.0` is a **stability**
> promise, **not** an audited-assurance claim — see [/SECURITY.md](/SECURITY.md) and
> [/docs/security-assurance.md](/docs/security-assurance.md) for the current assurance status.

## [Unreleased]

## [1.0.0] - 2026-06-30

First stable release. **`1.0` denotes API and format stability — not an independent
cryptographic audit** (none has been performed; see the Security note below).

### Changed

- **Stable API and on-disk/wire-format guarantee.** The public API and the persisted state
  format are now covered by Semantic Versioning: no breaking changes within the 1.x line.
- **Maturity labels updated** from "stable, preview" to **stable** across the README package
  and capability tables; status badge and documentation reflect 1.0.
- **Documentation aligned with shipped supply-chain assurances** — the security-assurance
  supply-chain section now records SBOMs, build-provenance attestations, CI fuzzing, CodeQL,
  and Trusted-Publishing as *in place* rather than planned.

### Fixed

- **HSS re-key fault no longer risks index reuse.** `HssSigner.SignAsync` now advances state
  (`PrepareNext`, including subtree re-keying) *inside* the persist-or-restore guard, and
  `HssEngine.Rekey` builds the fresh subtree and parent chain signature into locals before
  committing any field. Previously, a fault during re-keying (e.g. an allocation failure while
  building the new subtree) could leave the in-memory engine partially mutated — counter reset
  but the old, exhausted tree still in place — so a process that caught the fault and kept
  signing on the same instance could reuse a one-time-key index. A crash/restart was already
  safe (durable state was never advanced); this closes the fault-and-continue window.

### Security

- This release has **not** had an independent third-party cryptographic audit or a formal
  side-channel review. Do not make a CNSA 2.0 / production assurance claim on the basis of
  this library alone; commission your own review where required. See
  [/docs/security-assurance.md](/docs/security-assurance.md).
- **Dependency hardening** — pinned the transitive native SQLite binary
  (`SQLitePCLRaw.lib.e_sqlite3`) to a patched release to clear advisory GHSA-2m69-gcr7-jv3q,
  which affected the `PostQuantum.LMS.Signer.Sqlite` dependency graph.

## [0.9.2] - 2026-06-16

Documentation-only release to refresh the NuGet package page (no library code changes).

### Changed

- **README renders cleanly on NuGet.org** — removed the centered raw-HTML wrappers that NuGet's
  Markdown sanitizer mangled, and converted all relative documentation/sample links to absolute
  `github.com` URLs so they resolve on the package page instead of 404-ing.
- **Accurate package maturity** — the Analyzers package (three tested rules, `PQLMS001`–`PQLMS003`)
  and the Templates package (a working `dotnet new` firmware-signer) are no longer mislabeled as
  "preview skeletons."
- Documented the move to **NuGet Trusted Publishing** (OIDC) in place of a stored `NUGET_API_KEY`.

## [0.9.1] - 2026-06-15

First published release on NuGet.org. Carries the state-safety hardening below on top of 0.9.0.

### Fixed

- **Disposal-race hardening** — `Dispose()` now acquires the gate / init-lock before releasing
  resources across `HssSigner`, `LmsSigner`, `HssSigningService`, and `SqliteStateStore`, so disposal
  cannot race a concurrent operation (e.g. zeroing the LMS seed or disposing a semaphore mid-sign).

## [0.9.0] - 2026-06-15

Preview milestone: full SP 800-208 parameter coverage, a relational state store, productionized
ASP.NET Core + Hybrid, samples, benchmarks, fuzz tests, and supply-chain automation (SBOM,
provenance, checksums). Pre-1.0 — APIs may still change; see the assurance status before production use.

### Added

- **Full SP 800-208 parameter-set coverage** — all 16 LM-OTS and 20 LMS typecodes: SHA-256 and
  SHAKE256, at both full (n=32) and truncated (n=24) output; the n=24 and SHAKE families are
  cross-validated byte-for-byte against BouncyCastle.
- **Analyzer rules PQLMS002 / PQLMS003** — flag a discarded (unawaited) `SignAsync` result, and
  suggest `SignAsync` over the blocking synchronous `Sign`.
- **SQLite state store (`PostQuantum.LMS.Signer.Sqlite`)** — `SqliteStateStore`, a relational
  `IStateStore` reference backend with crash-safe compare-and-swap (conditional `UPDATE … WHERE
  version` under `BEGIN IMMEDIATE`); conformance-tested; the pattern ports to PostgreSQL/SQL Server.
- **Hybrid promoted to production** — ML-DSA key generation/import/export (`MlDsaKeyPair`),
  portable `HybridPublicKey` bundle, one-call verify requiring both legs.
- **ASP.NET Core promoted to production** — pluggable `IStateStore` (Redis/EF/HSM ready) via
  `LmsSignerOptions.StateStoreFactory`, options validation, low-budget warning, and
  `LmsSignerHealthCheck` for capacity observability.
- **Samples** — runnable `FirmwareSigning.Console` and `FirmwareSigning.Web` reference apps.
- Precise package **maturity matrix** in the README.
- Security assurance document ([/docs/security-assurance.md](/docs/security-assurance.md)):
  assurance status, threat-model summary, claimed-vs-not-claimed side-channel properties,
  non-goals, residual risks, and the supply-chain roadmap.
- Operator playbook ([/docs/operations.md](/docs/operations.md)): approved/forbidden
  deployment patterns, backup/restore/do-not-restore runbook, HSM/TPM integration guidance,
  key rotation & exhaustion management, observability, incident response, and the custom
  `IStateStore` validation checklist.
- CodeQL static-analysis workflow ([/.github/workflows/codeql.yml](/.github/workflows/codeql.yml)).
- **Benchmarks** (`benchmarks/`, BenchmarkDotNet) — head-to-head vs BouncyCastle for the firmware
  parameter set; results and honest analysis in [/docs/benchmarks.md](/docs/benchmarks.md).
- **Fuzz / negative-corpus tests** — verifiers never throw on arbitrary bytes; mutated/truncated
  signatures always fail closed; state and hybrid decoders throw only their documented exception type;
  corrupted state files are rejected. Runs as part of the CI test suite.
- **Release supply-chain automation** ([/.github/workflows/release.yml](/.github/workflows/release.yml)):
  tag-driven pack, per-package **CycloneDX SBOMs**, **SHA-256 checksums**, **build-provenance
  attestations** (`actions/attest-build-provenance`), optional code-signing and NuGet publish (secret-gated),
  and a GitHub Release with all artifacts attached. Verification steps in
  [/docs/releasing.md](/docs/releasing.md).

### Planned (not yet implemented)

- Author-signed NuGet packages (wired in release.yml; pending a code-signing certificate secret).
- NuGet publish on tag (wired; pending the `NUGET_API_KEY` secret).
- Independent third-party security/cryptography audit.

## [0.1.0-preview.1]

Initial preview. Stateful hash-based signatures (NIST SP 800-208 / RFC 8554, LMS & HSS) for
.NET, with crash-safe, never-reuse state management as the headline feature.

### Added

- **Core (`PostQuantum.LMS.Signer`)** — pure-managed LMS (`LmsSigner`) and HSS (`HssSigner`)
  signers; SHA-256 (n=32) RFC 8554 parameter sets; verification with no state required.
  Cross-validated byte-for-byte against BouncyCastle (test-only oracle) and pinned KATs.
- **State engine** — `IStateStore` contract requiring atomicity, durability, and
  compare-and-swap on a monotonic version; persist-before-sign ordering so a crash can waste
  an index but never reuse one; transparent, atomic HSS subtree re-keying.
- **`FileStateStore`** — crash-safe file-backed store: temp-write → flush → atomic rename,
  retained `.bak` (not auto-loaded), SHA-256 integrity tag rejected on load, exclusive lock
  file for the read-verify-write window. `InMemoryStateStore` for tests.
- **Exceptions** — `LmsStateException` (CAS mismatch / corrupt or tampered state),
  `LmsKeyExhaustedException` (terminal end-of-life), `LmsStateReuseException`, under the
  `LmsException` base type.
- **Testing (`PostQuantum.LMS.Signer.Testing`)** — known-answer vectors plus the
  `StateStoreConformance` harness (`AssertConformsAsync`, `AssertPreventsReuseAsync`) to prove
  a custom `IStateStore` is reuse-safe, and a reuse-attack lab.
- **CLI (`pqlms`, `PostQuantum.LMS.Signer.Cli`)** — `keygen`, `sign`, `verify`, `inspect`,
  `pubkey`; dependency-free, AOT-friendly argument parsing.
- **Hybrid (`PostQuantum.LMS.Signer.Hybrid`)** — composite LMS/HSS + ML-DSA (FIPS 204, via
  BouncyCastle) signatures where **both** legs must verify, with ML-DSA key management and a
  bundled public key.
- **ASP.NET Core (`PostQuantum.LMS.Signer.AspNetCore`)** — DI integration: `AddLmsSigner`,
  `ILmsSigningService`, file-backed signing service. (Preview skeleton.)
- **Analyzers (`PostQuantum.LMS.Signer.Analyzers`)** — Roslyn rule `PQLMS001`: flags
  `InMemoryStateStore` for a persistent key. (Preview skeleton.)
- **Templates (`PostQuantum.LMS.Signer.Templates`)** — `dotnet new pqlms-firmware-signer`
  scaffold. (Preview skeleton.)
- Builds target `net8.0`; the test suite runs on **.NET 8 and .NET 10**.

### Security

- This release has **not** had an independent third-party audit or a formal side-channel
  review. Do not make a CNSA 2.0 / production assurance claim on this library alone yet. See
  [/docs/security-assurance.md](/docs/security-assurance.md).
- Whole-machine rollback (restored VM snapshot or disk backup) can rewind the state counter
  and cause one-time-key reuse; this is not defendable in pure software. See
  [/docs/operations.md](/docs/operations.md).

[Unreleased]: https://github.com/systemslibrarian/postquantum-lms-signer/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/systemslibrarian/postquantum-lms-signer/compare/v0.9.2...v1.0.0
[0.9.2]: https://github.com/systemslibrarian/postquantum-lms-signer/compare/v0.9.1...v0.9.2
[0.9.1]: https://github.com/systemslibrarian/postquantum-lms-signer/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/systemslibrarian/postquantum-lms-signer/releases/tag/v0.9.0
[0.1.0-preview.1]: https://github.com/systemslibrarian/postquantum-lms-signer/releases/tag/v0.1.0-preview.1
