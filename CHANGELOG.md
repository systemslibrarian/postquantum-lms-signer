# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Preview notice.** This project is in **preview**. Until a `1.0.0` release, minor and patch
> versions may include breaking changes. See [/SECURITY.md](/SECURITY.md) and
> [/docs/security-assurance.md](/docs/security-assurance.md) for the current assurance status.

## [Unreleased]

### Added

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
- SHAKE256 and truncated (n=24) RFC 8554 parameter sets (currently throw when selected).

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

[Unreleased]: https://github.com/systemslibrarian/postquantum-lms-signer/compare/v0.1.0-preview.1...HEAD
[0.1.0-preview.1]: https://github.com/systemslibrarian/postquantum-lms-signer/releases/tag/v0.1.0-preview.1
