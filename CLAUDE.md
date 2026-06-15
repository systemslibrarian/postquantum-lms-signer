# CLAUDE.md — PostQuantum.LMS.Signer maintenance guide

This file orients future contributors (human or AI) working in this repository. Read it before
changing anything under `src/`, and treat the **state-safety invariants** below as non-negotiable.

## Project purpose

PostQuantum.LMS.Signer is a production-grade, auditable .NET implementation of **NIST SP 800-208** /
**RFC 8554** stateful hash-based signatures — **LMS** (Leighton–Micali Signatures) and **HSS**
(Hierarchical Signature System). These are conservative, quantum-resistant signature schemes whose
security rests only on the second-preimage resistance of a hash function, which makes them an excellent
fit for long-lived, high-assurance use cases: **firmware signing, secure boot, and code signing**.

The headline feature is not raw speed; it is **never reusing a one-time key index**, enforced through
crash-safe state management.

## The crypto-core decision

- The core (`src/PostQuantum.LMS.Signer/`) is a **pure managed** implementation — no native
  dependencies — so it is trimmable and AOT-compatible for embedded and signing-service scenarios.
- Correctness is established by validating the core **byte-for-byte against BouncyCastle as an oracle**
  (see `tests/.../LmsBouncyCastleCrossCheckTests.cs`). BouncyCastle is a test/oracle dependency, not a
  runtime dependency of the core.
- **The core is locked.** Do not modify, delete, or rewrite files under `src/PostQuantum.LMS.Signer/`,
  `tests/`, or the root build files (`*.sln`/`*.slnx`, `Directory.Build.props`,
  `Directory.Packages.props`, `.editorconfig`, `.gitignore`, `README.md`).

## State-safety invariants (the whole point)

A stateful hash-based signature scheme is catastrophically broken if a one-time key (OTS) index is ever
used twice. The design enforces these invariants:

1. **Persist-before-sign.** The signer advances the index and **durably persists** the new state
   *before* the signature is released. A crash can at worst *waste* an index, never *reuse* one.
2. **Never reuse an index.** Every signature consumes a distinct OTS leaf; exhausted subtrees are
   transparently and safely re-keyed (HSS).
3. **Compare-and-swap in `IStateStore`.** `SaveAsync` succeeds only if the stored version equals the
   expected version; a losing writer is told to stop (`LmsStateException`) rather than silently advance.
   This is what makes multi-process/multi-node backing of one key safe.
4. **`FileStateStore` is atomic + integrity-checked.** It writes to a temp file, flushes to disk, then
   atomically **renames** it over the target (keeping a `.bak`), holds an exclusive lock file for the
   read-verify-write window, and tags every record with a **SHA-256 checksum** so a torn or tampered
   file is detected on load instead of producing a reused index.

## Package map

| Package | Path | Purpose |
|---|---|---|
| **Core** | `src/PostQuantum.LMS.Signer/` | Locked LMS/HSS engine, state stores, exceptions. (`net8.0`) |
| **Testing** | `src/PostQuantum.LMS.Signer.Testing/` | KAT vectors + `StateStoreConformance` harness + reuse lab (framework-agnostic). (`net8.0`) |
| **Cli** | `src/PostQuantum.LMS.Signer.Cli/` | `pqlms` keygen/sign/verify/inspect/pubkey. (`net8.0`) |
| **Sqlite** | `src/PostQuantum.LMS.Signer.Sqlite/` | `SqliteStateStore` — relational `IStateStore` with CAS; reference DB backend. (`net8.0`) |
| **AspNetCore** | `src/PostQuantum.LMS.Signer.AspNetCore/` | DI: `AddLmsSigner`, `ILmsSigningService`, pluggable stores, options validation, `LmsSignerHealthCheck`. (`net8.0`) |
| **Hybrid** | `src/PostQuantum.LMS.Signer.Hybrid/` | Defense-in-depth composite: HSS + ML-DSA (FIPS 204) where **both** must verify; `MlDsaKeyPair`, `HybridPublicKey`. (`net8.0`) |
| **Analyzers** | `src/PostQuantum.LMS.Signer.Analyzers/` | Roslyn analyzer (`PQLMS001`: don't use `InMemoryStateStore` for a persistent key). (`netstandard2.0`) |
| **Templates** | `templates/PostQuantum.LMS.Signer.Templates/` | `dotnet new pqlms-firmware-signer` scaffold. |
| **Samples** | `samples/` | Runnable console + ASP.NET Core reference apps. |

## How to build & test

```bash
dotnet restore
dotnet build -c Release
dotnet test -c Release
```

- The test project multi-targets **net8.0** and **net10.0**; CI installs both SDKs (see
  `.github/workflows/ci.yml`).
- A tag push (`v*`) additionally runs `dotnet pack -c Release` in a separate `pack` job.

## Coding conventions

- `Nullable` enabled; write nullable-correct code.
- **File-scoped namespaces** (except the analyzer, which targets `netstandard2.0`).
- Explicit `public` accessibility modifiers.
- **`TreatWarningsAsErrors` and `GenerateDocumentationFile` are ON globally** — every public type/member
  needs XML `///` docs, and there must be zero warnings. Prefer fixing over suppressing; if you must
  suppress, do it narrowly with a per-project `<NoWarn>` and a comment explaining why.
- **Central Package Management**: `<PackageReference Include="X" />` with **no** `Version`. Versions live
  in `Directory.Packages.props` (do not edit it without coordination). The analyzer project opts out of
  CPM locally because analyzer SDK pinning conflicts with it.

## DANGER — stateful-signature pitfalls

Stateful signatures break the usual "backups are always safe" intuition. **The state IS the secret.**

- **VM snapshot / container rollback.** Reverting a signer host to an earlier snapshot rewinds the
  index. Signing after a rollback **reuses** indices already used post-snapshot. Never snapshot-restore a
  live signing host and resume signing.
- **Key cloning / copying.** Never copy a state directory to a second machine and sign from both. Two
  copies advancing independently *will* reuse indices. Use one authoritative writer (or the CAS path).
- **Backups.** A restored backup is an old, lower index. Restoring after additional signing reintroduces
  reuse. Backups are for *disaster identification*, not for resuming signing past the restore point.
- **`InMemoryStateStore`.** Convenient for tests only — it is not crash-safe and loses state on exit.
  The `PQLMS001` analyzer flags its use; heed it. Use `FileStateStore` (or another crash-safe,
  CAS-capable `IStateStore`) for anything that outlives the process.

When in doubt: a wasted index is fine; a reused index is a security incident.

To God be the glory.
