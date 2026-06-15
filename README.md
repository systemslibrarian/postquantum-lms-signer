<div align="center">

# 🛡️ PostQuantum.LMS.Signer

### Stateful hash-based signatures for .NET — built for firmware, secure boot, and code signing in the post-quantum era.

**NIST SP 800-208 · RFC 8554 · LMS & HSS · CNSA 2.0-aligned**

*Quantum-resistant today. Auditable by design. Obsessed with the one thing that actually breaks stateful signatures: **state.***

[![.NET](https://img.shields.io/badge/.NET-8.0%20%7C%2010.0-512BD4)](https://dotnet.microsoft.com/)
[![Spec](https://img.shields.io/badge/spec-RFC%208554%20%2F%20SP%20800--208-0a7)](https://datatracker.ietf.org/doc/html/rfc8554)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Status](https://img.shields.io/badge/status-preview-orange)]()

</div>

---

## Why this exists

When a cryptographically-relevant quantum computer arrives, Shor's algorithm breaks RSA and ECDSA — the signatures that today protect **firmware updates, secure boot chains, and signed code**. Those artifacts live in devices for 10–20 years. The signature you ship today must still be trustworthy in 2040.

**Hash-based signatures (LMS/HSS)** are the most conservative answer we have. Their security rests only on the collision/preimage resistance of a hash function — no new number-theoretic assumptions. That's why they were the **first** post-quantum signatures standardized (NIST SP 800-208, 2020) and why **CNSA 2.0 names LMS/XMSS for software/firmware signing**.

There's one catch, and it is the whole game:

> **LMS/HSS are *stateful*. Every signature consumes a one-time key. Sign two different messages with the same key index and you leak the private key.**

Most libraries hand you the math and wish you luck with the state. **This library treats state as the product.**

---

## What it gives you

| | |
|---|---|
| 🧮 **Pure-managed core, independently verified** | A clean, allocation-conscious RFC 8554 implementation — no native blobs, trim/AOT-friendly. Validated **byte-for-byte against BouncyCastle** and pinned known-answer vectors. Public keys and signatures interoperate with any conformant implementation. |
| 🔒 **State safety is the headline feature** | Persist-**before**-sign ordering, atomic crash-safe storage, integrity-checked state files, and **compare-and-swap** anti-reuse guards that refuse a stale or cloned signer instead of silently reusing a key. |
| 🏭 **Firmware-first defaults** | One line gives you the CNSA 2.0-aligned recommendation: two-level HSS, SHA-256, h=10/10, w=8 → **~1,048,576 signatures**, compact output, fast startup. |
| 🧰 **A real ecosystem, not a single DLL** | Core + ASP.NET Core DI + Hybrid (LMS/HSS **and** ML-DSA) + Roslyn analyzers + a `dotnet new` template + a framework-agnostic Testing package + a `pqlms` CLI. |
| 📜 **Honest about the threat model** | We document exactly what software state *cannot* defend against (whole-disk rollback / VM snapshots) and where you need an HSM or hardware monotonic counter. No overclaiming. |

---

## Install

```bash
dotnet add package PostQuantum.LMS.Signer
dotnet tool install -g PostQuantum.LMS.Signer.Cli   # the 'pqlms' command
```

---

## 60-second quickstart

```csharp
using PostQuantum.Lms;
using PostQuantum.Lms.State;

// Crash-safe, on-disk state store. The directory IS the key — guard it accordingly.
var store = new FileStateStore("/var/lib/firmware-signer/state");

// Generate a key once (refuses to overwrite an existing one).
using (var signer = await HssSigner.CreateAsync(HssParameters.FirmwareDefault, store, keyId: "fw-2026"))
{
    File.WriteAllBytes("fw-2026.pub", signer.PublicKey());   // ~1,048,576 signatures available
}

// ...later, on every release: load, sign, repeat.
using (var signer = await HssSigner.LoadAsync(store, "fw-2026"))
{
    byte[] image = File.ReadAllBytes("firmware-v3.bin");
    byte[] signature = await signer.SignAsync(image);        // index advanced & persisted FIRST
    File.WriteAllBytes("firmware-v3.sig", signature);
    Console.WriteLine($"{signer.SignaturesRemaining:N0} signatures left");
}

// Verification needs no state — ship the public key to your devices.
bool ok = HssSigner.Verify(
    File.ReadAllBytes("fw-2026.pub"),
    File.ReadAllBytes("firmware-v3.bin"),
    File.ReadAllBytes("firmware-v3.sig"));
```

### …or from the command line

```bash
pqlms keygen  --store ./state --key-id fw-2026 --params firmware-default --pubkey-out fw.pub
pqlms sign    --store ./state --key-id fw-2026 --in firmware-v3.bin --out firmware-v3.sig
pqlms verify  --pubkey fw.pub --in firmware-v3.bin --sig firmware-v3.sig
pqlms inspect --store ./state --key-id fw-2026     # capacity, used, remaining
```

---

## The state-safety model (read this part)

A stateful signature scheme is exactly as safe as the discipline around its counter. Here is ours, concretely:

1. **Persist before sign.** `SignAsync` advances the one-time-key index and *durably writes it* **before** the signature is computed. A crash at any instant can at worst *waste* a key — it can never *reuse* one.
2. **Atomic, integrity-checked storage.** `FileStateStore` writes to a temp file, flushes to disk, then atomically renames over the target, keeping a `.bak`. Every record carries a SHA-256 tag, so a torn or tampered file is rejected on load rather than silently producing a reused index.
3. **Compare-and-swap anti-reuse.** `IStateStore.SaveAsync` only succeeds if the stored version matches what the signer last saw. Two processes (or a cloned key) racing to advance the same index? The loser is **refused** with an exception — not allowed to reuse.
4. **Transparent, safe HSS re-keying.** When a bottom subtree fills, a fresh subtree is generated and re-signed by the parent — automatically, and persisted atomically like everything else.

```csharp
// The anti-reuse guard in action — two signers from one key (a clone, or two pods):
using var a = await HssSigner.LoadAsync(store, "fw-2026");
using var b = await HssSigner.LoadAsync(store, "fw-2026");

await a.SignAsync(msg);                              // ✅ advances the store
await b.SignAsync(msg);                              // ❌ throws LmsStateException — reuse prevented
```

### Threat model — what software *can't* do alone

| Threat | Defense |
|---|---|
| Crash mid-sign | ✅ Persist-before-sign (waste, never reuse) |
| Cloned key / concurrent signers | ✅ Compare-and-swap in the store |
| Corrupted/tampered state file | ✅ SHA-256 integrity tag on load |
| **Whole-disk rollback / VM snapshot restore** | ⚠️ **Not defendable in pure software** — the version counter rolls back too. Use an HSM, a TPM/hardware monotonic counter, or never snapshot a live signer. We say so loudly rather than pretend otherwise. |

> **Golden rule:** the state directory *is* the private key. Never restore it from a backup while signing continues. Never run two signers against one key without a coordinating (CAS-capable) store.

### ⚠️ Don't do this (plain English)

These signatures stay safe only because an internal counter **never goes backwards**. Anything that secretly rewinds that counter makes the signer reuse a key — and a reused key leaks the private key. Software can stop almost every cause, but it **cannot** detect a rewind of the whole machine. So:

- ❌ **Don't snapshot a VM that's signing and later restore the snapshot.** The counter is restored too, and the next signatures repeat ones you already made.
- ❌ **Don't restore the signer (or its state folder) from a backup** while it's still in use.
- ❌ **Don't copy the state folder to another machine and keep signing on both.**
- ❌ **Don't run two copies of the signer against the same state folder** without a coordinating store.

✅ **Safe normal use:** one signer, one state folder, on a machine you don't roll back. That's it. If you genuinely need rollback-proof guarantees (e.g. high-assurance environments), put the key/counter in an **HSM** or behind a **hardware monotonic counter** that physically can't go backwards.

> If none of the above describes your setup, you have nothing to worry about — this is "here's the sharp edge, don't grab it," not "something is broken."

---

## Choosing parameters

| Use case | Preset | Signatures | Notes |
|---|---|---|---|
| **Firmware / code signing (default)** | `HssParameters.FirmwareDefault` | ~1,048,576 | HSS L=2, SHA-256, h=10/10, w=8. CNSA 2.0-aligned, compact sigs, fast startup. |
| Bounded release count | `HssParameters.SingleLevel` | 32,768 | Single h=15 tree, simplest state. |
| Tests / demos | `HssParameters.Small` | 1,024 | h=5/5, fast. |
| Custom | `new HssParameters(new LmsParameters(LmsAlgorithm.Sha256M32H10, LmOtsAlgorithm.Sha256N32W8), ...)` | — | Mix any SP 800-208 SHA-256 sets, 1–8 levels. |

`w` trades size for speed: **w=8** → smallest signatures (best for firmware), more hashing. **w=1** → largest signatures, least hashing.

---

## Packages

| Package | What it gives you | Status |
|---|---|---|
| **PostQuantum.LMS.Signer** | Core LMS & HSS signers, parameters, `IStateStore`, file/in-memory stores | ✅ Production |
| **PostQuantum.LMS.Signer.Testing** | Known-answer vectors + an `IStateStore` **conformance harness** (prove your Redis/EF/HSM store is reuse-safe) + reuse-attack lab | ✅ Production |
| **PostQuantum.LMS.Signer.Cli** (`pqlms`) | keygen / sign / verify / inspect / pubkey | ✅ Production |
| **PostQuantum.LMS.Signer.Sqlite** | `SqliteStateStore` — a relational `IStateStore` with CAS; reference DB backend (pattern ports to Postgres/SQL Server) | ✅ Production |
| **PostQuantum.LMS.Signer.AspNetCore** | DI: `services.AddLmsSigner(...)`, `ILmsSigningService`, pluggable stores, options validation, a capacity health check | ✅ Production |
| **PostQuantum.LMS.Signer.Hybrid** | Composite **LMS/HSS + ML-DSA** signatures (belt-and-suspenders PQC), with ML-DSA key management and a bundled public key | ✅ Production |
| **PostQuantum.LMS.Signer.Analyzers** | Roslyn rule `PQLMS001`: flags `InMemoryStateStore` for a persistent key | 🧱 Preview skeleton |
| **PostQuantum.LMS.Signer.Templates** | `dotnet new pqlms-firmware-signer` scaffolding | 🧱 Preview skeleton |

### Maturity, precisely

No hand-waving — here's exactly where each piece stands:

| Capability | Maturity | Notes |
|---|---|---|
| LMS/HSS core (sign/verify/state) | **Stable, preview** | BC byte-for-byte + KAT validated, 77 tests on net8/net10. Awaiting external audit before a production assurance claim. |
| `FileStateStore` (single-host) | **Stable, preview** | Atomic, integrity-checked, CAS. |
| Testing conformance harness | **Stable** | |
| CLI (`pqlms`) | **Stable, preview** | |
| Hybrid (HSS + ML-DSA) | **Stable, preview** | ML-DSA via BouncyCastle. |
| AspNetCore DI + health check | **Stable, preview** | Pluggable stores; bring your own Redis/EF/HSM store. |
| Relational / DB state store | **Stable, preview** | `SqliteStateStore` (PostQuantum.LMS.Signer.Sqlite) with CAS; conformance-tested. Same pattern ports to Postgres/SQL Server. Multi-*host* signing still wants a server DB or HSM — see [docs/operations.md](docs/operations.md). |
| Analyzers | **Experimental** | `PQLMS001` only; more rules planned. |
| Templates | **Experimental** | Minimal starter. |
| SHAKE256 / n=24 parameter sets | **Not implemented** | Selecting them throws rather than doing the wrong thing. |
| SBOM · build provenance · checksums | **Automated** | Generated on every tagged release; verify per [docs/releasing.md](docs/releasing.md). |
| Author-signed packages · NuGet publish | **Wired, secret-gated** | Active once a signing cert / `NUGET_API_KEY` secret is configured. |
| Independent third-party audit | **Planned** | See [docs/security-assurance.md](docs/security-assurance.md). |

### Validate your own state store

Writing a Redis/EF Core/HSM-backed store? Prove it's safe before trusting a key to it:

```csharp
using PostQuantum.Lms.Testing;

await StateStoreConformance.AssertConformsAsync(myCustomStore);   // round-trip, versioning, CAS
await StateStoreConformance.AssertPreventsReuseAsync(myCustomStore);
```

---

## Hybrid signing (defense in depth)

Pair the conservative, stateful LMS/HSS with the stateless lattice scheme **ML-DSA (FIPS 204)**, so a break in *either* family alone is not enough to forge. Verification requires **both** legs to pass.

```csharp
using PostQuantum.Lms;
using PostQuantum.Lms.Hybrid;
using PostQuantum.Lms.State;

// One stateful HSS key + one stateless ML-DSA key (defaults to ML-DSA-65).
using var hss = await HssSigner.CreateAsync(HssParameters.FirmwareDefault, store, "fw-2026");
var mlDsa = MlDsaKeyPair.Generate();
var signer = new HybridHssMlDsaSigner(hss, mlDsa);

byte[] composite = await signer.SignAsync(image);   // HSS ‖ ML-DSA
HybridPublicKey pub = signer.PublicKey();           // one bundle to distribute
File.WriteAllBytes("fw-2026.hybrid.pub", pub.Encode());

// On the device — both legs must verify, or it's rejected:
bool ok = HybridPublicKey.Decode(File.ReadAllBytes("fw-2026.hybrid.pub"))
                         .Verify(image, composite);
```

> The HSS key is stateful (guard it per the rules above). The ML-DSA key is an ordinary stateless key — export it with `mlDsa.ExportPrivateKey()` and store it securely.

---

## Design decisions

- **Pure managed core, not a BouncyCastle wrapper.** Hash-based signatures are the one family where a self-implementation is professionally defensible — correctness is fully provable against published vectors. Owning the code is the only way to own the *state index*, which is the entire value proposition. BouncyCastle is wired into our **test suite** as an independent oracle, not shipped as a runtime dependency.
- **`net8.0` libraries, verified on .NET 8 *and* .NET 10.** Broad compatibility; CI runs the suite on both runtimes.
- **AOT- and trim-friendly.** No reflection in the hot path; suited to constrained signing services and embedded tooling.

## Standards & references

- [RFC 8554 — Leighton-Micali Hash-Based Signatures](https://datatracker.ietf.org/doc/html/rfc8554)
- [NIST SP 800-208 — Stateful Hash-Based Signature Schemes](https://csrc.nist.gov/publications/detail/sp/800-208/final)
- [CNSA 2.0 — software/firmware signing guidance](https://www.nsa.gov/cybersecurity-guidance/)
- [FIPS 204 — ML-DSA](https://csrc.nist.gov/pubs/fips/204/final) (hybrid)

## Documentation

- [Samples](samples/) — runnable console and ASP.NET Core reference apps (`dotnet run --project samples/...`).
- [Operations playbook](docs/operations.md) — rollback-safe deployment, single-writer topologies, backup/do-not-restore runbook, key rotation & exhaustion, incident response.
- [Security assurance](docs/security-assurance.md) — assurance status, side-channel properties (claimed vs not), non-goals, supply-chain roadmap.
- [Releasing & verifying artifacts](docs/releasing.md) — provenance, SBOM, checksum, and signature verification steps.
- [Architecture decisions](docs/adr/) · [Security policy](SECURITY.md) · [Changelog](CHANGELOG.md) · [Maintainer guide](CLAUDE.md)

## Status & honesty

This is a **preview**. The core is implemented and cross-validated, but **before any CNSA/production claim it should undergo an independent third-party audit and a side-channel review.** We document residual risks rather than paper over them — see [docs/security-assurance.md](docs/security-assurance.md).

## Contributing

Issues and PRs welcome — especially additional official test vectors, state-store backends, and audit findings. See [CLAUDE.md](CLAUDE.md) for architecture and the state-safety invariants any change must preserve.

## License

Apache-2.0.

---

<div align="center">

*Part of the **PostQuantum.*** family — the Bouncy Castle of the post-quantum era.*

**To God be the glory.**

</div>
