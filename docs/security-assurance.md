# Security assurance

This document states, honestly and concretely, what assurance this library currently has,
what security properties it does and does not claim, and what remains to be done. It is a
companion to [/SECURITY.md](/SECURITY.md) (reporting and scope) and the threat-model table in
[/README.md](/README.md).

## Assurance status

PostQuantum.LMS.Signer is **preview** software.

- It has **not** had an independent third-party security audit.
- It has **not** had a formal side-channel / constant-time review.
- Do **not** make a CNSA 2.0 or production assurance claim on the basis of this library
  alone until those reviews have happened.

What *has* been done, and is reproducible from the test suite:

- **Byte-for-byte cross-validation against BouncyCastle.** The pure-managed core is checked
  against BouncyCastle as an independent oracle (see
  `tests/PostQuantum.LMS.Signer.Tests/LmsBouncyCastleCrossCheckTests.cs`). BouncyCastle is a
  test/oracle dependency only — it is not a runtime dependency of the core.
- **Pinned known-answer tests (KATs).** Vectors are pinned in
  `PostQuantum.LMS.Signer.Testing` and asserted on every run, so a wire-format or computation
  regression fails the build.
- **68 tests on .NET 8 and .NET 10.** The suite multi-targets `net8.0` and `net10.0`; CI runs
  it on both runtimes.

This is meaningful evidence of **functional correctness and interoperability**. It is not a
substitute for an independent audit or a side-channel evaluation.

## Threat model summary

The full threat-model table — with the per-threat defenses — lives in
[/README.md](/README.md) ("Threat model — what software *can't* do alone"). In brief:

| Threat | Status |
|---|---|
| Crash mid-sign | Defended: persist-before-sign (a crash can waste an index, never reuse one). |
| Cloned key / concurrent signers | Defended: compare-and-swap in `IStateStore` refuses the losing writer (`LmsStateException`). |
| Tampered or corrupted state file | Defended: SHA-256 integrity tag rejected on load (`LmsStateException`). |
| Whole-disk rollback / VM snapshot restore | **Not defendable in pure software** — the monotonic version counter rolls back with the rest of the machine. Requires an HSM or hardware monotonic counter, or operational discipline (never snapshot/restore a live signer). |

The last row is the one limitation software alone cannot fix; the operator playbook in
[/docs/operations.md](/docs/operations.md) covers how to live with it.

## Side-channel properties — claimed vs. not claimed

Be precise here. Hash-based signatures have a favorable structure for side-channel resistance,
but a favorable structure is not a proof.

**What is true by construction:**

- LMS/HSS signing has **data-independent control flow**. There is no secret-dependent
  branching and no secret-dependent field arithmetic — the operations are hash invocations
  over public structure and the (secret) seed, in a fixed pattern determined by the public
  parameters and the one-time-key index. There is no modular reduction or big-integer
  arithmetic whose timing could depend on a secret.
- **Root/integrity comparisons use `CryptographicOperations.FixedTimeEquals`.** State-file
  integrity-tag verification in `FileStateStore.Decode` uses it, and the core uses it for
  hash/root comparison so a verification result does not leak via comparison timing.

**What we do NOT claim:**

- We do **not** claim formally-verified or empirically-measured constant-time behavior. No
  timing/power/EM side-channel evaluation has been performed. The underlying SHA-256
  primitive is the platform's `System.Security.Cryptography` implementation; its
  microarchitectural behavior is out of this library's control.
- We do **not** claim resistance to fault-injection or physical attacks.

**ML-DSA leg (Hybrid package):** the ML-DSA (FIPS 204) signatures in
`PostQuantum.LMS.Signer.Hybrid` are produced by **BouncyCastle**. Their cryptographic and
side-channel properties are **BouncyCastle's responsibility**, not this library's; we wrap and
compose them, we do not re-implement them.

## Non-goals

- **Not a general-purpose cryptography library.** It implements LMS/HSS (and composes ML-DSA
  via BouncyCastle for the hybrid). It is not a place for arbitrary primitives.
- **All SP 800-208 parameter sets are implemented** (SHA-256 and SHAKE256, n=32 and n=24); the
  non-SHA-256/n32 families are cross-checked byte-for-byte against BouncyCastle. An unknown/unregistered
  typecode **throws** rather than silently doing the wrong thing.
- **No protection against whole-machine rollback in pure software.** See the threat model
  above. This requires hardware (HSM / TPM / hardware monotonic counter) or operational
  controls.

## Residual risks

Even when used exactly as documented, these risks remain and are the operator's to manage:

- **Whole-machine state rollback** (restored VM snapshot or disk image) can rewind the
  monotonic counter and lead to one-time-key reuse. Software cannot detect this; reuse can
  leak the private key. See [/docs/operations.md](/docs/operations.md).
- **No independent audit yet** — undiscovered implementation bugs are possible despite
  cross-validation and KATs.
- **No side-channel evaluation yet** — see the section above for what is and is not claimed.
- **Custom `IStateStore` implementations** are only as safe as their atomicity, durability,
  and compare-and-swap guarantees. Validate any custom store with the conformance harness
  (below) before trusting a key to it.

## Supply-chain roadmap (planned — not yet done)

The following supply-chain assurances are **planned and not yet in place**. Do not assume they
exist today:

- [ ] **SBOM** (e.g. CycloneDX/SPDX) published with each release.
- [ ] **Signed NuGet packages** plus release **provenance / build attestations**.
- [ ] **Fuzzing in CI** for the wire-format parsers (signature and state decode paths).
- [ ] **CodeQL** static analysis. (A workflow exists at
  [/.github/workflows/codeql.yml](/.github/workflows/codeql.yml); treat results as advisory
  during preview.)

When these land they will be reflected in [/CHANGELOG.md](/CHANGELOG.md) and this document
will be updated to move them out of the "planned" list.

To God be the glory.
