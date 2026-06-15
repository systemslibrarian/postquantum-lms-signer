# What Would Make This Repo a 10/10?

## Bottom line

This is already a strong repo. The architecture is focused, the security story is unusually honest, the README is excellent, the package split is sensible, and there is meaningful test coverage around the thing that matters most: state safety.

If I were scoring it today as a public security-sensitive OSS package, I would put it around **8/10**.

It becomes a real **10/10** when three things are true at the same time:

1. **The trust story is independently defensible**.
2. **The implementation status matches the marketing/status claims exactly**.
3. **Operators get a complete production playbook, not just a good API**.

## What is already strong

- The repo has a clear thesis: state safety is the product, not just the math.
- The README is unusually strong and explains the sharp edges plainly.
- The core safety invariants are explicit in `CLAUDE.md` and reflected in the surrounding packages.
- CI already builds, tests, and packs on release tags in `.github/workflows/ci.yml`.
- NuGet metadata is better than average in `Directory.Build.props`: license, repo URL, symbols, README packing, and source publishing are already present.
- There is real package surface beyond the core: CLI, ASP.NET Core integration, analyzers, hybrid signing, testing helpers, and templates.
- The testing package has a useful conformance harness for custom stores, which is exactly the kind of ecosystem feature a serious cryptographic package should have.

## Why it is not a 10 yet

### 1. The assurance story still depends too much on self-assertion

For security-sensitive cryptographic software, “looks careful” is not enough. A top-tier score needs third-party evidence.

What is missing:

- An **independent security/cryptography audit** with a published report or summary.
- A **side-channel review** or explicit statement of what side-channel properties are and are not claimed.
- **Fuzzing and negative corpus evidence** published as part of CI or release notes.
- **Supply-chain attestations**: signed releases, provenance, SBOMs, and ideally artifact verification instructions.

What to add:

- A public `docs/security-assurance.md` covering audit scope, threat model, residual risks, and non-goals.
- CI jobs for fuzz/property testing where practical.
- Release provenance via GitHub attestations or equivalent.
- Signed NuGet packages and documented verification steps.

Without that, the repo can be impressive, but not fully trusted at the level the README aspires to.

### 2. Some package/status claims are ahead of the actual maturity

The public story is very polished, but a few parts still read more like “advanced preview” than “finished ecosystem.”

Evidence from the codebase:

- The analyzer only implements `PQLMS001`, while `PQLMS002` and `PQLMS003` are still TODOs in `src/PostQuantum.LMS.Signer.Analyzers/InMemoryStateStoreAnalyzer.cs`.
- The hybrid layer still carries a TODO around first-class ML-DSA key management in `src/PostQuantum.LMS.Signer.Hybrid/MlDsaSigner.cs`.
- The ASP.NET Core package is real and useful, but it is still a thin DI/service wrapper rather than a fully productionized hosting story.
- The template is present, but it is still a minimal starter rather than a full operator-ready scaffold.

What would close the gap:

- Either **finish the missing maturity work**, or **tighten the README/status language** so it distinguishes:
  - production-ready
  - stable but narrow
  - preview/experimental
- Add a compact **feature maturity matrix** to the README and package docs.
- For hybrid specifically, finish the key lifecycle story: generation, import/export guidance, storage guidance, rotation guidance, and explicit operational recommendations.
- For analyzers, ship the next footgun rules before claiming a mature safety ecosystem.

This is mostly a product-management issue, not an engineering failure, but it matters a lot for credibility.

### 3. The operator story needs to go beyond `FileStateStore`

The repo correctly emphasizes that rollback is the real danger. That is good. But a 10/10 version needs to help operators succeed in more than the simplest topology.

What is still missing:

- A first-party **database/distributed store reference implementation** or at least one serious sample backend.
- A documented **single-writer deployment model** for cloud/Kubernetes/VM environments.
- A concrete **backup/restore/do-not-restore** runbook.
- Guidance for **HSM/TPM/monotonic counter integration** for high-assurance users.
- Observable health and exhaustion guidance: capacity alerts, signer lock contention, state corruption handling, and rotation thresholds.

What to add:

- A `docs/operations.md` that covers:
  - approved deployment patterns
  - forbidden deployment patterns
  - incident response for suspected rollback/reuse
  - key rotation and exhaustion management
- A sample `IStateStore` backed by a real persistence system with CAS semantics.
- ASP.NET Core health checks, metrics, and logging conventions.
- CLI commands for safer operational workflows, such as explicit capacity thresholds and machine-readable output.

Right now the repo explains the danger well. A 10/10 repo also gives operators a full playbook for avoiding it.

### 4. Cross-implementation and interoperability proof could be broader

The BouncyCastle oracle story is good. A top score would broaden the evidence base further.

What would help:

- More published **known-answer vectors** and interop fixtures.
- Explicit interop docs for signatures/public keys consumed outside .NET.
- A compatibility matrix covering runtime versions, OSes, and expected behavior.
- Benchmark data for keygen/sign/verify across representative parameter sets.

That makes adoption easier and reduces the perceived risk for teams evaluating the package.

### 5. Release engineering is good, but not yet elite

The current CI is clean, but a 10/10 cryptographic OSS project usually goes further.

What would improve it:

- Add **package publishing automation** with guarded release workflows.
- Generate **release notes/changelog** automatically or maintain them explicitly.
- Publish **SBOMs**, checksums, and detached signatures for release artifacts.
- Add **CodeQL** / static security scanning if not already present.
- Add coverage reporting and trend visibility.
- Add a support policy: compatibility window, preview policy, and security-fix expectations.

## Highest-value improvements, in order

If the goal is to move this from very good to exceptional, I would prioritize these in this order:

### Tier 1: credibility

1. Commission and publish an independent audit.
2. Add a security assurance document and explicit side-channel/non-goal language.
3. Align README/package claims with actual maturity by package.

### Tier 2: production-operability

4. Publish a serious operations guide for rollback-safe deployment.
5. Provide at least one non-file production `IStateStore` example or reference backend.
6. Add observability and exhaustion-management guidance to the ASP.NET Core and CLI surfaces.

### Tier 3: ecosystem completeness

7. Finish analyzer roadmap items that catch more real misuse.
8. Finish the hybrid ML-DSA key-management story.
9. Expand templates/examples into true deployable reference apps.

### Tier 4: trust acceleration for adopters

10. Publish benchmarks, interoperability fixtures, and more vectors.
11. Add release provenance, SBOMs, signed artifacts, and verification instructions.
12. Maintain a public roadmap/changelog/support policy.

## My definition of “10/10” for this repo

This repository is a 10/10 when a cautious security engineer can say all of the following:

- “The cryptography and the state model have independent review, not just author confidence.”
- “The production guidance tells me exactly how not to shoot myself in the foot.”
- “The package maturity labels are precise and honest.”
- “The release artifacts are verifiable and supply-chain-friendly.”
- “There is enough interop, testing, and operational evidence for me to adopt this without heroics.”

## Short version

The repo already has the hard part most projects never achieve: a clear security thesis and discipline around the real failure mode.

To make it a 10/10, focus less on adding more surface area and more on **independent assurance, production operations guidance, release provenance, and exact maturity signaling**.