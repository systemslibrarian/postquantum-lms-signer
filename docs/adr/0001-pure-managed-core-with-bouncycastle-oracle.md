# ADR 0001 — Pure-managed core, BouncyCastle as test oracle (not a wrapper)

- **Status:** Accepted
- **Date:** 2026-06-15

## Context

LMS/HSS could be delivered by (a) wrapping BouncyCastle, (b) P/Invoking a native reference library,
or (c) a from-scratch managed implementation. The library's entire value proposition is *owning the
state index* (crash-safe, never-reuse, distributed-safe). BouncyCastle manages the private-key index
internally, which fights that goal; native interop adds build/licensing/AOT friction.

"Never roll your own crypto" is sound advice *in general*, but hash-based signatures are the specific
exception: correctness is fully provable against published test vectors (no secret-dependent timing,
no field arithmetic — only hashing and Merkle trees).

## Decision

Implement the RFC 8554 primitives in **pure managed C#** as the shipped product, with **no runtime
crypto dependency**. Wire **BouncyCastle into the test suite as an independent oracle**: our public
keys must match BouncyCastle byte-for-byte for the same seed, and signatures must interoperate in both
directions. Add pinned known-answer vectors as regression anchors.

## Consequences

- ✅ Full control of the state index → the differentiating state engine is possible and clean.
- ✅ Trim/AOT-friendly; no native blobs; small dependency surface.
- ✅ Strong, independent correctness evidence without shipping the oracle.
- ⚠️ We carry the audit burden of a crypto implementation. Mitigation: extensive cross-checks now,
  and an explicit requirement for a third-party audit + side-channel review before any production
  assurance claim (see SECURITY.md).
