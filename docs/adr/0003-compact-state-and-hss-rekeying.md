# ADR 0003 — Compact seed-derived state and HSS subtree re-keying

- **Status:** Accepted
- **Date:** 2026-06-15

## Context

State is written on the hot path (once per signature), so it must be small and fast to persist, yet
fully sufficient to resume signing safely after a restart. HSS additionally requires generating fresh
lower subtrees when a tree is exhausted, and re-signing each new subtree's public key with its parent.

## Decision

- **Seed-derived keys (RFC 8554 Appendix A).** Each tree's private key is regenerated from a compact
  `(I, SEED)` pair, so persisted state per level is just `(types, I, SEED, q)` — tens of bytes, not
  the whole tree. Trees are rebuilt in memory on load.
- **Persist the HSS chain signatures.** The parent-over-child signatures are stored, **not**
  recomputed, because re-signing the same child public key with a fresh randomizer would expose extra
  Winternitz chain elements of an already-used one-time key. Recomputation would be a vulnerability.
- **Re-key on exhaustion, root-down.** When the bottom subtree fills, generate a fresh subtree, have
  the parent sign it with its next leaf, recursing upward; exhausting the root throws
  `LmsKeyExhaustedException`. The whole advance (including re-key) is persisted atomically before the
  signature is released (see ADR 0002).

## Consequences

- ✅ State files are tiny and writes are cheap, even for million-signature keys.
- ✅ Re-keying is transparent and crash-safe; tested across multiple subtree boundaries and against
  BouncyCastle for L=2 and L=3.
- ⚠️ Full materialization of a tree on load is O(2^h); fine for the firmware heights (h ≤ 15). Large
  heights (h20/h25) would benefit from BDS-style streaming traversal — noted as future work.
