# ADR 0002 — Persist-before-sign ordering and compare-and-swap state contract

- **Status:** Accepted
- **Date:** 2026-06-15

## Context

A stateful one-time signature is broken the instant an index is reused. Two failure modes dominate in
production: (1) a crash between signing and recording the advance, and (2) two signers (a cloned key, a
restored backup, two pods) both consuming the same index.

## Decision

1. **Persist before sign.** `SignAsync` advances the index and **durably persists** the new state
   *before* computing the signature. A crash can therefore only *waste* an index, never *reuse* one.
2. **Compare-and-swap `IStateStore`.** `SaveAsync(keyId, data, expectedVersion)` succeeds only if the
   stored version equals `expectedVersion`; otherwise it throws. A stale/cloned signer is **refused**
   rather than allowed to reuse. A non-existent key is version 0; the first save returns version 1.
3. **Integrity-checked, atomic file store.** `FileStateStore` writes temp → flush-to-disk → atomic
   rename, retains a `.bak`, and tags each record with SHA-256 so torn/tampered state is rejected on
   load.

## Consequences

- ✅ Crash safety and clone/concurrency safety are structural, not advisory; both are unit-tested.
- ✅ Custom stores (Redis/EF/HSM) get a precise contract and a conformance harness to prove it.
- ⚠️ **Whole-machine rollback is out of scope for software** — restoring an entire disk/VM rolls the
  version counter back too, defeating CAS. Documented loudly; mitigation is HSM / hardware monotonic
  counters. `.bak` is for *manual* forensic recovery only and is deliberately **not** auto-loaded
  (doing so would itself be a rollback).
- ⚠️ A failed persist rolls back in-memory state to the last durable snapshot, so a transient store
  outage wastes nothing.
