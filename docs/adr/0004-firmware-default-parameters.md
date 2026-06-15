# ADR 0004 — Default parameter set for firmware/code signing

- **Status:** Accepted
- **Date:** 2026-06-15

## Context

Users need a safe, standards-aligned default so they don't have to reason about tree heights and
Winternitz widths to get started. The target use case is firmware / secure-boot / code signing on a
product lifetime.

## Decision

`HssParameters.FirmwareDefault` = two-level HSS, SHA-256, **h = 10 / 10**, **w = 8**.

- **HSS L=2 over a single huge LMS tree:** ~1,048,576 signatures with only ever materializing
  1024-leaf subtrees → fast startup and a small working set.
- **SHA-256:** the most universally hardware-accelerated, FIPS-ubiquitous hash on embedded targets.
- **w = 8:** the most compact signatures (firmware footprint matters), at the cost of more hashing.
- **CNSA 2.0-aligned** for software/firmware signing.

The library supports all registered SHA-256 sets; this is only the documented *recommendation*.

## Consequences

- ✅ One-liner gets a sensible, capacity-appropriate, standards-aligned key.
- ✅ Compact signatures suit size-constrained update channels.
- ⚠️ ~1M signatures is a hard lifetime cap per key; high-volume signing services should plan key
  rotation or choose larger parameters deliberately.
