# Benchmarks

Head-to-head with [BouncyCastle](https://www.bouncycastle.org/) (an independent RFC 8554
implementation) for the firmware-oriented parameter set **LMS_SHA256_M32_H10 + LMOTS_SHA256_N32_W8**.

Run them yourself:

```bash
dotnet run -c Release --project benchmarks/PostQuantum.LMS.Signer.Benchmarks
```

## Indicative results

> ⚠️ These are **`ShortRun`** numbers (3 iterations) captured on a small 2-core CI container
> (AMD EPYC, .NET 8). Variance is high — treat them as orders of magnitude, not precise figures, and
> run a full job on your target hardware for anything you depend on.

| Operation (LMS h=10, w=8) | This library | BouncyCastle | Allocated (ours / BC) |
|---|---:|---:|---|
| Key generation (build tree, one-time) | ~7.3 s | ~4.4 s | **1.2 MB** / 3.6 MB |
| Sign | ~3.3 ms | n/a* | 1.6 KB / — |
| Verify | ~3.6 ms | ~2.0 ms | **1.3 KB** / 5.2 KB |

\* BouncyCastle's signer advances an internal one-time index on every call, so benchmarking it under
repeated invocation exhausts the key; the figure isn't comparable and is omitted.

## Honest reading

- **Wall-clock:** the pure-managed core is the same order of magnitude as BouncyCastle, currently
  roughly **1.5–1.8× slower** on key generation and verification. For the target use case this is a
  non-issue: key generation happens **once** per key, and signing/verification are **single-digit
  milliseconds**.
- **Allocations:** the managed core allocates **less** than BouncyCastle (≈⅓ on key generation, ≈¼ on
  verify) — useful for constrained/embedded signing hosts.
- **Tradeoff:** the headline tradeoff isn't speed — it's **zero runtime dependency** and **full
  ownership of the state index** (the entire point of the library).

## Optimization notes (for maintainers)

The dominant cost is raw SHA-256 throughput (key generation hashes ≈ `p · 2^w · 2^h` ≈ 9M times for
this set). An experiment replacing the incremental hasher with one-shot `SHA256.HashData` over packed
buffers showed **no measurable wall-clock improvement** under `ShortRun` and slightly *increased*
allocations, so it was reverted — the bottleneck is the hash function itself, not per-call overhead.
Genuine wins would come from a faster SHA-256 path or BDS-style tree traversal, and should be proven
with a full benchmark job before landing. (Intellectual honesty over vanity numbers.)
