# Architecture Decision Records

Short records of the load-bearing decisions behind PostQuantum.LMS.Signer. Each captures the
context, the decision, and the consequences so future maintainers (human or AI) understand *why*
the code is shaped the way it is before changing it.

| ADR | Title |
|-----|-------|
| [0001](0001-pure-managed-core-with-bouncycastle-oracle.md) | Pure-managed core, BouncyCastle as test oracle (not a wrapper) |
| [0002](0002-persist-before-sign-and-cas.md) | Persist-before-sign ordering and compare-and-swap state contract |
| [0003](0003-compact-state-and-hss-rekeying.md) | Compact seed-derived state and HSS subtree re-keying |
| [0004](0004-firmware-default-parameters.md) | Default parameter set for firmware/code signing |
