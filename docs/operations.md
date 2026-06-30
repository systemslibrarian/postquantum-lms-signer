# Operations playbook

This is the operator's guide to running a stateful LMS/HSS signer safely. The single rule
behind everything here:

> **The state directory IS the private key, and its internal version counter must never go
> backwards.** A rewound counter causes one-time-key reuse, and reuse can leak the private
> key. A *wasted* index is harmless; a *reused* index is a security incident.

Read this alongside the "Don't do this" section in [/README.md](/README.md) and the
[/docs/security-assurance.md](/docs/security-assurance.md) threat model.

---

## 1. Approved deployment patterns

The invariant you must guarantee is **exactly one actively-advancing signer per key**
(single-writer), or — if you need more than one host — a **shared store whose compare-and-swap
(CAS) is authoritative**. The shipped `FileStateStore` enforces CAS for processes pointed at
the *same directory* via an exclusive lock file, but it cannot coordinate across hosts that
each have their own copy of the directory.

### Virtual machine (single host)

- One signer process, one state directory on a **local, non-snapshotted** disk.
- Do not enable live-snapshot/backup tooling against the state volume (see Forbidden
  patterns). If the platform takes automatic snapshots, exclude the state directory or accept
  that you must never restore them onto a live key.
- Restrict filesystem permissions to the signing service account.

### Container

- Mount the state directory on a **persistent, read-write-once (RWO) volume** — never on an
  ephemeral container layer (it would be lost on restart) and never on a volume shared
  read-write with another running container.
- Run **exactly one** container instance for a given key. Do not autoscale the signer.
- `InMemoryStateStore` is for tests only; the `PQLMS001` analyzer flags using it for a
  persistent key. Use `FileStateStore` (or a custom CAS-capable store).

### Kubernetes

Pick one of these, in rough order of preference:

1. **Single-replica `StatefulSet` (or `Deployment`) with an RWO `PersistentVolumeClaim`.**
   `replicas: 1`, `strategy.type: Recreate` (Deployment) so the old pod is terminated before
   the new one starts — never two pods writing the same volume at once. This is the simplest
   correct setup.
2. **Leader election.** Run multiple replicas for availability but ensure only the elected
   leader calls `SignAsync`. The non-leaders must not advance state. Combine with an RWO
   volume so a split-brain still cannot produce two writers on the same data.
3. **CAS-capable shared store.** Implement `IStateStore` over a backend with real
   compare-and-swap (e.g. a database row with optimistic-concurrency versioning, or an HSM —
   see §5). Multiple replicas may then attempt to sign; the store guarantees one winner per
   version and the losers receive `LmsStateException`. Validate the store with the conformance
   harness (§9) before production.

Whatever the topology, **`replicas: 2` against one RWO volume with both pods signing is not a
valid configuration** — it is the cloned-signer failure mode.

---

## 2. Forbidden patterns

Each of these can silently rewind the counter and cause reuse. Software cannot detect the
ones marked (machine-level).

- **VM snapshot/restore of a live signer (machine-level).** Snapshotting a signing host and
  later restoring the snapshot rewinds the counter to the snapshot point; signatures produced
  after restore repeat indices already used. Never snapshot-restore a live signer and resume.
- **Restoring the state directory from backup while signing continues.** A backup is an
  older, lower index. Restoring it past the point of additional signing reintroduces reuse.
- **Copying the state directory to a second node and signing on both.** Two copies advance
  independently and *will* collide on indices.
- **Horizontal scaling of the signer without a coordinating CAS store.** Two replicas with
  their own copies of the directory is the same as copying it. Only the patterns in §1.2/§1.3
  make multi-instance safe.
- **Sharing one state directory read-write between two live processes that bypass the lock**
  (e.g. across two hosts via a network filesystem that does not honor the exclusive lock).
  `FileStateStore`'s lock is OS-local; do not assume it serializes across hosts.

---

## 3. Backup / restore / DO-NOT-restore runbook

Stateful keys break the usual "backups are always safe" intuition.

### Always safe

- **Back up the PUBLIC key freely.** The public key (`signer.PublicKey()`, or the file written
  by `pqlms pubkey` / `pqlms keygen --pubkey-out`) carries no state and can be copied,
  archived, and redistributed without risk. You need it for verification and for revocation
  workflows.

### Conditionally safe

- **Backing up the state directory is only safe if you will NEVER restore it onto a key that
  has signed further since the backup.** The only legitimate restore is disaster recovery of a
  key that has produced **no** signatures since the backup was taken — and proving that is hard.
  When in doubt, do **not** restore; rotate to a new key instead (§6).

### The `.bak` file — forensic use only

- `FileStateStore` keeps a `.bak` sibling of the previous state on each save. **It is not
  auto-loaded** and **must not be blindly restored.** It is, by definition, an *older* index;
  restoring it over the live file rewinds the counter and creates reuse risk.
- Treat `.bak` (and `.tmp`, `.lock`) as internal/forensic artifacts. Use `.bak` only to
  *investigate* an incident (e.g. to see the prior index), never as a "fix" for a corrupt or
  missing state file.
- If the live state file fails its integrity check on load (`LmsStateException` from
  `Decode`), the file is corrupt or tampered. Do **not** silently restore `.bak`. Treat it as
  a potential incident (§8) and decide deliberately whether the key can be trusted at all.

---

## 4. Recovery decision tree

- **Crash mid-sign?** No action needed. Persist-before-sign means the index was either
  durably advanced (you may have wasted one index) or not advanced at all. Just reload and
  continue — `HssSigner.LoadAsync` / `LmsSigner.LoadAsync`.
- **State file corrupt / integrity check failed?** Stop. Do not restore `.bak` reflexively.
  Investigate (§8); prefer rotating to a new key (§6) over restoring an older index.
- **State file missing entirely?** The key is unrecoverable as a signer. Do not reconstruct
  from a backup unless you can prove no signing happened since. Rotate to a new key.
- **Suspected rollback or reuse?** Incident response, §8.

---

## 5. HSM / TPM / hardware monotonic counter integration

For high-assurance deployments that must survive whole-machine rollback (the one threat
software cannot fix), move the authority for the monotonic counter into hardware that
**physically cannot roll back**:

- **Implement `IStateStore` over the HSM/TPM.** The interface needs three guarantees:
  atomicity, durability, and compare-and-swap on a monotonic version. Map the `expectedVersion`
  CAS in `SaveAsync` onto the hardware's monotonic counter / authenticated-write primitive so
  that a save can only succeed when advancing the counter, and a stale writer is rejected.
- **Keep the counter where it can't be rewound.** A restored VM image must not be able to
  reset the counter. That is the entire point of using hardware here — the counter's value
  lives in the HSM/TPM, not in the (restorable) filesystem.
- **Optionally keep the seed in the HSM too.** If the HSM can perform the hashing, the secret
  seed need never leave it. At minimum, ensure the counter is authoritative.
- **Validate before trusting a key to it.** Run the conformance harness (§9) against your
  hardware-backed store. A store that does not truly enforce CAS is worse than `FileStateStore`.

This is conceptual guidance — no HSM/TPM `IStateStore` ships in this release.

---

## 6. Key rotation & exhaustion management

LMS/HSS keys have a **finite** signature budget. The firmware default
(`HssParameters.FirmwareDefault`) is ~1,048,576 signatures; `SingleLevel` is 32,768; `Small`
is 1,024.

- **Monitor `SignaturesRemaining`** (on `HssSigner` / `LmsSigner`, also shown by
  `pqlms inspect`). Treat it like a depleting resource.
- **Rotate before exhaustion.** Generate a *new* `keyId` (e.g. `fw-2027`) well before the old
  key runs out, distribute its public key to verifiers, and cut over signing. Plan rotation so
  there is overlap; do not wait for the last signature.
- **Exhaustion is terminal.** When the budget is spent, `SignAsync` throws
  `LmsKeyExhaustedException`. This is a normal end-of-life condition, not a bug — the key is
  permanently spent and cannot be extended. The only response is rotation to a fresh key.
- **Never "reset" a key to reclaim capacity.** Lowering the index to sign again is exactly the
  reuse failure mode.

---

## 7. Observability — what to alert on

Wire these into your monitoring and treat the security-relevant ones as pages, not emails:

| Signal | Why it matters | Suggested action |
|---|---|---|
| `SignaturesRemaining` below a threshold (e.g. < 10% or < N) | Approaching exhaustion | Trigger key rotation (§6) before it hits zero |
| `LmsStateException` on save (CAS mismatch) | Two writers raced for one version — likely a **misconfigured multi-writer** deployment | Investigate topology immediately; you may have a cloned/concurrent signer |
| `LmsStateException` on load (integrity-tag failure) | State file is **corrupt or tampered** | Stop signing on that key; incident response (§8) |
| `LmsKeyExhaustedException` | Key fully spent | Rotation should already be complete; if not, expedite |
| Elevated signer lock contention / `SignAsync` latency | Multiple callers serializing on the per-signer gate, or contention on the `FileStateStore` lock file | Check for unintended concurrency; confirm single-writer assumptions |

A sudden `LmsStateException` (CAS) in a deployment you *thought* was single-writer is the
canonical early warning of an accidental clone. Do not silence it.

---

## 8. Incident response — suspected rollback or reuse

If you suspect the counter was rewound (snapshot restored, backup restored over a live key,
two nodes signed from copies of the state, or a CAS mismatch you cannot explain):

1. **Stop signing with that key immediately.** Take the signer offline.
2. **Treat the key as COMPROMISED.** Be direct about why: one-time-key reuse in LMS/HSS can
   leak the private key. Once two different messages may have been signed under one index, you
   must assume forgery is possible.
3. **Revoke / rotate the public key with downstream verifiers.** Distribute a new public key
   (new `keyId`) and arrange for devices/verifiers to stop trusting the old one through your
   normal trust-update channel.
4. **Investigate how the state was rewound.** Snapshot/backup tooling touching the state
   volume? Two pods on one volume? A network filesystem that didn't honor the lock? Fix the
   root cause before deploying any new key into the same environment.
5. **Preserve evidence.** The `.bak`/`.tmp`/`.lock` artifacts and host snapshots help
   reconstruct what indices were used. Do not "repair" by restoring `.bak`.

Report library-level defects (e.g. a code path that could reuse an index) privately per
[/SECURITY.md](/SECURITY.md). An operator-caused rollback is an environment incident, not a
library defect, but the response above is the same: assume compromise and rotate.

---

## 9. Custom `IStateStore` checklist

Before trusting a key to any store other than `FileStateStore`, the store **must** be:

- **Atomic** — a save is all-or-nothing; a reader never observes a torn/partial write.
- **Durable** — the data is on stable storage before `SaveAsync` returns.
- **Compare-and-swap on the version** — `SaveAsync` succeeds only if the stored version equals
  `expectedVersion`, and otherwise throws `LmsStateException`. A non-existent key is version 0;
  the first successful save returns version 1. This is what makes multi-writer safe: the loser
  is refused, never allowed to reuse an index.

Validate it with the conformance harness from `PostQuantum.LMS.Signer.Testing` **before
production**:

```csharp
using PostQuantum.Lms.Testing;

await StateStoreConformance.AssertConformsAsync(myCustomStore);      // round-trip, versioning, CAS contract
await StateStoreConformance.AssertPreventsReuseAsync(myCustomStore); // proves a stale writer cannot reuse an index
```

A store that passes both is safe to back a real key (subject to the durability of its
underlying medium). A store that fails either must not be used for a persistent key.

To God be the glory.
