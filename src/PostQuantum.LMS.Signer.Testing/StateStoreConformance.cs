using PostQuantum.Lms.State;

namespace PostQuantum.Lms.Testing;

/// <summary>
/// A conformance harness for custom <see cref="IStateStore"/> implementations. Stateful hash-based
/// signatures are only as safe as their state store, so before trusting a Redis-, EF Core-, or
/// HSM-backed store with a production key you should prove it honors the contract: round-tripping,
/// monotonic versioning, and — most importantly — compare-and-swap that rejects stale writers.
/// </summary>
/// <remarks>
/// This harness is framework-agnostic: it throws <see cref="InvalidOperationException"/> on the first
/// violation rather than depending on any test framework. Call it from a fact/test of your own.
/// </remarks>
public static class StateStoreConformance
{
    /// <summary>
    /// Exercises the full <see cref="IStateStore"/> contract against <paramref name="store"/> using a
    /// fresh, unique key. Throws on the first violation; returns normally if the store conforms.
    /// </summary>
    /// <exception cref="InvalidOperationException">The store violated some part of the contract.</exception>
    public static async Task AssertConformsAsync(IStateStore store, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(store);
        string keyId = "conformance-" + Guid.NewGuid().ToString("N");

        // 1. A missing key loads as null.
        if (await store.LoadAsync(keyId, cancellationToken).ConfigureAwait(false) is not null)
        {
            throw Fail("LoadAsync on a non-existent key must return null.");
        }

        // 2. First save with expectedVersion 0 succeeds and returns version 1.
        byte[] v1Data = [1, 2, 3, 4];
        long v1 = await store.SaveAsync(keyId, v1Data, expectedVersion: 0, cancellationToken).ConfigureAwait(false);
        if (v1 != 1)
        {
            throw Fail($"First save must return version 1, returned {v1}.");
        }

        // 3. Load returns the exact bytes and version.
        LoadedState? loaded = await store.LoadAsync(keyId, cancellationToken).ConfigureAwait(false)
            ?? throw Fail("LoadAsync returned null immediately after a successful save.");
        if (loaded.Version != 1 || !loaded.Data.AsSpan().SequenceEqual(v1Data))
        {
            throw Fail("Loaded state did not round-trip exactly (data or version mismatch).");
        }

        // 4. Saving with a STALE expectedVersion must be rejected (the anti-reuse guard).
        bool casRejected = false;
        try
        {
            await store.SaveAsync(keyId, new byte[] { 9, 9, 9 }, expectedVersion: 0, cancellationToken).ConfigureAwait(false);
        }
        catch (LmsStateException)
        {
            casRejected = true;
        }

        if (!casRejected)
        {
            throw Fail("Compare-and-swap failure: a save with a stale expectedVersion was NOT rejected. " +
                       "This store cannot safely back a signing key — concurrent writers could reuse a one-time key.");
        }

        // 5. The rejected write must not have mutated state.
        LoadedState? afterReject = await store.LoadAsync(keyId, cancellationToken).ConfigureAwait(false);
        if (afterReject is null || afterReject.Version != 1 || !afterReject.Data.AsSpan().SequenceEqual(v1Data))
        {
            throw Fail("A rejected (stale) save must leave the stored state and version unchanged.");
        }

        // 6. A correctly-versioned save advances to version 2.
        byte[] v2Data = [5, 6, 7, 8, 9];
        long v2 = await store.SaveAsync(keyId, v2Data, expectedVersion: 1, cancellationToken).ConfigureAwait(false);
        if (v2 != 2)
        {
            throw Fail($"Save with correct expectedVersion 1 must return version 2, returned {v2}.");
        }

        LoadedState? finalState = await store.LoadAsync(keyId, cancellationToken).ConfigureAwait(false);
        if (finalState is null || finalState.Version != 2 || !finalState.Data.AsSpan().SequenceEqual(v2Data))
        {
            throw Fail("Final state did not reflect the second successful save.");
        }
    }

    /// <summary>
    /// Demonstrates and asserts that <paramref name="store"/> prevents one-time-key reuse when two
    /// signers are loaded from the same key (simulating a cloned key or two processes). The second
    /// signer to sign must be rejected. Returns the signature produced by the winning signer.
    /// </summary>
    /// <exception cref="InvalidOperationException">The store failed to prevent the reuse.</exception>
    public static async Task<byte[]> AssertPreventsReuseAsync(IStateStore store, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(store);
        string keyId = "reuse-lab-" + Guid.NewGuid().ToString("N");

        using (await HssSigner.CreateAsync(HssParameters.Small, store, keyId, cancellationToken).ConfigureAwait(false)) { }

        using HssSigner first = await HssSigner.LoadAsync(store, keyId, cancellationToken).ConfigureAwait(false);
        using HssSigner second = await HssSigner.LoadAsync(store, keyId, cancellationToken).ConfigureAwait(false);

        byte[] winning = await first.SignAsync("authorized"u8.ToArray(), cancellationToken).ConfigureAwait(false);

        try
        {
            await second.SignAsync("rogue"u8.ToArray(), cancellationToken).ConfigureAwait(false);
        }
        catch (LmsStateException)
        {
            return winning; // good: the stale signer was refused.
        }

        throw Fail("Reuse was NOT prevented: a second signer loaded from the same state succeeded in signing. " +
                   "This store does not provide safe compare-and-swap semantics.");
    }

    private static InvalidOperationException Fail(string message)
        => new($"IStateStore conformance failure: {message}");
}
