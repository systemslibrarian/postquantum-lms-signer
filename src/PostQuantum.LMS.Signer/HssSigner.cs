using PostQuantum.Lms.Internal;
using PostQuantum.Lms.State;

namespace PostQuantum.Lms;

/// <summary>
/// A stateful HSS signer (RFC 8554 §6): a hierarchy of LMS trees giving a very large signature budget
/// with fast key generation. This is the recommended entry point for firmware and code signing — see
/// <see cref="HssParameters.FirmwareDefault"/>.
/// </summary>
/// <remarks>
/// <para>Like <see cref="LmsSigner"/>, every signature advances and durably persists the index before
/// the signature is released; exhausted subtrees are transparently and safely re-keyed. The signer is
/// the sole authority for its key's state — back it with a crash-safe, single-writer (or CAS-capable)
/// <see cref="IStateStore"/> such as <see cref="FileStateStore"/>.</para>
/// </remarks>
public sealed class HssSigner : IDisposable
{
    private readonly IStateStore _store;
    private readonly string _keyId;
    private readonly SemaphoreSlim _gate = new(1, 1);

    private HssEngine _engine;
    private long _version;
    private bool _disposed;

    private HssSigner(IStateStore store, string keyId, HssEngine engine, long version)
    {
        _store = store;
        _keyId = keyId;
        _engine = engine;
        _version = version;
    }

    /// <summary>The HSS public key in RFC 8554 wire format. Distribute this to verifiers.</summary>
    public byte[] PublicKey() => _engine.PublicKey();

    /// <summary>Total message signatures this key can ever produce.</summary>
    public long MaxSignatures => _engine.MaxSignatures;

    /// <summary>Message signatures still available before the key is exhausted.</summary>
    public long SignaturesRemaining => _engine.SignaturesRemaining;

    /// <summary>
    /// Generates a fresh HSS key, persists its initial state, and returns a ready signer. Fails if the
    /// <paramref name="keyId"/> already exists in the store.
    /// </summary>
    public static async Task<HssSigner> CreateAsync(
        HssParameters parameters, IStateStore store, string keyId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(store);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);

        if (await store.LoadAsync(keyId, cancellationToken).ConfigureAwait(false) is not null)
        {
            throw new LmsStateException($"A key already exists at '{keyId}'. Refusing to overwrite a stateful key.");
        }

        var engine = HssEngine.Create(parameters);
        long version = await store.SaveAsync(keyId, engine.Serialize(), expectedVersion: 0, cancellationToken).ConfigureAwait(false);
        return new HssSigner(store, keyId, engine, version);
    }

    /// <summary>Loads an existing HSS key from the store.</summary>
    public static async Task<HssSigner> LoadAsync(IStateStore store, string keyId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);

        LoadedState loaded = await store.LoadAsync(keyId, cancellationToken).ConfigureAwait(false)
            ?? throw new LmsStateException($"No HSS key found at '{keyId}'.");
        return new HssSigner(store, keyId, HssEngine.Deserialize(loaded.Data), loaded.Version);
    }

    /// <summary>
    /// Signs <paramref name="message"/>. State (including any subtree re-keying) is advanced and durably
    /// persisted before the signature is computed; if persistence fails, in-memory state is rolled back
    /// to the last durable snapshot so no key index is ever silently consumed or reused.
    /// </summary>
    public async Task<byte[]> SignAsync(byte[] message, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);
        ObjectDisposedException.ThrowIf(_disposed, this);

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            byte[] snapshot = _engine.Serialize();
            HssEngine.SignaturePlan plan = _engine.PrepareNext();
            try
            {
                _version = await _store.SaveAsync(_keyId, _engine.Serialize(), _version, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                _engine = HssEngine.Deserialize(snapshot); // restore last durable state
                throw;
            }

            return _engine.CompleteSign(plan, message);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Synchronous convenience wrapper over <see cref="SignAsync"/>. Prefer the async form on hot paths.</summary>
    public byte[] Sign(byte[] message) => SignAsync(message).GetAwaiter().GetResult();

    /// <summary>Verifies an HSS signature against an HSS public key (both in RFC 8554 wire format).</summary>
    public static bool Verify(byte[] publicKey, byte[] message, byte[] signature)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(signature);
        return HssEngine.Verify(publicKey, message, signature);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _gate.Wait();
        try
        {
            // _engine does not require disposal.
        }
        finally
        {
            _gate.Release();
            _gate.Dispose();
        }
    }
}
