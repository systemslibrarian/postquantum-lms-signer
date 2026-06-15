using System.Buffers.Binary;
using System.Security.Cryptography;
using PostQuantum.Lms.Internal;
using PostQuantum.Lms.State;

namespace PostQuantum.Lms;

/// <summary>
/// A stateful single-tree LMS signer (RFC 8554 §5). Each instance owns one Merkle tree and hands out
/// each leaf's one-time key at most once, persisting the advanced index <b>before</b> releasing a
/// signature so a crash can never cause reuse.
/// </summary>
/// <remarks>
/// Use <see cref="HssSigner"/> when you need more than <see cref="LmsParameters.MaxSignatures"/>
/// signatures or faster key generation. An <see cref="LmsSigner"/> is bound to a single
/// <see cref="IStateStore"/> entry identified by a <c>keyId</c>; treat that entry as the one true
/// source of the key's state and never run two signers against it without a coordinating store.
/// </remarks>
public sealed class LmsSigner : IDisposable
{
    private const byte StateFormat = 2;

    private readonly IStateStore _store;
    private readonly string _keyId;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly LmsParameters _parameters;
    private readonly byte[] _identifier;
    private readonly byte[] _seed;
    private readonly long _capacity;

    private readonly LmsTree _tree;
    private long _q;
    private long _version;
    private bool _disposed;

    private LmsSigner(IStateStore store, string keyId, LmsParameters parameters, byte[] identifier, byte[] seed, long q, long version)
    {
        _store = store;
        _keyId = keyId;
        _parameters = parameters;
        _identifier = identifier;
        _seed = seed;
        _q = q;
        _version = version;
        _capacity = parameters.MaxSignatures;
        _tree = LmsTree.Build(parameters.Lms, parameters.LmOts, identifier, seed);
    }

    /// <summary>The parameters this key was generated with.</summary>
    public LmsParameters Parameters => _parameters;

    /// <summary>The LMS public key in RFC 8554 wire format. Distribute this to verifiers.</summary>
    public byte[] PublicKey() => _tree.PublicKey();

    /// <summary>Total signatures this key can ever produce.</summary>
    public long MaxSignatures => _capacity;

    /// <summary>Signatures still available before the key is exhausted.</summary>
    public long SignaturesRemaining => _capacity - Volatile.Read(ref _q);

    /// <summary>
    /// Generates a fresh key, persists its initial state, and returns a ready signer. Fails if the
    /// <paramref name="keyId"/> already exists in the store (so you can never clobber a live key).
    /// </summary>
    public static async Task<LmsSigner> CreateAsync(
        LmsParameters parameters, IStateStore store, string keyId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(store);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);

        if (await store.LoadAsync(keyId, cancellationToken).ConfigureAwait(false) is not null)
        {
            throw new LmsStateException($"A key already exists at '{keyId}'. Refusing to overwrite a stateful key.");
        }

        byte[] identifier = RandomNumberGenerator.GetBytes(LmsConstants.IdentifierLength);
        byte[] seed = RandomNumberGenerator.GetBytes(LmOtsParams.Resolve(parameters.LmOts).N);
        var signer = new LmsSigner(store, keyId, parameters, identifier, seed, q: 0, version: 0);
        signer._version = await store.SaveAsync(keyId, signer.Serialize(), expectedVersion: 0, cancellationToken).ConfigureAwait(false);
        return signer;
    }

    /// <summary>Loads an existing key from the store.</summary>
    public static async Task<LmsSigner> LoadAsync(IStateStore store, string keyId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);

        LoadedState loaded = await store.LoadAsync(keyId, cancellationToken).ConfigureAwait(false)
            ?? throw new LmsStateException($"No LMS key found at '{keyId}'.");
        return Deserialize(store, keyId, loaded.Data, loaded.Version);
    }

    /// <summary>
    /// Signs <paramref name="message"/>. The state index is advanced and durably persisted before the
    /// signature is computed, so a crash at any point cannot produce a reused one-time key.
    /// </summary>
    public async Task<byte[]> SignAsync(byte[] message, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);
        ObjectDisposedException.ThrowIf(_disposed, this);

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_q >= _capacity)
            {
                throw new LmsKeyExhaustedException(
                    $"LMS key '{_keyId}' has produced all {_capacity} signatures. Generate a new key.");
            }

            long leaf = _q;
            _q = leaf + 1;
            try
            {
                _version = await _store.SaveAsync(_keyId, Serialize(), _version, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                _q = leaf; // persistence failed: the leaf was never consumed, so roll back in memory.
                throw;
            }

            byte[] randomizer = RandomNumberGenerator.GetBytes(_tree.Root.Length);
            return _tree.Sign((uint)leaf, message, randomizer);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Synchronous convenience wrapper over <see cref="SignAsync"/>. Prefer the async form on hot paths.</summary>
    public byte[] Sign(byte[] message) => SignAsync(message).GetAwaiter().GetResult();

    /// <summary>Verifies an LMS signature against a public key (both in RFC 8554 wire format).</summary>
    public static bool Verify(byte[] publicKey, byte[] message, byte[] signature)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(signature);
        return LmsTree.Verify(publicKey, message, signature);
    }

    private byte[] Serialize()
    {
        int n = _seed.Length;
        byte[] buffer = new byte[1 + 4 + 4 + LmsConstants.IdentifierLength + n + 8];
        Span<byte> span = buffer;
        span[0] = StateFormat;
        BinaryPrimitives.WriteUInt32BigEndian(span.Slice(1), (uint)_parameters.Lms);
        BinaryPrimitives.WriteUInt32BigEndian(span.Slice(5), (uint)_parameters.LmOts);
        _identifier.CopyTo(span.Slice(9));
        _seed.CopyTo(span.Slice(9 + LmsConstants.IdentifierLength));
        BinaryPrimitives.WriteInt64BigEndian(span.Slice(9 + LmsConstants.IdentifierLength + n), _q);
        return buffer;
    }

    private static LmsSigner Deserialize(IStateStore store, string keyId, byte[] state, long version)
    {
        try
        {
            ReadOnlySpan<byte> span = state;
            if (span[0] != StateFormat)
            {
                throw new LmsStateException($"Unsupported LMS state format {span[0]}.");
            }

            var lmsType = (LmsAlgorithm)BinaryPrimitives.ReadUInt32BigEndian(span.Slice(1));
            var otsType = (LmOtsAlgorithm)BinaryPrimitives.ReadUInt32BigEndian(span.Slice(5));
            var parameters = new LmsParameters(lmsType, otsType);
            byte[] identifier = span.Slice(9, LmsConstants.IdentifierLength).ToArray();
            int n = LmOtsParams.Resolve(otsType).N;
            byte[] seed = span.Slice(9 + LmsConstants.IdentifierLength, n).ToArray();
            long q = BinaryPrimitives.ReadInt64BigEndian(span.Slice(9 + LmsConstants.IdentifierLength + n));
            return new LmsSigner(store, keyId, parameters, identifier, seed, q, version);
        }
        catch (Exception ex) when (ex is not LmsException)
        {
            throw new LmsStateException($"LMS state at '{keyId}' is corrupt or truncated.", ex);
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        CryptographicOperations.ZeroMemory(_seed);
        _gate.Dispose();
    }
}
