using System.Security.Cryptography;

namespace PostQuantum.Lms.Internal;

/// <summary>
/// In-memory HSS state machine (RFC 8554 §6): a stack of LMS trees where each non-bottom tree signs
/// the public key of the tree below it, and the bottom tree signs messages. Handles deterministic
/// re-keying of exhausted subtrees. This type is deliberately oblivious to persistence — the owning
/// <see cref="HssSigner"/> snapshots/serializes it and enforces the persist-before-sign ordering.
/// </summary>
/// <remarks>
/// Persisted state is intentionally compact: per level we keep (types, I, SEED, q) plus the cached
/// chain signatures. Everything else (the materialized trees, the intermediate public keys) is
/// recomputed on load. The chain signatures <b>must</b> be persisted rather than recomputed, because
/// re-signing the same child public key with a fresh randomizer would reveal extra Winternitz chain
/// elements of an already-used one-time key.
/// </remarks>
internal sealed class HssEngine
{
    private const byte StateFormat = 1;

    private readonly LmsParameters[] _levelParams;
    private readonly byte[][] _identifier;   // [L][16]
    private readonly byte[][] _seed;         // [L][n]
    private readonly long[] _q;              // [L] next free leaf per level
    private readonly byte[][] _chainSig;     // [L-1] LMS sig by level i over pub[i+1]
    private readonly LmsTree[] _trees;       // [L] materialized, recomputed on load/rekey
    private readonly long[] _capacity;       // [L] 2^h per level

    private HssEngine(LmsParameters[] levelParams, byte[][] identifier, byte[][] seed, long[] q, byte[][] chainSig)
    {
        _levelParams = levelParams;
        _identifier = identifier;
        _seed = seed;
        _q = q;
        _chainSig = chainSig;
        _trees = new LmsTree[levelParams.Length];
        _capacity = new long[levelParams.Length];
        for (int i = 0; i < levelParams.Length; i++)
        {
            _capacity[i] = levelParams[i].MaxSignatures;
            _trees[i] = BuildTree(i);
        }
    }

    /// <summary>Number of levels L.</summary>
    public int LevelCount => _levelParams.Length;

    private LmsTree BuildTree(int level)
        => LmsTree.Build(_levelParams[level].Lms, _levelParams[level].LmOts, _identifier[level], _seed[level]);

    private static byte[] RandomBytes(int length)
    {
        byte[] b = new byte[length];
        RandomNumberGenerator.Fill(b);
        return b;
    }

    private int SeedLength(int level) => LmOtsParams.Resolve(_levelParams[level].LmOts).N;

    /// <summary>Generates a brand-new HSS key with fresh randomness and builds the initial signature chain.</summary>
    public static HssEngine Create(HssParameters parameters)
    {
        int l = parameters.LevelCount;
        var levelParams = parameters.Levels.ToArray();
        var identifier = new byte[l][];
        var seed = new byte[l][];
        var q = new long[l];
        for (int i = 0; i < l; i++)
        {
            identifier[i] = RandomBytes(LmsConstants.IdentifierLength);
            seed[i] = RandomBytes(LmOtsParams.Resolve(levelParams[i].LmOts).N);
        }

        var chainSig = new byte[Math.Max(0, l - 1)][];
        var engine = new HssEngine(levelParams, identifier, seed, q, chainSig);

        // Initial chain: each non-bottom tree signs the public key of the tree directly below it,
        // consuming its leaf 0.
        for (int i = 0; i < l - 1; i++)
        {
            byte[] childPub = engine._trees[i + 1].PublicKey();
            engine._chainSig[i] = engine._trees[i].Sign((uint)engine._q[i], childPub, RandomBytes(engine.SeedLength(i)));
            engine._q[i]++;
        }

        return engine;
    }

    /// <summary>The HSS public key wire format: <c>u32(L) ‖ lms_public_key[0]</c>.</summary>
    public byte[] PublicKey()
    {
        byte[] rootPub = _trees[0].PublicKey();
        byte[] pk = new byte[4 + rootPub.Length];
        Endian.WriteU32(pk, (uint)_levelParams.Length);
        rootPub.CopyTo(pk.AsSpan(4));
        return pk;
    }

    /// <summary>Total message signatures the key can ever produce: the product of per-level capacities.</summary>
    public long MaxSignatures
    {
        get
        {
            long product = 1;
            foreach (long c in _capacity)
            {
                product = checked(product * c);
            }

            return product;
        }
    }

    /// <summary>Signatures still available (odometer over the level indices).</summary>
    public long SignaturesRemaining
    {
        get
        {
            long remaining = 0;
            long multiplier = 1;
            for (int i = _levelParams.Length - 1; i >= 0; i--)
            {
                remaining += (_capacity[i] - _q[i]) * multiplier;
                multiplier *= _capacity[i];
            }

            return remaining;
        }
    }

    /// <summary>A reserved bottom-tree leaf, returned by <see cref="PrepareNext"/> and consumed by <see cref="CompleteSign"/>.</summary>
    internal readonly record struct SignaturePlan(uint Leaf);

    /// <summary>
    /// Advances state to reserve the next message-signing leaf, re-keying exhausted subtrees as needed.
    /// The caller MUST persist (via <see cref="Serialize"/>) before calling <see cref="CompleteSign"/>.
    /// </summary>
    public SignaturePlan PrepareNext()
    {
        EnsureUsableBottom();
        int bottom = _levelParams.Length - 1;
        uint leaf = (uint)_q[bottom];
        _q[bottom] = leaf + 1;
        return new SignaturePlan(leaf);
    }

    private void EnsureUsableBottom()
    {
        int bottom = _levelParams.Length - 1;
        if (_q[bottom] < _capacity[bottom])
        {
            return;
        }

        Rekey(bottom);
    }

    private void Rekey(int level)
    {
        if (level == 0)
        {
            throw new LmsKeyExhaustedException(
                "This HSS key has produced every signature its parameters allow. Generate a new key pair.");
        }

        if (_q[level - 1] >= _capacity[level - 1])
        {
            Rekey(level - 1);
        }

        // Fresh subtree at this level.
        _identifier[level] = RandomBytes(LmsConstants.IdentifierLength);
        _seed[level] = RandomBytes(SeedLength(level));
        _q[level] = 0;
        _trees[level] = BuildTree(level);

        // Parent signs the new child public key with its next leaf.
        byte[] childPub = _trees[level].PublicKey();
        uint parentLeaf = (uint)_q[level - 1];
        _chainSig[level - 1] = _trees[level - 1].Sign(parentLeaf, childPub, RandomBytes(SeedLength(level - 1)));
        _q[level - 1] = parentLeaf + 1;
    }

    /// <summary>Produces the full HSS signature for <paramref name="message"/> using the reserved plan.</summary>
    public byte[] CompleteSign(SignaturePlan plan, ReadOnlySpan<byte> message)
    {
        int l = _levelParams.Length;
        int bottom = l - 1;
        byte[] bottomSig = _trees[bottom].Sign(plan.Leaf, message, RandomBytes(SeedLength(bottom)));

        // HSS signature: u32(Nspk) ‖ { sig_i ‖ pub_{i+1} } ‖ bottomSig
        var parts = new List<byte[]> { Endian.U32((uint)(l - 1)) };
        for (int i = 0; i < l - 1; i++)
        {
            parts.Add(_chainSig[i]);
            parts.Add(_trees[i + 1].PublicKey());
        }

        parts.Add(bottomSig);

        int total = parts.Sum(p => p.Length);
        byte[] result = new byte[total];
        int offset = 0;
        foreach (byte[] part in parts)
        {
            part.CopyTo(result, offset);
            offset += part.Length;
        }

        return result;
    }

    /// <summary>Serializes the compact persistable state.</summary>
    public byte[] Serialize()
    {
        using var ms = new MemoryStream();
        ms.WriteByte(StateFormat);
        ms.WriteByte((byte)_levelParams.Length);
        Span<byte> u32 = stackalloc byte[4];
        Span<byte> u64 = stackalloc byte[8];

        for (int i = 0; i < _levelParams.Length; i++)
        {
            Endian.WriteU32(u32, (uint)_levelParams[i].Lms);
            ms.Write(u32);
            Endian.WriteU32(u32, (uint)_levelParams[i].LmOts);
            ms.Write(u32);
            ms.Write(_identifier[i]);
            ms.Write(_seed[i]);
            System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(u64, _q[i]);
            ms.Write(u64);
        }

        for (int i = 0; i < _levelParams.Length - 1; i++)
        {
            Endian.WriteU32(u32, (uint)_chainSig[i].Length);
            ms.Write(u32);
            ms.Write(_chainSig[i]);
        }

        return ms.ToArray();
    }

    /// <summary>Reconstructs an engine from serialized state, rebuilding all trees.</summary>
    public static HssEngine Deserialize(byte[] state)
    {
        try
        {
            int pos = 0;
            byte fmt = state[pos++];
            if (fmt != StateFormat)
            {
                throw new LmsStateException($"Unsupported HSS state format {fmt}.");
            }

            int l = state[pos++];
            var levelParams = new LmsParameters[l];
            var identifier = new byte[l][];
            var seed = new byte[l][];
            var q = new long[l];

            for (int i = 0; i < l; i++)
            {
                var lmsType = (LmsAlgorithm)Endian.ReadU32(state.AsSpan(pos)); pos += 4;
                var otsType = (LmOtsAlgorithm)Endian.ReadU32(state.AsSpan(pos)); pos += 4;
                levelParams[i] = new LmsParameters(lmsType, otsType);
                identifier[i] = state.AsSpan(pos, LmsConstants.IdentifierLength).ToArray();
                pos += LmsConstants.IdentifierLength;
                int n = LmOtsParams.Resolve(otsType).N;
                seed[i] = state.AsSpan(pos, n).ToArray();
                pos += n;
                q[i] = System.Buffers.Binary.BinaryPrimitives.ReadInt64BigEndian(state.AsSpan(pos));
                pos += 8;
            }

            var chainSig = new byte[Math.Max(0, l - 1)][];
            for (int i = 0; i < l - 1; i++)
            {
                int len = (int)Endian.ReadU32(state.AsSpan(pos)); pos += 4;
                chainSig[i] = state.AsSpan(pos, len).ToArray();
                pos += len;
            }

            return new HssEngine(levelParams, identifier, seed, q, chainSig);
        }
        catch (Exception ex) when (ex is not LmsException)
        {
            throw new LmsStateException("HSS state is corrupt or truncated.", ex);
        }
    }

    /// <summary>Verifies an HSS signature against an HSS public key (RFC 8554 §6.3).</summary>
    public static bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
    {
        if (publicKey.Length < 4 || signature.Length < 4)
        {
            return false;
        }

        uint levels = Endian.ReadU32(publicKey);
        uint nspk = Endian.ReadU32(signature);
        if (levels == 0 || levels > 8 || nspk != levels - 1)
        {
            return false;
        }

        byte[] currentKey = publicKey.Slice(4).ToArray();
        int sigOffset = 4;

        for (int i = 0; i < nspk; i++)
        {
            if (!TryReadLmsSignature(signature, ref sigOffset, out ReadOnlySpan<byte> lmsSig) ||
                !TryReadLmsPublicKey(signature, ref sigOffset, out ReadOnlySpan<byte> childPub))
            {
                return false;
            }

            byte[] childPubBytes = childPub.ToArray();

            // Tree i signed the child public key bytes.
            if (!LmsTree.Verify(currentKey, childPubBytes, lmsSig))
            {
                return false;
            }

            currentKey = childPubBytes;
        }

        ReadOnlySpan<byte> finalSig = signature.Slice(sigOffset);
        return LmsTree.Verify(currentKey, message, finalSig);
    }

    private static bool TryReadLmsPublicKey(ReadOnlySpan<byte> buffer, ref int offset, out ReadOnlySpan<byte> result)
    {
        result = default;
        if (offset + 8 > buffer.Length || !Enum.IsDefined(typeof(LmsAlgorithm), Endian.ReadU32(buffer.Slice(offset))))
        {
            return false;
        }

        var lms = LmsParams.Resolve((LmsAlgorithm)Endian.ReadU32(buffer.Slice(offset)));
        int len = 8 + LmsConstants.IdentifierLength + lms.M;
        if (offset + len > buffer.Length)
        {
            return false;
        }

        result = buffer.Slice(offset, len);
        offset += len;
        return true;
    }

    private static bool TryReadLmsSignature(ReadOnlySpan<byte> buffer, ref int offset, out ReadOnlySpan<byte> result)
    {
        result = default;
        // Layout: u32(q) ‖ [u32(otsType) ‖ C ‖ y…] ‖ u32(lmsType) ‖ path.
        if (offset + 8 > buffer.Length || !Enum.IsDefined(typeof(LmOtsAlgorithm), Endian.ReadU32(buffer.Slice(offset + 4))))
        {
            return false;
        }

        var ots = LmOtsParams.Resolve((LmOtsAlgorithm)Endian.ReadU32(buffer.Slice(offset + 4)));
        int lmsTypeOffset = offset + 4 + ots.SignatureLength;
        if (lmsTypeOffset + 4 > buffer.Length || !Enum.IsDefined(typeof(LmsAlgorithm), Endian.ReadU32(buffer.Slice(lmsTypeOffset))))
        {
            return false;
        }

        var lms = LmsParams.Resolve((LmsAlgorithm)Endian.ReadU32(buffer.Slice(lmsTypeOffset)));
        int len = 4 + ots.SignatureLength + 4 + (lms.H * lms.M);
        if (offset + len > buffer.Length)
        {
            return false;
        }

        result = buffer.Slice(offset, len);
        offset += len;
        return true;
    }
}
