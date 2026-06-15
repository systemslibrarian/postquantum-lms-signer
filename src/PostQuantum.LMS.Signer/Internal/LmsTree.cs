namespace PostQuantum.Lms.Internal;

/// <summary>
/// A fully materialized LMS Merkle tree (RFC 8554 §5) for one (I, SEED) pair. Holds every node so
/// authentication paths are O(h) lookups. Memory cost is <c>2^(h+1) · m</c> bytes — fine for the
/// firmware-oriented heights (h ≤ 15); larger heights should use streaming traversal (future work).
/// Verification does not need a tree and is exposed as static methods.
/// </summary>
internal sealed class LmsTree
{
    private readonly LmsParams _lms;
    private readonly LmOtsParams _ots;
    private readonly byte[] _identifier;   // 16 bytes
    private readonly byte[] _seed;         // n bytes
    private readonly byte[][] _nodes;      // T[0..2^(h+1)-1]; index 0 unused
    private readonly long _leafCount;

    public LmsAlgorithm LmsType => _lms.Type;
    public LmOtsAlgorithm OtsType => _ots.Type;
    public ReadOnlySpan<byte> Identifier => _identifier;
    public long LeafCount => _leafCount;
    public ReadOnlySpan<byte> Root => _nodes[1];

    private LmsTree(LmsParams lms, LmOtsParams ots, byte[] identifier, byte[] seed, byte[][] nodes, long leafCount)
    {
        _lms = lms;
        _ots = ots;
        _identifier = identifier;
        _seed = seed;
        _nodes = nodes;
        _leafCount = leafCount;
    }

    /// <summary>Builds the entire tree by deriving all <c>2^h</c> leaf OTS keys and hashing upward.</summary>
    public static LmsTree Build(LmsAlgorithm lmsType, LmOtsAlgorithm otsType, byte[] identifier, byte[] seed)
    {
        var lms = LmsParams.Resolve(lmsType);
        var ots = LmOtsParams.Resolve(otsType);
        if (lms.HashAlgorithm != ots.HashAlgorithm || lms.M != ots.N)
        {
            throw new ArgumentException("LMS and LM-OTS parameter sets must share the same hash and output length.");
        }

        long leaves = lms.LeafCount;
        long total = leaves * 2;
        var nodes = new byte[total][];

        using var hash = LmsHash.Create(lms.HashAlgorithm);
        int m = lms.M;
        Span<byte> leafTag = stackalloc byte[2];
        Endian.WriteU16(leafTag, LmsConstants.D_LEAF);
        Span<byte> intrTag = stackalloc byte[2];
        Endian.WriteU16(intrTag, LmsConstants.D_INTR);
        Span<byte> r4 = stackalloc byte[4];
        Span<byte> otsPub = stackalloc byte[m];

        // Leaves: T[2^h + q] = H(I ‖ u32(r) ‖ u16(D_LEAF) ‖ OTS_PUB[q]).
        for (long q = 0; q < leaves; q++)
        {
            long r = leaves + q;
            LmOts.DeriveLeafPublicKey(hash, ots, identifier, (uint)q, seed, otsPub);
            var node = new byte[m];
            Endian.WriteU32(r4, (uint)r);
            hash.Update(identifier).Update(r4).Update(leafTag).Update(otsPub).Finish(node);
            nodes[r] = node;
        }

        // Interior: T[r] = H(I ‖ u32(r) ‖ u16(D_INTR) ‖ T[2r] ‖ T[2r+1]).
        for (long r = leaves - 1; r >= 1; r--)
        {
            var node = new byte[m];
            Endian.WriteU32(r4, (uint)r);
            hash.Update(identifier).Update(r4).Update(intrTag)
                .Update(nodes[2 * r]).Update(nodes[(2 * r) + 1]).Finish(node);
            nodes[r] = node;
        }

        return new LmsTree(lms, ots, identifier, seed, nodes, leaves);
    }

    /// <summary>Public key wire format: <c>u32(lms_type) ‖ u32(lmots_type) ‖ I ‖ T[1]</c>.</summary>
    public byte[] PublicKey()
    {
        var pk = new byte[8 + LmsConstants.IdentifierLength + _lms.M];
        Endian.WriteU32(pk, (uint)_lms.Type);
        Endian.WriteU32(pk.AsSpan(4), (uint)_ots.Type);
        _identifier.CopyTo(pk.AsSpan(8));
        _nodes[1].CopyTo(pk.AsSpan(8 + LmsConstants.IdentifierLength));
        return pk;
    }

    /// <summary>Total LMS signature length for this tree.</summary>
    public int SignatureLength => 4 + _ots.SignatureLength + 4 + (_lms.H * _lms.M);

    /// <summary>
    /// Signs <paramref name="message"/> with the one-time key at leaf <paramref name="q"/> using the
    /// supplied <paramref name="randomizer"/> (n bytes). The caller is responsible for guaranteeing
    /// <paramref name="q"/> is never reused — that invariant lives in the state engine.
    /// </summary>
    public byte[] Sign(uint q, ReadOnlySpan<byte> message, ReadOnlySpan<byte> randomizer)
    {
        if (q >= _leafCount)
        {
            throw new ArgumentOutOfRangeException(nameof(q), "Leaf index exceeds tree capacity.");
        }

        using var hash = LmsHash.Create(_lms.HashAlgorithm);
        var signature = new byte[SignatureLength];

        Endian.WriteU32(signature, q);
        var otsSig = signature.AsSpan(4, _ots.SignatureLength);
        LmOts.Sign(hash, _ots, _identifier, q, _seed, message, randomizer, otsSig);

        int offset = 4 + _ots.SignatureLength;
        Endian.WriteU32(signature.AsSpan(offset), (uint)_lms.Type);
        offset += 4;

        // Authentication path: siblings from the leaf up to (but excluding) the root.
        long node = _leafCount + q;
        int m = _lms.M;
        for (int i = 0; i < _lms.H; i++)
        {
            _nodes[node ^ 1].CopyTo(signature.AsSpan(offset));
            offset += m;
            node >>= 1;
        }

        return signature;
    }

    /// <summary>
    /// Verifies an LMS signature against a public key in wire format (RFC 8554 §5.4.2, Algorithm 6).
    /// </summary>
    public static bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
    {
        if (publicKey.Length < 8 + LmsConstants.IdentifierLength)
        {
            return false;
        }

        if (!Enum.IsDefined(typeof(LmsAlgorithm), Endian.ReadU32(publicKey)) ||
            !Enum.IsDefined(typeof(LmOtsAlgorithm), Endian.ReadU32(publicKey.Slice(4))))
        {
            return false;
        }

        var lms = LmsParams.Resolve((LmsAlgorithm)Endian.ReadU32(publicKey));
        var ots = LmOtsParams.Resolve((LmOtsAlgorithm)Endian.ReadU32(publicKey.Slice(4)));
        int m = lms.M;
        if (publicKey.Length != 8 + LmsConstants.IdentifierLength + m)
        {
            return false;
        }

        ReadOnlySpan<byte> identifier = publicKey.Slice(8, LmsConstants.IdentifierLength);
        ReadOnlySpan<byte> expectedRoot = publicKey.Slice(8 + LmsConstants.IdentifierLength, m);

        // Parse signature: u32(q) ‖ ots_sig ‖ u32(lms_type) ‖ path.
        int expectedLen = 4 + ots.SignatureLength + 4 + (lms.H * m);
        if (signature.Length != expectedLen)
        {
            return false;
        }

        uint q = Endian.ReadU32(signature);
        if (q >= lms.LeafCount)
        {
            return false;
        }

        ReadOnlySpan<byte> otsSig = signature.Slice(4, ots.SignatureLength);
        int offset = 4 + ots.SignatureLength;
        if (Endian.ReadU32(signature.Slice(offset)) != (uint)lms.Type)
        {
            return false;
        }

        offset += 4;
        ReadOnlySpan<byte> path = signature.Slice(offset);

        using var hash = LmsHash.Create(lms.HashAlgorithm);
        Span<byte> candidate = stackalloc byte[m];
        if (!LmOts.TryRecoverPublicKey(hash, ots, identifier, q, message, otsSig, candidate))
        {
            return false;
        }

        Span<byte> intrTag = stackalloc byte[2];
        Endian.WriteU16(intrTag, LmsConstants.D_INTR);
        Span<byte> r4 = stackalloc byte[4];

        // tmp = H(I ‖ u32(2^h + q) ‖ u16(D_LEAF) ‖ Kc)
        long node = lms.LeafCount + q;
        Span<byte> tmp = stackalloc byte[m];
        Span<byte> leafTag = stackalloc byte[2];
        Endian.WriteU16(leafTag, LmsConstants.D_LEAF);
        Endian.WriteU32(r4, (uint)node);
        hash.Update(identifier).Update(r4).Update(leafTag).Update(candidate).Finish(tmp);

        for (int i = 0; i < lms.H; i++)
        {
            ReadOnlySpan<byte> sibling = path.Slice(i * m, m);
            Endian.WriteU32(r4, (uint)(node >> 1));
            hash.Update(identifier).Update(r4).Update(intrTag);
            if ((node & 1) == 1)
            {
                hash.Update(sibling).Update(tmp);
            }
            else
            {
                hash.Update(tmp).Update(sibling);
            }

            hash.Finish(tmp);
            node >>= 1;
        }

        return CryptographicEquals(tmp, expectedRoot);
    }

    private static bool CryptographicEquals(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
        => System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(a, b);
}
