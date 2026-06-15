namespace PostQuantum.Lms.Internal;

/// <summary>
/// The Leighton-Micali One-Time Signature scheme (RFC 8554 §4). Each LM-OTS key may sign
/// <b>exactly one</b> message; reuse catastrophically leaks the private key. Single-use is
/// enforced one level up by the LMS Merkle tree (each leaf = one LM-OTS key) and by the
/// state engine (each leaf index is handed out at most once).
/// </summary>
/// <remarks>
/// Private keys are generated pseudorandomly from a per-tree <c>SEED</c> (RFC 8554 Appendix A):
/// <c>x_q[i] = H(I ‖ u32(q) ‖ u16(i) ‖ u8(0xff) ‖ SEED)</c>. This lets the entire private key be
/// reconstructed from the compact (I, SEED) pair, which is what keeps persisted signer state tiny.
/// </remarks>
internal static class LmOts
{
    /// <summary>Extracts the <paramref name="index"/>-th <c>w</c>-bit coefficient of <paramref name="s"/> (RFC 8554 §3.1.3).</summary>
    public static int Coefficient(ReadOnlySpan<byte> s, int index, int w)
    {
        int mask = (1 << w) - 1;
        int byteIndex = (index * w) / 8;
        int shift = 8 - (w * (index % (8 / w)) + w);
        return (s[byteIndex] >> shift) & mask;
    }

    /// <summary>Computes the LM-OTS checksum of message hash <paramref name="q"/> (RFC 8554 §4.4).</summary>
    public static ushort Checksum(ReadOnlySpan<byte> q, in LmOtsParams p)
    {
        int sum = 0;
        int max = p.MaxDigit;
        int count = p.CoefficientCount;
        for (int i = 0; i < count; i++)
        {
            sum += max - Coefficient(q, i, p.W);
        }

        return (ushort)(sum << p.Ls);
    }

    /// <summary>Builds the 20-byte <c>I ‖ u32(q)</c> prefix shared by every hash for one OTS key.</summary>
    private static void BuildPrefix(ReadOnlySpan<byte> identifier, uint q, Span<byte> prefix)
    {
        identifier.CopyTo(prefix);
        Endian.WriteU32(prefix.Slice(LmsConstants.IdentifierLength), q);
    }

    /// <summary>One Winternitz chain step: <c>H(I ‖ u32(q) ‖ u16(i) ‖ u8(j) ‖ input)</c>.</summary>
    private static void ChainStep(LmsHash hash, ReadOnlySpan<byte> prefix, ushort i, byte j, ReadOnlySpan<byte> input, Span<byte> output)
    {
        Span<byte> i2 = stackalloc byte[2];
        Endian.WriteU16(i2, i);
        hash.Update(prefix).Update(i2).UpdateByte(j).Update(input).Finish(output);
    }

    /// <summary>Derives the pseudorandom private element <c>x_q[i]</c> (RFC 8554 Appendix A).</summary>
    private static void PrivateElement(LmsHash hash, ReadOnlySpan<byte> prefix, ushort i, ReadOnlySpan<byte> seed, Span<byte> output)
        => ChainStep(hash, prefix, i, 0xff, seed, output);

    /// <summary>
    /// Computes the LM-OTS public key <c>K</c> for leaf <paramref name="q"/> from the tree's
    /// <paramref name="identifier"/> and <paramref name="seed"/>.
    /// </summary>
    public static void DeriveLeafPublicKey(
        LmsHash hash, in LmOtsParams p, ReadOnlySpan<byte> identifier, uint q, ReadOnlySpan<byte> seed, Span<byte> publicKey)
    {
        Span<byte> prefix = stackalloc byte[LmsConstants.IdentifierLength + 4];
        BuildPrefix(identifier, q, prefix);

        int n = p.N;
        Span<byte> tmp = stackalloc byte[n];
        byte[] yConcat = new byte[n * p.P];

        for (int i = 0; i < p.P; i++)
        {
            PrivateElement(hash, prefix, (ushort)i, seed, tmp);
            for (int j = 0; j < p.MaxDigit; j++)
            {
                ChainStep(hash, prefix, (ushort)i, (byte)j, tmp, tmp);
            }

            tmp.CopyTo(yConcat.AsSpan(i * n));
        }

        // K = H(I ‖ u32(q) ‖ u16(D_PBLC) ‖ y[0] ‖ … ‖ y[p-1])
        Span<byte> dpblc = stackalloc byte[2];
        Endian.WriteU16(dpblc, LmsConstants.D_PBLC);
        hash.Update(prefix).Update(dpblc).Update(yConcat).Finish(publicKey);
    }

    /// <summary>Computes the message hash <c>Q ‖ u16(Cksm(Q))</c> packed into <paramref name="hashed"/> (length n+2).</summary>
    private static void MessageHash(
        LmsHash hash, in LmOtsParams p, ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> randomizer, ReadOnlySpan<byte> message, Span<byte> hashed)
    {
        Span<byte> dmesg = stackalloc byte[2];
        Endian.WriteU16(dmesg, LmsConstants.D_MESG);
        Span<byte> q = hashed.Slice(0, p.N);
        hash.Update(prefix).Update(dmesg).Update(randomizer).Update(message).Finish(q);
        Endian.WriteU16(hashed.Slice(p.N), Checksum(q, p));
    }

    /// <summary>
    /// Produces an LM-OTS signature in wire format (<c>u32(type) ‖ C ‖ y[0..p-1]</c>) into
    /// <paramref name="signature"/> (length <see cref="LmOtsParams.SignatureLength"/>).
    /// </summary>
    public static void Sign(
        LmsHash hash, in LmOtsParams p, ReadOnlySpan<byte> identifier, uint q, ReadOnlySpan<byte> seed,
        ReadOnlySpan<byte> message, ReadOnlySpan<byte> randomizer, Span<byte> signature)
    {
        Span<byte> prefix = stackalloc byte[LmsConstants.IdentifierLength + 4];
        BuildPrefix(identifier, q, prefix);

        int n = p.N;
        Span<byte> hashed = stackalloc byte[n + 2];
        MessageHash(hash, p, prefix, randomizer, message, hashed);

        Endian.WriteU32(signature, (uint)p.Type);
        randomizer.CopyTo(signature.Slice(4));
        Span<byte> yArea = signature.Slice(4 + n);

        Span<byte> tmp = stackalloc byte[n];
        for (int i = 0; i < p.P; i++)
        {
            int a = Coefficient(hashed, i, p.W);
            PrivateElement(hash, prefix, (ushort)i, seed, tmp);
            for (int j = 0; j < a; j++)
            {
                ChainStep(hash, prefix, (ushort)i, (byte)j, tmp, tmp);
            }

            tmp.CopyTo(yArea.Slice(i * n));
        }
    }

    /// <summary>
    /// Recovers the candidate LM-OTS public key from a signature + message (RFC 8554 §4.6, Algorithm 4b).
    /// Returns <see langword="false"/> if the signature is malformed (wrong typecode/length).
    /// </summary>
    public static bool TryRecoverPublicKey(
        LmsHash hash, in LmOtsParams p, ReadOnlySpan<byte> identifier, uint q,
        ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature, Span<byte> candidate)
    {
        if (signature.Length != p.SignatureLength)
        {
            return false;
        }

        if (Endian.ReadU32(signature) != (uint)p.Type)
        {
            return false;
        }

        Span<byte> prefix = stackalloc byte[LmsConstants.IdentifierLength + 4];
        BuildPrefix(identifier, q, prefix);

        int n = p.N;
        ReadOnlySpan<byte> randomizer = signature.Slice(4, n);
        ReadOnlySpan<byte> yArea = signature.Slice(4 + n);

        Span<byte> hashed = stackalloc byte[n + 2];
        MessageHash(hash, p, prefix, randomizer, message, hashed);

        byte[] zConcat = new byte[n * p.P];
        Span<byte> tmp = stackalloc byte[n];
        for (int i = 0; i < p.P; i++)
        {
            int a = Coefficient(hashed, i, p.W);
            yArea.Slice(i * n, n).CopyTo(tmp);
            for (int j = a; j < p.MaxDigit; j++)
            {
                ChainStep(hash, prefix, (ushort)i, (byte)j, tmp, tmp);
            }

            tmp.CopyTo(zConcat.AsSpan(i * n));
        }

        Span<byte> dpblc = stackalloc byte[2];
        Endian.WriteU16(dpblc, LmsConstants.D_PBLC);
        hash.Update(prefix).Update(dpblc).Update(zConcat).Finish(candidate);
        return true;
    }
}
