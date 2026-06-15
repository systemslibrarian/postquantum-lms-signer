using System.Buffers.Binary;

namespace PostQuantum.Lms.Hybrid;

/// <summary>
/// Encoding helpers for a composite signature that concatenates a stateful LMS/HSS signature with a
/// stateless ML-DSA signature, each framed by a 4-byte big-endian length prefix.
/// </summary>
/// <remarks>
/// Wire format: <c>[4-byte BE len(a)][a bytes][4-byte BE len(b)][b bytes]</c>. The two components are
/// independent signatures over the same message; a verifier must validate <b>both</b>.
/// </remarks>
public static class HybridSignature
{
    private const int LengthPrefixSize = 4;

    /// <summary>Encodes the two component signatures into a single length-prefixed composite blob.</summary>
    /// <param name="lmsOrHssSignature">The stateful LMS/HSS signature component.</param>
    /// <param name="mlDsaSignature">The stateless ML-DSA signature component.</param>
    /// <returns>The composite signature bytes.</returns>
    public static byte[] Encode(ReadOnlySpan<byte> lmsOrHssSignature, ReadOnlySpan<byte> mlDsaSignature)
    {
        int total = LengthPrefixSize + lmsOrHssSignature.Length + LengthPrefixSize + mlDsaSignature.Length;
        byte[] buffer = new byte[total];
        Span<byte> span = buffer;

        BinaryPrimitives.WriteInt32BigEndian(span, lmsOrHssSignature.Length);
        lmsOrHssSignature.CopyTo(span.Slice(LengthPrefixSize));

        int offset = LengthPrefixSize + lmsOrHssSignature.Length;
        BinaryPrimitives.WriteInt32BigEndian(span.Slice(offset), mlDsaSignature.Length);
        mlDsaSignature.CopyTo(span.Slice(offset + LengthPrefixSize));

        return buffer;
    }

    /// <summary>Decodes a composite signature back into its two component signatures.</summary>
    /// <param name="composite">The composite signature produced by <see cref="Encode"/>.</param>
    /// <returns>A tuple of the LMS/HSS component and the ML-DSA component.</returns>
    /// <exception cref="ArgumentException">The composite is malformed or has inconsistent lengths.</exception>
    public static (byte[] LmsOrHss, byte[] MlDsa) Decode(ReadOnlySpan<byte> composite)
    {
        if (composite.Length < LengthPrefixSize)
        {
            throw new ArgumentException("Composite signature is truncated.", nameof(composite));
        }

        int lenA = BinaryPrimitives.ReadInt32BigEndian(composite);
        if (lenA < 0 || LengthPrefixSize + (long)lenA + LengthPrefixSize > composite.Length)
        {
            throw new ArgumentException("Composite signature first component length is invalid.", nameof(composite));
        }

        ReadOnlySpan<byte> a = composite.Slice(LengthPrefixSize, lenA);
        int offset = LengthPrefixSize + lenA;

        int lenB = BinaryPrimitives.ReadInt32BigEndian(composite.Slice(offset));
        if (lenB < 0 || offset + LengthPrefixSize + (long)lenB != composite.Length)
        {
            throw new ArgumentException("Composite signature second component length is invalid.", nameof(composite));
        }

        ReadOnlySpan<byte> b = composite.Slice(offset + LengthPrefixSize, lenB);
        return (a.ToArray(), b.ToArray());
    }
}
