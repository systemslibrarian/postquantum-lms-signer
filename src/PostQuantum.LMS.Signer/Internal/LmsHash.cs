using System.Security.Cryptography;

namespace PostQuantum.Lms.Internal;

/// <summary>
/// The hash function family selected by an LMS/LM-OTS parameter set.
/// RFC 8554 registers SHA-256 sets; SP 800-208 additionally registers SHAKE256 and
/// truncated (n=24) sets. v1 implements the SHA-256 (n=32) family; the seam exists for the rest.
/// </summary>
internal enum LmsHashAlgorithm
{
    /// <summary>SHA-256, 32-byte output. RFC 8554 registered sets.</summary>
    Sha256 = 0,

    /// <summary>SHAKE256 with 32-byte output (SP 800-208). Reserved — not yet implemented.</summary>
    Shake256 = 1,
}

/// <summary>
/// A reusable incremental hasher implementing the RFC 8554 <c>H</c> primitive.
/// Not thread-safe by design: a single instance is owned by one signing/verification operation,
/// which always runs under the signer's state lock. Reuse (Update… then <see cref="Finish(Span{byte})"/>)
/// avoids per-hash allocation in the hot Winternitz chains.
/// </summary>
internal sealed class LmsHash : IDisposable
{
    private readonly IncrementalHash _hash;

    /// <summary>The hash output length <c>n</c> in bytes.</summary>
    public int Length { get; }

    private LmsHash(IncrementalHash hash, int length)
    {
        _hash = hash;
        Length = length;
    }

    /// <summary>Creates a fresh hasher for the given algorithm.</summary>
    public static LmsHash Create(LmsHashAlgorithm algorithm) => algorithm switch
    {
        LmsHashAlgorithm.Sha256 => new LmsHash(IncrementalHash.CreateHash(HashAlgorithmName.SHA256), 32),
        _ => throw new NotSupportedException(
            $"Hash algorithm '{algorithm}' is registered by SP 800-208 but not implemented in this release. " +
            "Use a SHA-256 (n=32) parameter set."),
    };

    /// <summary>Appends data to the running hash.</summary>
    public LmsHash Update(ReadOnlySpan<byte> data)
    {
        _hash.AppendData(data);
        return this;
    }

    /// <summary>Appends a single byte (used for the <c>u8str(j)</c> Winternitz iteration index).</summary>
    public LmsHash UpdateByte(byte value)
    {
        Span<byte> b = stackalloc byte[1] { value };
        _hash.AppendData(b);
        return this;
    }

    /// <summary>Finalizes into <paramref name="destination"/> and resets for reuse.</summary>
    public void Finish(Span<byte> destination) => _hash.GetHashAndReset(destination);

    public void Dispose() => _hash.Dispose();
}
