using System.Security.Cryptography;

namespace PostQuantum.Lms.Internal;

/// <summary>
/// The hash function family + output length selected by an LMS/LM-OTS parameter set, per
/// NIST SP 800-208: SHA-256 and SHAKE256, each at full (n=32) or truncated (n=24) output.
/// </summary>
internal enum LmsHashAlgorithm
{
    /// <summary>SHA-256, 32-byte output (RFC 8554).</summary>
    Sha256N32 = 0,

    /// <summary>SHA-256 truncated to 24 bytes / 192 bits (SP 800-208).</summary>
    Sha256N24 = 1,

    /// <summary>SHAKE256 with 32-byte output (SP 800-208).</summary>
    Shake256N32 = 2,

    /// <summary>SHAKE256 with 24-byte output (SP 800-208).</summary>
    Shake256N24 = 3,
}

/// <summary>
/// A reusable incremental hasher implementing the RFC 8554 / SP 800-208 <c>H</c> primitive across all
/// four registered hash families. Not thread-safe by design: one instance is owned by a single
/// signing/verification operation, which always runs under the signer's state lock.
/// </summary>
internal sealed class LmsHash : IDisposable
{
    private readonly IncrementalHash? _sha;   // SHA-256 family
    private readonly Shake256? _shake;        // SHAKE256 family
    private readonly bool _truncate;          // true for n=24 (SHA-256 produces 32 → take first 24)

    /// <summary>The hash output length <c>n</c> in bytes (24 or 32).</summary>
    public int Length { get; }

    private LmsHash(IncrementalHash? sha, Shake256? shake, int length, bool truncate)
    {
        _sha = sha;
        _shake = shake;
        Length = length;
        _truncate = truncate;
    }

    /// <summary>Creates a fresh hasher for the given algorithm.</summary>
    public static LmsHash Create(LmsHashAlgorithm algorithm) => algorithm switch
    {
        LmsHashAlgorithm.Sha256N32 => new LmsHash(IncrementalHash.CreateHash(HashAlgorithmName.SHA256), null, 32, truncate: false),
        LmsHashAlgorithm.Sha256N24 => new LmsHash(IncrementalHash.CreateHash(HashAlgorithmName.SHA256), null, 24, truncate: true),
        LmsHashAlgorithm.Shake256N32 => new LmsHash(null, new Shake256(), 32, truncate: false),
        LmsHashAlgorithm.Shake256N24 => new LmsHash(null, new Shake256(), 24, truncate: false),
        _ => throw new NotSupportedException($"Unknown hash algorithm '{algorithm}'."),
    };

    /// <summary>Appends data to the running hash.</summary>
    public LmsHash Update(ReadOnlySpan<byte> data)
    {
        if (_sha is not null)
        {
            _sha.AppendData(data);
        }
        else
        {
            _shake!.AppendData(data);
        }

        return this;
    }

    /// <summary>Appends a single byte (used for the <c>u8str(j)</c> Winternitz iteration index).</summary>
    public LmsHash UpdateByte(byte value)
    {
        Span<byte> b = stackalloc byte[1] { value };
        return Update(b);
    }

    /// <summary>Finalizes <c>n</c> bytes into <paramref name="destination"/> and resets for reuse.</summary>
    public void Finish(Span<byte> destination)
    {
        if (_shake is not null)
        {
            // SHAKE is an XOF: request exactly n bytes.
            _shake.GetHashAndReset(destination.Slice(0, Length));
            return;
        }

        if (_truncate)
        {
            // SHA-256 produces 32 bytes; SP 800-208 n=24 sets take the leftmost 24.
            Span<byte> full = stackalloc byte[32];
            _sha!.GetHashAndReset(full);
            full.Slice(0, Length).CopyTo(destination);
        }
        else
        {
            _sha!.GetHashAndReset(destination);
        }
    }

    public void Dispose()
    {
        _sha?.Dispose();
        _shake?.Dispose();
    }
}
