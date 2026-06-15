namespace PostQuantum.Lms.Internal;

/// <summary>
/// Resolved numeric parameters for an LMS typecode (RFC 8554 §5.1, Table 2).
/// </summary>
/// <param name="Type">On-the-wire typecode.</param>
/// <param name="HashAlgorithm">Hash family.</param>
/// <param name="M">Node hash length in bytes.</param>
/// <param name="H">Merkle tree height.</param>
internal readonly record struct LmsParams(
    LmsAlgorithm Type,
    LmsHashAlgorithm HashAlgorithm,
    int M,
    int H)
{
    /// <summary>Number of one-time keys (leaves / signatures) the tree can produce: <c>2^h</c>.</summary>
    public long LeafCount => 1L << H;

    /// <summary>Resolves the parameters for a typecode. Values are taken verbatim from RFC 8554 / SP 800-208.</summary>
    public static LmsParams Resolve(LmsAlgorithm type) => type switch
    {
        // SHA-256, m=32
        LmsAlgorithm.Sha256M32H5 => new(type, LmsHashAlgorithm.Sha256N32, M: 32, H: 5),
        LmsAlgorithm.Sha256M32H10 => new(type, LmsHashAlgorithm.Sha256N32, M: 32, H: 10),
        LmsAlgorithm.Sha256M32H15 => new(type, LmsHashAlgorithm.Sha256N32, M: 32, H: 15),
        LmsAlgorithm.Sha256M32H20 => new(type, LmsHashAlgorithm.Sha256N32, M: 32, H: 20),
        LmsAlgorithm.Sha256M32H25 => new(type, LmsHashAlgorithm.Sha256N32, M: 32, H: 25),
        // SHA-256/192 (truncated), m=24
        LmsAlgorithm.Sha256M24H5 => new(type, LmsHashAlgorithm.Sha256N24, M: 24, H: 5),
        LmsAlgorithm.Sha256M24H10 => new(type, LmsHashAlgorithm.Sha256N24, M: 24, H: 10),
        LmsAlgorithm.Sha256M24H15 => new(type, LmsHashAlgorithm.Sha256N24, M: 24, H: 15),
        LmsAlgorithm.Sha256M24H20 => new(type, LmsHashAlgorithm.Sha256N24, M: 24, H: 20),
        LmsAlgorithm.Sha256M24H25 => new(type, LmsHashAlgorithm.Sha256N24, M: 24, H: 25),
        // SHAKE256, m=32
        LmsAlgorithm.Shake256M32H5 => new(type, LmsHashAlgorithm.Shake256N32, M: 32, H: 5),
        LmsAlgorithm.Shake256M32H10 => new(type, LmsHashAlgorithm.Shake256N32, M: 32, H: 10),
        LmsAlgorithm.Shake256M32H15 => new(type, LmsHashAlgorithm.Shake256N32, M: 32, H: 15),
        LmsAlgorithm.Shake256M32H20 => new(type, LmsHashAlgorithm.Shake256N32, M: 32, H: 20),
        LmsAlgorithm.Shake256M32H25 => new(type, LmsHashAlgorithm.Shake256N32, M: 32, H: 25),
        // SHAKE256, m=24
        LmsAlgorithm.Shake256M24H5 => new(type, LmsHashAlgorithm.Shake256N24, M: 24, H: 5),
        LmsAlgorithm.Shake256M24H10 => new(type, LmsHashAlgorithm.Shake256N24, M: 24, H: 10),
        LmsAlgorithm.Shake256M24H15 => new(type, LmsHashAlgorithm.Shake256N24, M: 24, H: 15),
        LmsAlgorithm.Shake256M24H20 => new(type, LmsHashAlgorithm.Shake256N24, M: 24, H: 20),
        LmsAlgorithm.Shake256M24H25 => new(type, LmsHashAlgorithm.Shake256N24, M: 24, H: 25),
        _ => throw new ArgumentOutOfRangeException(nameof(type), type, "Unknown LMS typecode."),
    };
}
