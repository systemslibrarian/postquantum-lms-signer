namespace PostQuantum.Lms.Internal;

/// <summary>
/// Resolved numeric parameters for an LM-OTS typecode (RFC 8554 §4.1, Table 1).
/// </summary>
/// <param name="Type">On-the-wire typecode.</param>
/// <param name="HashAlgorithm">Hash family.</param>
/// <param name="N">Hash output length in bytes.</param>
/// <param name="W">Winternitz width in bits (1, 2, 4, or 8).</param>
/// <param name="P">Number of n-byte chains in a signature.</param>
/// <param name="Ls">Left-shift applied to the checksum.</param>
internal readonly record struct LmOtsParams(
    LmOtsAlgorithm Type,
    LmsHashAlgorithm HashAlgorithm,
    int N,
    int W,
    int P,
    int Ls)
{
    /// <summary>Number of <c>w</c>-bit coefficients across the n-byte message hash: <c>8n/w</c>.</summary>
    public int CoefficientCount => (8 * N) / W;

    /// <summary>Maximum value of a Winternitz chain step: <c>2^w - 1</c>.</summary>
    public int MaxDigit => (1 << W) - 1;

    /// <summary>Total signature length in bytes: <c>4 (type) + n (randomizer C) + n*p</c>.</summary>
    public int SignatureLength => 4 + N + (N * P);

    /// <summary>Resolves the parameters for a typecode. Values are taken verbatim from RFC 8554 Table 1.</summary>
    public static LmOtsParams Resolve(LmOtsAlgorithm type) => type switch
    {
        LmOtsAlgorithm.Sha256N32W1 => new(type, LmsHashAlgorithm.Sha256, N: 32, W: 1, P: 265, Ls: 7),
        LmOtsAlgorithm.Sha256N32W2 => new(type, LmsHashAlgorithm.Sha256, N: 32, W: 2, P: 133, Ls: 6),
        LmOtsAlgorithm.Sha256N32W4 => new(type, LmsHashAlgorithm.Sha256, N: 32, W: 4, P: 67, Ls: 4),
        LmOtsAlgorithm.Sha256N32W8 => new(type, LmsHashAlgorithm.Sha256, N: 32, W: 8, P: 34, Ls: 0),
        _ => throw new ArgumentOutOfRangeException(nameof(type), type, "Unknown LM-OTS typecode."),
    };
}
