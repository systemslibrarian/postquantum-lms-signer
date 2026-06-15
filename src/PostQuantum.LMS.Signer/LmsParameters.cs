using PostQuantum.Lms.Internal;

namespace PostQuantum.Lms;

/// <summary>
/// A complete LMS parameter selection: the Merkle-tree set (<see cref="LmsAlgorithm"/>) paired with
/// the one-time-signature set (<see cref="LmOtsAlgorithm"/>). Both must use the same hash family and
/// output length, which the constructor enforces.
/// </summary>
public sealed class LmsParameters : IEquatable<LmsParameters>
{
    /// <summary>The Merkle-tree (LMS) algorithm.</summary>
    public LmsAlgorithm Lms { get; }

    /// <summary>The one-time-signature (LM-OTS) algorithm.</summary>
    public LmOtsAlgorithm LmOts { get; }

    /// <summary>Tree height <c>h</c>.</summary>
    public int Height => LmsParams.Resolve(Lms).H;

    /// <summary>Total number of signatures this single tree can ever produce: <c>2^h</c>.</summary>
    public long MaxSignatures => LmsParams.Resolve(Lms).LeafCount;

    /// <summary>Size in bytes of a signature produced under these parameters.</summary>
    public int SignatureLength
    {
        get
        {
            var lms = LmsParams.Resolve(Lms);
            var ots = LmOtsParams.Resolve(LmOts);
            return 4 + ots.SignatureLength + 4 + (lms.H * lms.M);
        }
    }

    /// <summary>Size in bytes of the LMS public key.</summary>
    public int PublicKeyLength => 8 + LmsConstants.IdentifierLength + LmsParams.Resolve(Lms).M;

    /// <summary>Creates a validated parameter pair.</summary>
    /// <exception cref="ArgumentException">The two sets use different hash families or output lengths.</exception>
    public LmsParameters(LmsAlgorithm lms, LmOtsAlgorithm lmOts)
    {
        var lmsP = LmsParams.Resolve(lms);
        var otsP = LmOtsParams.Resolve(lmOts);
        if (lmsP.HashAlgorithm != otsP.HashAlgorithm || lmsP.M != otsP.N)
        {
            throw new ArgumentException(
                $"LMS set '{lms}' and LM-OTS set '{lmOts}' are incompatible: their hash family/output length must match.");
        }

        Lms = lms;
        LmOts = lmOts;
    }

    /// <summary>H=15 / w=8: 32768 signatures, compact ~1.6&#160;KB signatures. A good bounded-release default.</summary>
    public static LmsParameters FirmwareSingleTree { get; } =
        new(LmsAlgorithm.Sha256M32H15, LmOtsAlgorithm.Sha256N32W8);

    /// <summary>H=10 / w=8: 1024 signatures. The building block of the recommended two-level HSS default.</summary>
    public static LmsParameters H10W8 { get; } =
        new(LmsAlgorithm.Sha256M32H10, LmOtsAlgorithm.Sha256N32W8);

    /// <summary>H=5 / w=8: 32 signatures. Small/fast — handy for tests and short-lived keys.</summary>
    public static LmsParameters H5W8 { get; } =
        new(LmsAlgorithm.Sha256M32H5, LmOtsAlgorithm.Sha256N32W8);

    /// <inheritdoc />
    public bool Equals(LmsParameters? other) => other is not null && Lms == other.Lms && LmOts == other.LmOts;

    /// <inheritdoc />
    public override bool Equals(object? obj) => Equals(obj as LmsParameters);

    /// <inheritdoc />
    public override int GetHashCode() => HashCode.Combine(Lms, LmOts);

    /// <inheritdoc />
    public override string ToString() => $"{Lms}+{LmOts}";
}
