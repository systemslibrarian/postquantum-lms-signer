namespace PostQuantum.Lms;

/// <summary>
/// HSS (Hierarchical Signature System, RFC 8554 §6) parameters: an ordered list of
/// <see cref="LmsParameters"/>, one per tree level, from the root (index 0) down to the
/// message-signing tree (the last level). Total capacity is the product of each level's
/// <see cref="LmsParameters.MaxSignatures"/>.
/// </summary>
/// <remarks>
/// Why HSS rather than a single huge LMS tree? Key generation for a tree is O(2^h) hashing; a single
/// h=20 tree costs ~1&#160;million leaf computations up front. A two-level h=10/h=10 HSS gives the same
/// ~1&#160;million signatures while only ever materializing 1024-leaf subtrees — fast startup and small
/// working set, at the cost of a slightly larger signature.
/// </remarks>
public sealed class HssParameters
{
    private readonly LmsParameters[] _levels;

    /// <summary>The per-level parameters, root first.</summary>
    public IReadOnlyList<LmsParameters> Levels => _levels;

    /// <summary>Number of levels <c>L</c> in the hierarchy.</summary>
    public int LevelCount => _levels.Length;

    /// <summary>
    /// Total number of message signatures the key can produce: the product of every level's capacity.
    /// </summary>
    public long MaxSignatures
    {
        get
        {
            long product = 1;
            foreach (var level in _levels)
            {
                product = checked(product * level.MaxSignatures);
            }

            return product;
        }
    }

    /// <summary>Creates HSS parameters from one or more levels (root first). 1–8 levels are supported.</summary>
    public HssParameters(params LmsParameters[] levels)
    {
        ArgumentNullException.ThrowIfNull(levels);
        if (levels.Length is < 1 or > 8)
        {
            throw new ArgumentException("HSS supports between 1 and 8 levels.", nameof(levels));
        }

        _levels = (LmsParameters[])levels.Clone();
    }

    /// <summary>
    /// The recommended firmware/code-signing default: two-level HSS, SHA-256, h=10/h=10, w=8.
    /// ~1,048,576 signatures, CNSA 2.0-aligned, with compact signatures and fast startup.
    /// </summary>
    public static HssParameters FirmwareDefault { get; } =
        new(LmsParameters.H10W8, LmsParameters.H10W8);

    /// <summary>Single-level HSS wrapping <see cref="LmsParameters.FirmwareSingleTree"/> (32768 signatures).</summary>
    public static HssParameters SingleLevel { get; } =
        new(LmsParameters.FirmwareSingleTree);

    /// <summary>Small two-level set (h=5/h=5 ⇒ 1024 signatures) for tests and demos.</summary>
    public static HssParameters Small { get; } =
        new(LmsParameters.H5W8, LmsParameters.H5W8);
}
