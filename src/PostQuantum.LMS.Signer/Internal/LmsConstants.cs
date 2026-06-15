namespace PostQuantum.Lms.Internal;

/// <summary>
/// Domain-separation tags from RFC 8554 §4.2/§5.3. These 16-bit values are mixed into every
/// hash to ensure leaf, interior, public-key, and message hashes can never collide.
/// </summary>
internal static class LmsConstants
{
    /// <summary>Domain separator for an LM-OTS public key hash.</summary>
    public const ushort D_PBLC = 0x8080;

    /// <summary>Domain separator for the message hash inside LM-OTS.</summary>
    public const ushort D_MESG = 0x8181;

    /// <summary>Domain separator for an LMS Merkle leaf node.</summary>
    public const ushort D_LEAF = 0x8282;

    /// <summary>Domain separator for an LMS Merkle interior node.</summary>
    public const ushort D_INTR = 0x8383;

    /// <summary>Length in bytes of the LMS key identifier <c>I</c> (RFC 8554 §5).</summary>
    public const int IdentifierLength = 16;
}
