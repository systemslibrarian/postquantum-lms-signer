namespace PostQuantum.Lms;

/// <summary>
/// LMS (Leighton-Micali Signature) Merkle-tree parameter sets registered by RFC 8554 §5.1 and
/// NIST SP 800-208, identified by their on-the-wire 32-bit typecode. The height <c>h</c> fixes the
/// number of one-time keys (signatures) a single tree can ever produce: exactly <c>2^h</c>.
/// <c>M32</c> = 32-byte nodes (256-bit); <c>M24</c> = 24-byte nodes (192-bit).
/// </summary>
public enum LmsAlgorithm : uint
{
    /// <summary>SHA-256, m=32, height 5 ⇒ 32 signatures. Typecode 0x00000005.</summary>
    Sha256M32H5 = 0x00000005,

    /// <summary>SHA-256, m=32, height 10 ⇒ 1024 signatures. Typecode 0x00000006.</summary>
    Sha256M32H10 = 0x00000006,

    /// <summary>SHA-256, m=32, height 15 ⇒ 32768 signatures. Typecode 0x00000007.</summary>
    Sha256M32H15 = 0x00000007,

    /// <summary>SHA-256, m=32, height 20 ⇒ 1048576 signatures. Typecode 0x00000008.</summary>
    Sha256M32H20 = 0x00000008,

    /// <summary>SHA-256, m=32, height 25 ⇒ 33554432 signatures. Typecode 0x00000009.</summary>
    Sha256M32H25 = 0x00000009,

    /// <summary>SHA-256/192 (truncated), m=24, height 5. Typecode 0x0000000A.</summary>
    Sha256M24H5 = 0x0000000A,

    /// <summary>SHA-256/192 (truncated), m=24, height 10. Typecode 0x0000000B.</summary>
    Sha256M24H10 = 0x0000000B,

    /// <summary>SHA-256/192 (truncated), m=24, height 15. Typecode 0x0000000C.</summary>
    Sha256M24H15 = 0x0000000C,

    /// <summary>SHA-256/192 (truncated), m=24, height 20. Typecode 0x0000000D.</summary>
    Sha256M24H20 = 0x0000000D,

    /// <summary>SHA-256/192 (truncated), m=24, height 25. Typecode 0x0000000E.</summary>
    Sha256M24H25 = 0x0000000E,

    /// <summary>SHAKE256, m=32, height 5. Typecode 0x0000000F.</summary>
    Shake256M32H5 = 0x0000000F,

    /// <summary>SHAKE256, m=32, height 10. Typecode 0x00000010.</summary>
    Shake256M32H10 = 0x00000010,

    /// <summary>SHAKE256, m=32, height 15. Typecode 0x00000011.</summary>
    Shake256M32H15 = 0x00000011,

    /// <summary>SHAKE256, m=32, height 20. Typecode 0x00000012.</summary>
    Shake256M32H20 = 0x00000012,

    /// <summary>SHAKE256, m=32, height 25. Typecode 0x00000013.</summary>
    Shake256M32H25 = 0x00000013,

    /// <summary>SHAKE256, m=24, height 5. Typecode 0x00000014.</summary>
    Shake256M24H5 = 0x00000014,

    /// <summary>SHAKE256, m=24, height 10. Typecode 0x00000015.</summary>
    Shake256M24H10 = 0x00000015,

    /// <summary>SHAKE256, m=24, height 15. Typecode 0x00000016.</summary>
    Shake256M24H15 = 0x00000016,

    /// <summary>SHAKE256, m=24, height 20. Typecode 0x00000017.</summary>
    Shake256M24H20 = 0x00000017,

    /// <summary>SHAKE256, m=24, height 25. Typecode 0x00000018.</summary>
    Shake256M24H25 = 0x00000018,
}
