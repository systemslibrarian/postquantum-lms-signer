namespace PostQuantum.Lms;

/// <summary>
/// LM-OTS (Leighton-Micali One-Time Signature) parameter sets registered by RFC 8554 §4.1 and
/// NIST SP 800-208, identified by their on-the-wire 32-bit typecode.
/// </summary>
/// <remarks>
/// The Winternitz parameter <c>w</c> trades signature size against signing/verification time:
/// larger <c>w</c> ⇒ smaller signatures but more hashing. <c>w=8</c> is the usual choice for firmware.
/// <c>N32</c> = 32-byte hash (256-bit security); <c>N24</c> = 24-byte truncated hash (192-bit).
/// </remarks>
public enum LmOtsAlgorithm : uint
{
    /// <summary>SHA-256, n=32, w=1. Typecode 0x00000001.</summary>
    Sha256N32W1 = 0x00000001,

    /// <summary>SHA-256, n=32, w=2. Typecode 0x00000002.</summary>
    Sha256N32W2 = 0x00000002,

    /// <summary>SHA-256, n=32, w=4. Typecode 0x00000003.</summary>
    Sha256N32W4 = 0x00000003,

    /// <summary>SHA-256, n=32, w=8 (smallest signatures). Recommended firmware default. Typecode 0x00000004.</summary>
    Sha256N32W8 = 0x00000004,

    /// <summary>SHA-256/192 (truncated), n=24, w=1. Typecode 0x00000005.</summary>
    Sha256N24W1 = 0x00000005,

    /// <summary>SHA-256/192 (truncated), n=24, w=2. Typecode 0x00000006.</summary>
    Sha256N24W2 = 0x00000006,

    /// <summary>SHA-256/192 (truncated), n=24, w=4. Typecode 0x00000007.</summary>
    Sha256N24W4 = 0x00000007,

    /// <summary>SHA-256/192 (truncated), n=24, w=8. Typecode 0x00000008.</summary>
    Sha256N24W8 = 0x00000008,

    /// <summary>SHAKE256, n=32, w=1. Typecode 0x00000009.</summary>
    Shake256N32W1 = 0x00000009,

    /// <summary>SHAKE256, n=32, w=2. Typecode 0x0000000A.</summary>
    Shake256N32W2 = 0x0000000A,

    /// <summary>SHAKE256, n=32, w=4. Typecode 0x0000000B.</summary>
    Shake256N32W4 = 0x0000000B,

    /// <summary>SHAKE256, n=32, w=8. Typecode 0x0000000C.</summary>
    Shake256N32W8 = 0x0000000C,

    /// <summary>SHAKE256, n=24, w=1. Typecode 0x0000000D.</summary>
    Shake256N24W1 = 0x0000000D,

    /// <summary>SHAKE256, n=24, w=2. Typecode 0x0000000E.</summary>
    Shake256N24W2 = 0x0000000E,

    /// <summary>SHAKE256, n=24, w=4. Typecode 0x0000000F.</summary>
    Shake256N24W4 = 0x0000000F,

    /// <summary>SHAKE256, n=24, w=8. Typecode 0x00000010.</summary>
    Shake256N24W8 = 0x00000010,
}
