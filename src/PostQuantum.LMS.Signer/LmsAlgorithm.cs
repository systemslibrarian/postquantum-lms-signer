namespace PostQuantum.Lms;

/// <summary>
/// LMS (Leighton-Micali Signature) Merkle-tree parameter sets registered by RFC 8554 §5.1,
/// identified by their on-the-wire 32-bit typecode. The height <c>h</c> fixes the number of
/// one-time keys (signatures) a single tree can ever produce: exactly <c>2^h</c>.
/// </summary>
public enum LmsAlgorithm : uint
{
    /// <summary>Height 5 ⇒ 32 signatures. Typecode 0x00000005.</summary>
    Sha256M32H5 = 0x00000005,

    /// <summary>Height 10 ⇒ 1024 signatures. Typecode 0x00000006.</summary>
    Sha256M32H10 = 0x00000006,

    /// <summary>Height 15 ⇒ 32768 signatures. Typecode 0x00000007.</summary>
    Sha256M32H15 = 0x00000007,

    /// <summary>Height 20 ⇒ 1048576 signatures. Typecode 0x00000008.</summary>
    Sha256M32H20 = 0x00000008,

    /// <summary>Height 25 ⇒ 33554432 signatures. Typecode 0x00000009.</summary>
    Sha256M32H25 = 0x00000009,
}
