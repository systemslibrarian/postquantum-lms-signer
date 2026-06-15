namespace PostQuantum.Lms;

/// <summary>
/// LM-OTS (Leighton-Micali One-Time Signature) parameter sets registered by
/// RFC 8554 §4.1, identified by their on-the-wire 32-bit typecode.
/// </summary>
/// <remarks>
/// The Winternitz parameter <c>w</c> trades signature size against signing/verification time:
/// larger <c>w</c> ⇒ smaller signatures but more hashing. <c>w=8</c> is the usual choice for
/// firmware where signature footprint matters.
/// </remarks>
public enum LmOtsAlgorithm : uint
{
    /// <summary>w=1: largest signatures (~8.5&#160;KB), fewest hashes. Typecode 0x00000001.</summary>
    Sha256N32W1 = 0x00000001,

    /// <summary>w=2. Typecode 0x00000002.</summary>
    Sha256N32W2 = 0x00000002,

    /// <summary>w=4. Typecode 0x00000003.</summary>
    Sha256N32W4 = 0x00000003,

    /// <summary>w=8: smallest signatures (~1.1&#160;KB), most hashes. Recommended firmware default. Typecode 0x00000004.</summary>
    Sha256N32W8 = 0x00000004,
}
