using System.Buffers.Binary;

namespace PostQuantum.Lms.Internal;

/// <summary>
/// Big-endian integer encoding helpers matching the <c>u8str</c>/<c>u16str</c>/<c>u32str</c>
/// primitives defined in RFC 8554 §3.1. All multi-byte values in LMS/HSS are network byte order.
/// </summary>
internal static class Endian
{
    /// <summary>Writes a 32-bit value as 4 big-endian bytes (<c>u32str</c>).</summary>
    public static void WriteU32(Span<byte> destination, uint value)
        => BinaryPrimitives.WriteUInt32BigEndian(destination, value);

    /// <summary>Writes a 16-bit value as 2 big-endian bytes (<c>u16str</c>).</summary>
    public static void WriteU16(Span<byte> destination, ushort value)
        => BinaryPrimitives.WriteUInt16BigEndian(destination, value);

    /// <summary>Reads a big-endian 32-bit value.</summary>
    public static uint ReadU32(ReadOnlySpan<byte> source)
        => BinaryPrimitives.ReadUInt32BigEndian(source);

    /// <summary>Reads a big-endian 16-bit value.</summary>
    public static ushort ReadU16(ReadOnlySpan<byte> source)
        => BinaryPrimitives.ReadUInt16BigEndian(source);

    /// <summary>Allocates 4 bytes containing the big-endian representation of <paramref name="value"/>.</summary>
    public static byte[] U32(uint value)
    {
        var buffer = new byte[4];
        WriteU32(buffer, value);
        return buffer;
    }
}
