using System.Buffers.Binary;
using Org.BouncyCastle.Crypto.Parameters;

namespace PostQuantum.Lms.Hybrid;

/// <summary>
/// A self-describing bundle of the two public keys needed to verify a hybrid signature: the HSS public
/// key (RFC 8554 wire format) and the ML-DSA public key plus its parameter set. Distribute one
/// <see cref="Encode"/>d blob to your devices and verification is a single call.
/// </summary>
/// <remarks>
/// Wire format: <c>u8 version(1) ‖ u8 mlDsaParamId ‖ u32 len(hssPub) ‖ hssPub ‖ u32 len(mlDsaPub) ‖ mlDsaPub</c>
/// (all lengths big-endian).
/// </remarks>
public sealed class HybridPublicKey
{
    private const byte FormatVersion = 1;

    /// <summary>The HSS public key in RFC 8554 wire format.</summary>
    public byte[] HssPublicKey { get; }

    /// <summary>The ML-DSA parameter set of <see cref="MlDsaPublicKey"/>.</summary>
    public MLDsaParameters MlDsaParameters { get; }

    /// <summary>The raw encoded ML-DSA public key.</summary>
    public byte[] MlDsaPublicKey { get; }

    /// <summary>Creates a bundle from its parts.</summary>
    public HybridPublicKey(byte[] hssPublicKey, MLDsaParameters mlDsaParameters, byte[] mlDsaPublicKey)
    {
        ArgumentNullException.ThrowIfNull(hssPublicKey);
        ArgumentNullException.ThrowIfNull(mlDsaParameters);
        ArgumentNullException.ThrowIfNull(mlDsaPublicKey);
        HssPublicKey = hssPublicKey;
        MlDsaParameters = mlDsaParameters;
        MlDsaPublicKey = mlDsaPublicKey;
    }

    /// <summary>Serializes the bundle to a single portable blob.</summary>
    public byte[] Encode()
    {
        byte paramId = ParamId(MlDsaParameters);
        byte[] buffer = new byte[1 + 1 + 4 + HssPublicKey.Length + 4 + MlDsaPublicKey.Length];
        Span<byte> span = buffer;
        span[0] = FormatVersion;
        span[1] = paramId;
        BinaryPrimitives.WriteInt32BigEndian(span.Slice(2), HssPublicKey.Length);
        HssPublicKey.CopyTo(span.Slice(6));
        int offset = 6 + HssPublicKey.Length;
        BinaryPrimitives.WriteInt32BigEndian(span.Slice(offset), MlDsaPublicKey.Length);
        MlDsaPublicKey.CopyTo(span.Slice(offset + 4));
        return buffer;
    }

    /// <summary>Parses a bundle produced by <see cref="Encode"/>.</summary>
    /// <exception cref="ArgumentException">The blob is malformed or uses an unknown ML-DSA parameter id.</exception>
    public static HybridPublicKey Decode(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length < 6 || encoded[0] != FormatVersion)
        {
            throw new ArgumentException("Hybrid public key is truncated or has an unknown format.", nameof(encoded));
        }

        MLDsaParameters parameters = ParamFromId(encoded[1]);
        int hssLen = BinaryPrimitives.ReadInt32BigEndian(encoded.Slice(2));
        if (hssLen < 0 || 6L + hssLen + 4 > encoded.Length)
        {
            throw new ArgumentException("Hybrid public key HSS section length is invalid.", nameof(encoded));
        }

        byte[] hssPub = encoded.Slice(6, hssLen).ToArray();
        int offset = 6 + hssLen;
        int mlLen = BinaryPrimitives.ReadInt32BigEndian(encoded.Slice(offset));
        if (mlLen < 0 || offset + 4L + mlLen != encoded.Length)
        {
            throw new ArgumentException("Hybrid public key ML-DSA section length is invalid.", nameof(encoded));
        }

        byte[] mlPub = encoded.Slice(offset + 4, mlLen).ToArray();
        return new HybridPublicKey(hssPub, parameters, mlPub);
    }

    /// <summary>Verifies a composite signature requiring BOTH legs to pass. Never throws on bad input — returns false.</summary>
    public bool Verify(byte[] message, byte[] compositeSignature)
        => HybridHssMlDsaSigner.Verify(HssPublicKey, MlDsaParameters, MlDsaPublicKey, message, compositeSignature);

    private static byte ParamId(MLDsaParameters p)
    {
        if (p == MLDsaParameters.ml_dsa_44) { return 1; }
        if (p == MLDsaParameters.ml_dsa_65) { return 2; }
        if (p == MLDsaParameters.ml_dsa_87) { return 3; }
        throw new ArgumentException(
            $"Unsupported ML-DSA parameter set '{p.Name}' for a hybrid public key. Use ml_dsa_44/65/87.");
    }

    private static MLDsaParameters ParamFromId(byte id) => id switch
    {
        1 => MLDsaParameters.ml_dsa_44,
        2 => MLDsaParameters.ml_dsa_65,
        3 => MLDsaParameters.ml_dsa_87,
        _ => throw new ArgumentException($"Unknown ML-DSA parameter id {id} in hybrid public key."),
    };
}
