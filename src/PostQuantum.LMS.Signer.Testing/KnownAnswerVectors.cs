namespace PostQuantum.Lms.Testing;

/// <summary>
/// A single LMS/HSS known-answer test (KAT): a public key, message, and signature in RFC 8554 wire
/// format, with the expected verification result.
/// </summary>
public sealed class KnownAnswerVector
{
    /// <summary>A human-readable label for the vector.</summary>
    public required string Name { get; init; }

    /// <summary>The public key bytes (hex-decoded).</summary>
    public required byte[] PublicKey { get; init; }

    /// <summary>The message bytes (hex-decoded).</summary>
    public required byte[] Message { get; init; }

    /// <summary>The signature bytes (hex-decoded).</summary>
    public required byte[] Signature { get; init; }

    /// <summary>Whether <see cref="Signature"/> should verify against <see cref="PublicKey"/>/<see cref="Message"/>.</summary>
    public required bool Expected { get; init; }

    /// <summary>True for HSS vectors, false for single-tree LMS vectors.</summary>
    public required bool IsHss { get; init; }
}

/// <summary>
/// Pinned known-answer vectors used as regression anchors. The LMS vector below was produced from a
/// fixed identifier/seed and independently cross-validated against BouncyCastle (an RFC 8554-conformant
/// implementation), so it doubles as an interop check against the standard wire format.
/// </summary>
/// <remarks>
/// To add the official RFC 8554 Appendix F vectors, decode their hex and append <see cref="KnownAnswerVector"/>
/// entries here. The harness in <see cref="AssertAll"/> will pick them up automatically.
/// </remarks>
public static class KnownAnswerVectors
{
    // LMS_SHA256_M32_H5 + LMOTS_SHA256_N32_W8, I = 00..0f, seed = 80..9f.
    private const string LmsPublicKeyHex =
        "0000000500000004000102030405060708090a0b0c0d0e0f79963e99555018dd280eed3da9377ec8c829fa848ee295159d954fec14efa1f5";

    private const string LmsMessageHex =
        "506f73745175616e74756d2e4c4d532e5369676e6572204b4154";

    private const string LmsSignatureHex =
        "00000000000000043b0c1de8e72eb64f341ab7e0834ebeb81e05feda514abe9c736f06afe9e5f27e557abb0a90ef698cfd13ad09b86ebfa687100872eed7b041882c125eb586b5383b563613a35e02b7fa92fc5f58b3e346276df335ec49b2df11d98e46dd9fbfdc62f82d63e92443d9a6a948a34b1bc125c8de23d89b27686e10db6076849082f48f512eb3ad8bd04f2147544eb9623b9f7ddb288a60c2fd78cfe35f5f42e14e2bf4774838f8d7eced077f140985505d6709125eb9db7db4ec42c73ba7fceb1bc546179f9b2ab8ef1996df2fe5129bf03cd61a2f6902c5ee026b1e8c2c845421fd6eace5e8e1c6ca20cf715e9872ebb6a6db89bd3e999a2a049a2342c3de6a5be33be5eec306af5b7037a25b8add4a38f2ab092333edcfab4a320991f39f722e4aceee3d40c1454a3a9cb29627d2dfe59d84deed698f10b5d072d740ae4f2838ccce855ffaeb83932d8cd7d7f3ab692e34c23e2f9e4a4a22e23db28ddeba2cf906c7e72ddb3ada109ad2db7e2bfec563a7556a95c9de700f8cfeea7b1cdc690d0afbba61d67ee3b4d52901dc58e82c50cb7598e39b05e25e8e7d89f8bac2eed9e27764ce4bbd304179f999272eb3d15b9d5fc67f43ae37db5e4de6ce39e3d37ad95940152b4275f4da29248cb9d6400f2613243d36b1fbb7189263659bb60ed6cb7886278cd492c9cb8117a94708292d85695b31ba57d064d3914dfc48a6caf902721f30ffb67f47abf3880b47d1678585fb3f12c921cd0f307324f8086f8939158686b6516b28513b2ffdf21f42299df0d2d52a8ab4438773b5a6a4f211dd21bfb52e8af4abe1a0b8a04c49ffd44044d7b57a9056f48ab9351aeee3504e52ebc87ac6cda1752eb92adb685a9d9901d45a42ce54bc13af00b8f364bebf043b70aaff18b33e03c464bb7249b2d7f22e095534ef33fefa0fe6578a31bda58cd1e534299932e10bbe224b5ff7d91f7895b42368047606c345df9988c46d8eedbe2fb1aadb9849e05dceabf23f2a95bb06bc3ca58811fc1cacd6374a0f43334b4cdc242db81eae945c369f62df0c2790125e9ba0a5c52606c0f5c7be102c94359456f338faa4f2e90da386f094b6136f1f35950d58440f311cb0a67f80e7983a6de90f0060c77644e2b9ac1005d128b73c89ebe218aa8d3a042d4c677239838933e2e5698a7486ecb7e66482a0acc1761d9d3dbbb7726bf1acf5c9aa038a7eb1055410c4dbda345e7829609ee1055f35fd1f192fd4b0c123fb3cc2e99ee489facf59bbb4113985dcd04b3caf6e2ef8b650cace3ff50f8cab33efb047976fca1dcb8a5f0411e87464160aa59dd66345174d55b1dd15a91430e34f81a11d17de7afa04a3cbee1c5f207e4fc2effd8af642aec4890d5705358e9c1d84194e7e7adb1ce9edc9eb4834ffa8bc5a8cd989115a249a059a0c0bb9a6857edaf8e529d6f5e7d26eb0fbb595d58a6fc98ab1cf2aaed26c61192ab52951f844d68ebf26bda845772b5e4b30ef150c495cb259ff22be3138cb43ffa1beed95e0fe1a1053c2fb69646b4d0267fecbb6e5ac3c99b9777a1ff84af5496fe312f0c255774bced90ff9c418000000059e6f8432ed2751be3062087b7d29467220b516f4fa005825a606f333bed9d7592f67efe93974031901cb83ccc59c7081b4b5cb666ee352a183621f266f179d3ce703b8d1428c0376c3dec7fb857fb28a6b3b1808dadeb60ba0be28ba7500d444352a9703964c451967856d5a140cc1df971202cfb4807addb0ab74adc73b5e387efe3f607e42c841a807a9dd80474fff2c9c8ac04476ec5bb5dc13cb3035d536";

    /// <summary>All pinned vectors.</summary>
    public static IReadOnlyList<KnownAnswerVector> All { get; } = BuildVectors();

    private static KnownAnswerVector[] BuildVectors()
    {
        byte[] pub = Convert.FromHexString(LmsPublicKeyHex);
        byte[] msg = Convert.FromHexString(LmsMessageHex);
        byte[] sig = Convert.FromHexString(LmsSignatureHex);

        byte[] tampered = (byte[])msg.Clone();
        tampered[0] ^= 0xFF;

        return
        [
            new KnownAnswerVector
            {
                Name = "LMS_SHA256_M32_H5/W8 valid (BouncyCastle cross-validated)",
                PublicKey = pub, Message = msg, Signature = sig, Expected = true, IsHss = false,
            },
            new KnownAnswerVector
            {
                Name = "LMS_SHA256_M32_H5/W8 tampered message must fail",
                PublicKey = pub, Message = tampered, Signature = sig, Expected = false, IsHss = false,
            },
        ];
    }

    /// <summary>
    /// Runs every pinned vector through the public verifier and throws if any result disagrees with
    /// its expected value. Call this from your own test project to guard against accidental wire-format
    /// or algorithm regressions.
    /// </summary>
    /// <exception cref="InvalidOperationException">A vector produced an unexpected verification result.</exception>
    public static void AssertAll()
    {
        foreach (KnownAnswerVector v in All)
        {
            bool actual = v.IsHss
                ? HssSigner.Verify(v.PublicKey, v.Message, v.Signature)
                : LmsSigner.Verify(v.PublicKey, v.Message, v.Signature);

            if (actual != v.Expected)
            {
                throw new InvalidOperationException(
                    $"Known-answer vector '{v.Name}' failed: expected verify={v.Expected}, got {actual}.");
            }
        }
    }
}
