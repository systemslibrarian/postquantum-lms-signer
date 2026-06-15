using PostQuantum.Lms;
using PostQuantum.Lms.Hybrid;
using PostQuantum.Lms.State;
using Org.BouncyCastle.Crypto.Parameters;

namespace PostQuantum.Lms.Tests;

/// <summary>
/// Tests the production hybrid signer: a composite of a stateful HSS signature and a stateless ML-DSA
/// signature, where verification requires BOTH legs. Uses real generated ML-DSA keys.
/// </summary>
public sealed class HybridTests
{
    private static async Task<(HybridHssMlDsaSigner signer, HybridPublicKey pub)> NewSignerAsync()
    {
        var hss = await HssSigner.CreateAsync(HssParameters.Small, new InMemoryStateStore(), "k");
        var mlDsa = MlDsaKeyPair.Generate(); // ML-DSA-65 default
        var signer = new HybridHssMlDsaSigner(hss, mlDsa);
        return (signer, signer.PublicKey());
    }

    [Fact]
    public async Task EndToEnd_BothLegsVerify()
    {
        var (signer, pub) = await NewSignerAsync();
        byte[] message = "firmware-v9.bin"u8.ToArray();

        byte[] composite = await signer.SignAsync(message);

        Assert.True(pub.Verify(message, composite));
        Assert.Equal(HssParameters.Small.MaxSignatures - 1, signer.SignaturesRemaining);
    }

    [Fact]
    public async Task TamperedMessage_Fails()
    {
        var (signer, pub) = await NewSignerAsync();
        byte[] message = "good"u8.ToArray();
        byte[] composite = await signer.SignAsync(message);

        Assert.False(pub.Verify("evil"u8.ToArray(), composite));
    }

    [Fact]
    public async Task WrongMlDsaKey_Fails_EvenThoughHssLegIsValid()
    {
        var (signer, pub) = await NewSignerAsync();
        byte[] message = "msg"u8.ToArray();
        byte[] composite = await signer.SignAsync(message);

        // Swap in a DIFFERENT ML-DSA public key: the HSS leg still verifies but the composite must not.
        var attackerMlDsa = MlDsaKeyPair.Generate();
        var forgedBundle = new HybridPublicKey(pub.HssPublicKey, pub.MlDsaParameters, attackerMlDsa.PublicKey);

        Assert.False(forgedBundle.Verify(message, composite));

        // Sanity: the embedded HSS leg on its own IS valid (proves the failure is the ML-DSA leg).
        var (hssLeg, _) = HybridSignature.Decode(composite);
        Assert.True(HssSigner.Verify(pub.HssPublicKey, message, hssLeg));
    }

    [Fact]
    public async Task CorruptedHssLeg_Fails()
    {
        var (signer, pub) = await NewSignerAsync();
        byte[] message = "msg"u8.ToArray();
        byte[] composite = await signer.SignAsync(message);

        var (hssLeg, mlLeg) = HybridSignature.Decode(composite);
        hssLeg[100] ^= 0xFF; // flip a byte inside the HSS signature
        byte[] tampered = HybridSignature.Encode(hssLeg, mlLeg);

        Assert.False(pub.Verify(message, tampered));
    }

    [Fact]
    public async Task CorruptedMlDsaLeg_Fails()
    {
        var (signer, pub) = await NewSignerAsync();
        byte[] message = "msg"u8.ToArray();
        byte[] composite = await signer.SignAsync(message);

        var (hssLeg, mlLeg) = HybridSignature.Decode(composite);
        mlLeg[10] ^= 0xFF;
        byte[] tampered = HybridSignature.Encode(hssLeg, mlLeg);

        Assert.False(pub.Verify(message, tampered));
    }

    [Fact]
    public async Task HybridPublicKey_RoundTrips_AndStillVerifies()
    {
        var (signer, pub) = await NewSignerAsync();
        byte[] message = "roundtrip"u8.ToArray();
        byte[] composite = await signer.SignAsync(message);

        byte[] encoded = pub.Encode();
        HybridPublicKey decoded = HybridPublicKey.Decode(encoded);

        Assert.Equal(pub.HssPublicKey, decoded.HssPublicKey);
        Assert.Equal(pub.MlDsaPublicKey, decoded.MlDsaPublicKey);
        Assert.True(decoded.Verify(message, composite));
    }

    [Fact]
    public void MalformedComposite_VerifyReturnsFalse_DoesNotThrow()
    {
        var pub = new HybridPublicKey(new byte[60], MLDsaParameters.ml_dsa_65, new byte[1952]);
        Assert.False(pub.Verify("m"u8.ToArray(), new byte[] { 0, 0, 0, 5 })); // truncated composite
        Assert.False(pub.Verify("m"u8.ToArray(), Array.Empty<byte>()));
    }

    [Fact]
    public void MlDsaKeyPair_ExportImport_RoundTrips()
    {
        var kp = MlDsaKeyPair.Generate(MLDsaParameters.ml_dsa_65);
        byte[] priv = kp.ExportPrivateKey();
        var reimported = MlDsaKeyPair.ImportPrivateKey(MLDsaParameters.ml_dsa_65, priv);

        byte[] message = "x"u8.ToArray();
        byte[] sig = reimported.CreateSigner().Sign(message);
        Assert.True(kp.CreateVerifier().Verify(message, sig));
        Assert.Equal(kp.PublicKey, reimported.PublicKey);
    }
}
