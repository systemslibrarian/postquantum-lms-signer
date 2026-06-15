using System.Security.Cryptography;
using PostQuantum.Lms;
using PostQuantum.Lms.Internal;
using Bc = Org.BouncyCastle.Pqc.Crypto.Lms;

namespace PostQuantum.Lms.Tests;

/// <summary>
/// Validates the SP 800-208 parameter sets beyond the RFC 8554 SHA-256/n32 family — namely the
/// truncated SHA-256/192 (n=24) and SHAKE256 (n=32/n=24) sets — against BouncyCastle: byte-for-byte
/// public keys plus bidirectional signature interop. Also pins the n=24 LM-OTS table constants.
/// </summary>
public sealed class Sp800208ParameterSetTests
{
    public static TheoryData<LmsAlgorithm, LmOtsAlgorithm> Sets() => new()
    {
        { LmsAlgorithm.Sha256M24H5, LmOtsAlgorithm.Sha256N24W8 },
        { LmsAlgorithm.Sha256M24H5, LmOtsAlgorithm.Sha256N24W4 },
        { LmsAlgorithm.Sha256M24H5, LmOtsAlgorithm.Sha256N24W1 },
        { LmsAlgorithm.Shake256M32H5, LmOtsAlgorithm.Shake256N32W8 },
        { LmsAlgorithm.Shake256M32H5, LmOtsAlgorithm.Shake256N32W2 },
        { LmsAlgorithm.Shake256M24H5, LmOtsAlgorithm.Shake256N24W8 },
    };

    private static Bc.LMSigParameters BcSig(LmsAlgorithm a) => a switch
    {
        LmsAlgorithm.Sha256M24H5 => Bc.LMSigParameters.lms_sha256_n24_h5,
        LmsAlgorithm.Shake256M32H5 => Bc.LMSigParameters.lms_shake256_n32_h5,
        LmsAlgorithm.Shake256M24H5 => Bc.LMSigParameters.lms_shake256_n24_h5,
        _ => throw new ArgumentOutOfRangeException(nameof(a)),
    };

    private static Bc.LMOtsParameters BcOts(LmOtsAlgorithm a) => a switch
    {
        LmOtsAlgorithm.Sha256N24W1 => Bc.LMOtsParameters.sha256_n24_w1,
        LmOtsAlgorithm.Sha256N24W4 => Bc.LMOtsParameters.sha256_n24_w4,
        LmOtsAlgorithm.Sha256N24W8 => Bc.LMOtsParameters.sha256_n24_w8,
        LmOtsAlgorithm.Shake256N32W2 => Bc.LMOtsParameters.shake256_n32_w2,
        LmOtsAlgorithm.Shake256N32W8 => Bc.LMOtsParameters.shake256_n32_w8,
        LmOtsAlgorithm.Shake256N24W8 => Bc.LMOtsParameters.shake256_n24_w8,
        _ => throw new ArgumentOutOfRangeException(nameof(a)),
    };

    [Theory]
    [MemberData(nameof(Sets))]
    public void PublicKey_MatchesBouncyCastle(LmsAlgorithm lmsAlg, LmOtsAlgorithm otsAlg)
    {
        int n = lmsAlg.ToString().Contains("M24") ? 24 : 32;
        byte[] id = RandomNumberGenerator.GetBytes(16);
        byte[] seed = RandomNumberGenerator.GetBytes(n);

        var ours = LmsTree.Build(lmsAlg, otsAlg, id, seed);
        var bc = Bc.Lms.GenerateKeys(BcSig(lmsAlg), BcOts(otsAlg), 0, id, seed);

        Assert.Equal(bc.GetPublicKey().GetEncoded(), ours.PublicKey());
    }

    [Theory]
    [MemberData(nameof(Sets))]
    public void Signatures_Interop_BothDirections(LmsAlgorithm lmsAlg, LmOtsAlgorithm otsAlg)
    {
        int n = lmsAlg.ToString().Contains("M24") ? 24 : 32;
        byte[] id = RandomNumberGenerator.GetBytes(16);
        byte[] seed = RandomNumberGenerator.GetBytes(n);
        byte[] message = "sp800-208-interop"u8.ToArray();

        // Ours -> BouncyCastle
        var ours = LmsTree.Build(lmsAlg, otsAlg, id, seed);
        byte[] sig = ours.Sign(0, message, RandomNumberGenerator.GetBytes(n));
        var bcPub = Bc.LmsPublicKeyParameters.GetInstance(ours.PublicKey());
        Assert.True(Bc.Lms.VerifySignature(bcPub, sig, message), "BC rejected our signature.");

        // BouncyCastle -> ours
        var bcPriv = Bc.Lms.GenerateKeys(BcSig(lmsAlg), BcOts(otsAlg), 0, id, seed);
        byte[] bcSig = Bc.Lms.GenerateSign(bcPriv, message).GetEncoded();
        Assert.True(LmsTree.Verify(bcPriv.GetPublicKey().GetEncoded(), message, bcSig), "We rejected a BC signature.");
    }

    [Theory]
    [InlineData(LmOtsAlgorithm.Sha256N24W1, 1, 200, 8)]
    [InlineData(LmOtsAlgorithm.Sha256N24W2, 2, 101, 6)]
    [InlineData(LmOtsAlgorithm.Sha256N24W4, 4, 51, 4)]
    [InlineData(LmOtsAlgorithm.Sha256N24W8, 8, 26, 0)]
    public void N24_LmOtsTable_MatchesSp800208(LmOtsAlgorithm alg, int w, int p, int ls)
    {
        var r = LmOtsParams.Resolve(alg);
        Assert.Equal(24, r.N);
        Assert.Equal(w, r.W);
        Assert.Equal(p, r.P);
        Assert.Equal(ls, r.Ls);
    }

    [Fact]
    public async Task HssSigner_WorksWithShakeAndN24()
    {
        // End-to-end through the public signer with non-default hash families.
        var shakeParams = new HssParameters(
            new LmsParameters(LmsAlgorithm.Shake256M32H5, LmOtsAlgorithm.Shake256N32W8));
        using var signer = await HssSigner.CreateAsync(shakeParams, new State.InMemoryStateStore(), "k");
        byte[] msg = "shake-firmware"u8.ToArray();
        byte[] sig = await signer.SignAsync(msg);
        Assert.True(HssSigner.Verify(signer.PublicKey(), msg, sig));
    }
}
