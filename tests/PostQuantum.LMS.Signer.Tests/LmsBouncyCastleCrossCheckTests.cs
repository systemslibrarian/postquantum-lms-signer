using System.Security.Cryptography;
using PostQuantum.Lms;
using PostQuantum.Lms.Internal;
using Bc = Org.BouncyCastle.Pqc.Crypto.Lms;

namespace PostQuantum.Lms.Tests;

/// <summary>
/// Cross-checks our pure-managed LMS implementation against BouncyCastle, an independent
/// RFC 8554 implementation. Because BouncyCastle exposes seed-based key generation
/// (<c>Lms.GenerateKeys(sig, ots, q, I, rootSeed)</c>) using the same Appendix A derivation,
/// we can assert public keys match <b>byte-for-byte</b> and that signatures interoperate in both
/// directions. This is the primary correctness oracle for the core.
/// </summary>
public sealed class LmsBouncyCastleCrossCheckTests
{
    public static TheoryData<LmsAlgorithm, LmOtsAlgorithm> Combinations()
    {
        var data = new TheoryData<LmsAlgorithm, LmOtsAlgorithm>();
        foreach (var lms in new[] { LmsAlgorithm.Sha256M32H5, LmsAlgorithm.Sha256M32H10 })
        {
            foreach (var ots in new[]
            {
                LmOtsAlgorithm.Sha256N32W1, LmOtsAlgorithm.Sha256N32W2,
                LmOtsAlgorithm.Sha256N32W4, LmOtsAlgorithm.Sha256N32W8,
            })
            {
                data.Add(lms, ots);
            }
        }

        return data;
    }

    private static Bc.LMSigParameters BcSig(LmsAlgorithm a) => a switch
    {
        LmsAlgorithm.Sha256M32H5 => Bc.LMSigParameters.lms_sha256_n32_h5,
        LmsAlgorithm.Sha256M32H10 => Bc.LMSigParameters.lms_sha256_n32_h10,
        LmsAlgorithm.Sha256M32H15 => Bc.LMSigParameters.lms_sha256_n32_h15,
        _ => throw new ArgumentOutOfRangeException(nameof(a)),
    };

    private static Bc.LMOtsParameters BcOts(LmOtsAlgorithm a) => a switch
    {
        LmOtsAlgorithm.Sha256N32W1 => Bc.LMOtsParameters.sha256_n32_w1,
        LmOtsAlgorithm.Sha256N32W2 => Bc.LMOtsParameters.sha256_n32_w2,
        LmOtsAlgorithm.Sha256N32W4 => Bc.LMOtsParameters.sha256_n32_w4,
        LmOtsAlgorithm.Sha256N32W8 => Bc.LMOtsParameters.sha256_n32_w8,
        _ => throw new ArgumentOutOfRangeException(nameof(a)),
    };

    [Theory]
    [MemberData(nameof(Combinations))]
    public void PublicKey_MatchesBouncyCastle_ByteForByte(LmsAlgorithm lmsAlg, LmOtsAlgorithm otsAlg)
    {
        byte[] identifier = RandomNumberGenerator.GetBytes(16);
        byte[] seed = RandomNumberGenerator.GetBytes(32);

        var ours = LmsTree.Build(lmsAlg, otsAlg, identifier, seed);
        var bcPriv = Bc.Lms.GenerateKeys(BcSig(lmsAlg), BcOts(otsAlg), 0, identifier, seed);

        Assert.Equal(bcPriv.GetPublicKey().GetEncoded(), ours.PublicKey());
    }

    [Theory]
    [MemberData(nameof(Combinations))]
    public void OurSignature_VerifiesUnderBouncyCastle(LmsAlgorithm lmsAlg, LmOtsAlgorithm otsAlg)
    {
        byte[] identifier = RandomNumberGenerator.GetBytes(16);
        byte[] seed = RandomNumberGenerator.GetBytes(32);
        byte[] message = "firmware-image-v1.2.3"u8.ToArray();
        byte[] randomizer = RandomNumberGenerator.GetBytes(32);

        var ours = LmsTree.Build(lmsAlg, otsAlg, identifier, seed);
        byte[] sig = ours.Sign(0, message, randomizer);
        byte[] pub = ours.PublicKey();

        var bcPub = Bc.LmsPublicKeyParameters.GetInstance(pub);
        Assert.True(Bc.Lms.VerifySignature(bcPub, sig, message), "BouncyCastle rejected our signature.");

        // Negative control: a tampered message must fail.
        message[0] ^= 0xFF;
        Assert.False(Bc.Lms.VerifySignature(bcPub, sig, message));
    }

    [Theory]
    [MemberData(nameof(Combinations))]
    public void BouncyCastleSignature_VerifiesUnderOurs(LmsAlgorithm lmsAlg, LmOtsAlgorithm otsAlg)
    {
        byte[] identifier = RandomNumberGenerator.GetBytes(16);
        byte[] seed = RandomNumberGenerator.GetBytes(32);
        byte[] message = "secure-boot-payload"u8.ToArray();

        var bcPriv = Bc.Lms.GenerateKeys(BcSig(lmsAlg), BcOts(otsAlg), 0, identifier, seed);
        byte[] bcSig = Bc.Lms.GenerateSign(bcPriv, message).GetEncoded();
        byte[] bcPub = bcPriv.GetPublicKey().GetEncoded();

        Assert.True(LmsTree.Verify(bcPub, message, bcSig), "We rejected a valid BouncyCastle signature.");

        byte[] tampered = (byte[])message.Clone();
        tampered[^1] ^= 0xFF;
        Assert.False(LmsTree.Verify(bcPub, tampered, bcSig));
    }

    [Theory]
    [MemberData(nameof(Combinations))]
    public void RoundTrip_AcrossSeveralLeaves(LmsAlgorithm lmsAlg, LmOtsAlgorithm otsAlg)
    {
        byte[] identifier = RandomNumberGenerator.GetBytes(16);
        byte[] seed = RandomNumberGenerator.GetBytes(32);
        var tree = LmsTree.Build(lmsAlg, otsAlg, identifier, seed);
        byte[] pub = tree.PublicKey();

        for (uint q = 0; q < 8; q++)
        {
            byte[] message = System.Text.Encoding.UTF8.GetBytes($"message-{q}");
            byte[] sig = tree.Sign(q, message, RandomNumberGenerator.GetBytes(32));
            Assert.True(LmsTree.Verify(pub, message, sig), $"Self round-trip failed at leaf {q}.");
        }
    }
}
