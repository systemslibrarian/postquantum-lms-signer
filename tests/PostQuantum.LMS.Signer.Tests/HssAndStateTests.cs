using System.Security.Cryptography;
using PostQuantum.Lms;
using PostQuantum.Lms.State;
using Org.BouncyCastle.Security;
using Bc = Org.BouncyCastle.Pqc.Crypto.Lms;

namespace PostQuantum.Lms.Tests;

public sealed class HssAndStateTests
{
    private static string Msg(int i) => $"firmware-blob-{i}";

    [Fact]
    public async Task Hss_RoundTrip_AcrossSubtreeBoundary_ForcesRekey()
    {
        // Small = h5/h5: each bottom subtree holds 32 signatures, so crossing index 32 forces a re-key.
        using var signer = await HssSigner.CreateAsync(HssParameters.Small, new InMemoryStateStore(), "k");
        byte[] pub = signer.PublicKey();

        var signatures = new List<(byte[] msg, byte[] sig)>();
        for (int i = 0; i < 40; i++)
        {
            byte[] message = System.Text.Encoding.UTF8.GetBytes(Msg(i));
            signatures.Add((message, await signer.SignAsync(message)));
        }

        Assert.Equal(HssParameters.Small.MaxSignatures - 40, signer.SignaturesRemaining);
        foreach (var (message, sig) in signatures)
        {
            Assert.True(HssSigner.Verify(pub, message, sig), "A signature spanning the re-key boundary failed to verify.");
        }
    }

    [Fact]
    public async Task Hss_OurSignature_VerifiesUnderBouncyCastle()
    {
        using var signer = await HssSigner.CreateAsync(HssParameters.Small, new InMemoryStateStore(), "k");
        byte[] pub = signer.PublicKey();
        byte[] message = "cnsa-2.0-firmware"u8.ToArray();
        byte[] sig = await signer.SignAsync(message);

        var bcPub = Bc.HssPublicKeyParameters.GetInstance(pub);
        var bcSig = Bc.HssSignature.GetInstance(sig, HssParameters.Small.LevelCount);
        Assert.True(Bc.Hss.VerifySignature(bcPub, bcSig, message), "BouncyCastle rejected our HSS signature.");
    }

    [Fact]
    public async Task Hss_BouncyCastleSignature_VerifiesUnderOurs()
    {
        var bcParams = new[]
        {
            new Bc.LmsParameters(Bc.LMSigParameters.lms_sha256_n32_h5, Bc.LMOtsParameters.sha256_n32_w8),
            new Bc.LmsParameters(Bc.LMSigParameters.lms_sha256_n32_h5, Bc.LMOtsParameters.sha256_n32_w8),
        };
        var bcPriv = Bc.Hss.GenerateHssKeyPair(new Bc.HssKeyGenerationParameters(bcParams, new SecureRandom()));
        byte[] message = "interop-message"u8.ToArray();

        byte[] bcSig = Bc.Hss.GenerateSignature(bcPriv, message).GetEncoded();
        byte[] bcPub = bcPriv.GetPublicKey().GetEncoded();

        Assert.True(HssSigner.Verify(bcPub, message, bcSig), "We rejected a valid BouncyCastle HSS signature.");

        byte[] tampered = (byte[])message.Clone();
        tampered[0] ^= 0xFF;
        Assert.False(HssSigner.Verify(bcPub, tampered, bcSig));
    }

    [Fact]
    public async Task State_SurvivesDisposeAndReload_NoIndexReuse()
    {
        string dir = Path.Combine(Path.GetTempPath(), "lms-test-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new FileStateStore(dir);
            byte[] pub;
            var leaves = new List<byte[]>();

            using (var signer = await HssSigner.CreateAsync(HssParameters.Small, store, "fw"))
            {
                pub = signer.PublicKey();
                for (int i = 0; i < 5; i++)
                {
                    leaves.Add(await signer.SignAsync(System.Text.Encoding.UTF8.GetBytes(Msg(i))));
                }
            }

            // Reload from disk and continue — must not restart the index.
            using (var reloaded = await HssSigner.LoadAsync(store, "fw"))
            {
                Assert.Equal(HssParameters.Small.MaxSignatures - 5, reloaded.SignaturesRemaining);
                for (int i = 5; i < 10; i++)
                {
                    leaves.Add(await reloaded.SignAsync(System.Text.Encoding.UTF8.GetBytes(Msg(i))));
                }
            }

            for (int i = 0; i < 10; i++)
            {
                Assert.True(HssSigner.Verify(pub, System.Text.Encoding.UTF8.GetBytes(Msg(i)), leaves[i]));
            }
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task ReuseAttack_ConcurrentClonedSigners_AreRejectedByCas()
    {
        // THE headline guard. Two signers loaded from the same persisted state simulate a cloned key
        // or two processes sharing one key. Whoever advances the store first wins; the other is refused
        // by the compare-and-swap check rather than silently reusing the same one-time-key index.
        var store = new InMemoryStateStore();
        using var seed = await HssSigner.CreateAsync(HssParameters.Small, store, "shared");

        using var a = await HssSigner.LoadAsync(store, "shared");
        using var b = await HssSigner.LoadAsync(store, "shared");

        byte[] sigA = await a.SignAsync("legit"u8.ToArray());   // advances store version
        var reuse = await Assert.ThrowsAsync<LmsStateException>(
            async () => await b.SignAsync("attacker"u8.ToArray()));

        Assert.Contains("Concurrent state modification", reuse.Message);
        Assert.True(HssSigner.Verify(seed.PublicKey(), "legit"u8.ToArray(), sigA));
    }

    [Fact]
    public async Task FileStore_DetectsTamperedState()
    {
        string dir = Path.Combine(Path.GetTempPath(), "lms-tamper-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new FileStateStore(dir);
            using (await HssSigner.CreateAsync(HssParameters.Small, store, "fw")) { }

            string file = Directory.GetFiles(dir, "*.lms.state").Single();
            byte[] bytes = await File.ReadAllBytesAsync(file);
            bytes[^1] ^= 0xFF; // corrupt the integrity tag
            await File.WriteAllBytesAsync(file, bytes);

            await Assert.ThrowsAsync<LmsStateException>(async () => await HssSigner.LoadAsync(store, "fw"));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task LmsSigner_Exhaustion_Throws()
    {
        using var signer = await LmsSigner.CreateAsync(LmsParameters.H5W8, new InMemoryStateStore(), "k");
        byte[] pub = signer.PublicKey();
        Assert.Equal(32, signer.MaxSignatures);

        for (int i = 0; i < 32; i++)
        {
            byte[] sig = await signer.SignAsync(System.Text.Encoding.UTF8.GetBytes(Msg(i)));
            Assert.True(LmsSigner.Verify(pub, System.Text.Encoding.UTF8.GetBytes(Msg(i)), sig));
        }

        Assert.Equal(0, signer.SignaturesRemaining);
        await Assert.ThrowsAsync<LmsKeyExhaustedException>(async () => await signer.SignAsync("one too many"u8.ToArray()));
    }

    [Fact]
    public async Task Create_RefusesToOverwriteExistingKey()
    {
        var store = new InMemoryStateStore();
        using (await HssSigner.CreateAsync(HssParameters.Small, store, "fw")) { }
        await Assert.ThrowsAsync<LmsStateException>(
            async () => await HssSigner.CreateAsync(HssParameters.Small, store, "fw"));
    }
}
