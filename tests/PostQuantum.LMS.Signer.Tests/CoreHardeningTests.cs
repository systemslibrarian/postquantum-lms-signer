using PostQuantum.Lms;
using PostQuantum.Lms.Internal;
using PostQuantum.Lms.State;
using Org.BouncyCastle.Security;
using Bc = Org.BouncyCastle.Pqc.Crypto.Lms;

namespace PostQuantum.Lms.Tests;

/// <summary>
/// Locks down the core: every registered parameter set's constants are validated against RFC 8554,
/// and the dangerous edge cases (multi-level HSS, repeated re-keying, exact-boundary exhaustion,
/// concurrent compare-and-swap, crash-safety artifacts) are exercised directly.
/// </summary>
public sealed class CoreHardeningTests
{
    // ---- Parameter table correctness (RFC 8554 Tables 1 & 2) ----

    [Theory]
    [InlineData(LmOtsAlgorithm.Sha256N32W1, 1, 265, 7)]
    [InlineData(LmOtsAlgorithm.Sha256N32W2, 2, 133, 6)]
    [InlineData(LmOtsAlgorithm.Sha256N32W4, 4, 67, 4)]
    [InlineData(LmOtsAlgorithm.Sha256N32W8, 8, 34, 0)]
    public void LmOtsParams_MatchRfc8554Table1(LmOtsAlgorithm alg, int w, int p, int ls)
    {
        var resolved = LmOtsParams.Resolve(alg);
        Assert.Equal(32, resolved.N);
        Assert.Equal(w, resolved.W);
        Assert.Equal(p, resolved.P);
        Assert.Equal(ls, resolved.Ls);
        // Signature length = u32(type) + C + p*n.
        Assert.Equal(4 + 32 + (32 * p), resolved.SignatureLength);
    }

    [Theory]
    [InlineData(LmsAlgorithm.Sha256M32H5, 5)]
    [InlineData(LmsAlgorithm.Sha256M32H10, 10)]
    [InlineData(LmsAlgorithm.Sha256M32H15, 15)]
    [InlineData(LmsAlgorithm.Sha256M32H20, 20)]
    [InlineData(LmsAlgorithm.Sha256M32H25, 25)]
    public void LmsParams_MatchRfc8554Table2(LmsAlgorithm alg, int h)
    {
        var resolved = LmsParams.Resolve(alg);
        Assert.Equal(32, resolved.M);
        Assert.Equal(h, resolved.H);
        Assert.Equal(1L << h, resolved.LeafCount);
    }

    [Fact]
    public void PublicSignatureLengths_AreSelfConsistent()
    {
        // Every (height × width) combination's reported sizes must match the wire math.
        foreach (LmsAlgorithm lms in Enum.GetValues<LmsAlgorithm>())
        {
            foreach (LmOtsAlgorithm ots in Enum.GetValues<LmOtsAlgorithm>())
            {
                var p = new LmsParameters(lms, ots);
                int h = LmsParams.Resolve(lms).H;
                int otsSig = LmOtsParams.Resolve(ots).SignatureLength;
                Assert.Equal(4 + otsSig + 4 + (h * 32), p.SignatureLength);
                Assert.Equal(8 + 16 + 32, p.PublicKeyLength);
                Assert.Equal(1L << h, p.MaxSignatures);
            }
        }
    }

    // ---- HSS depth & re-keying ----

    [Fact]
    public async Task Hss_ThreeLevels_RoundTripsAndInteropsWithBouncyCastle()
    {
        var parameters = new HssParameters(LmsParameters.H5W8, LmsParameters.H5W8, LmsParameters.H5W8);
        using var signer = await HssSigner.CreateAsync(parameters, new InMemoryStateStore(), "k");
        byte[] pub = signer.PublicKey();
        Assert.Equal(32L * 32 * 32, signer.MaxSignatures);

        byte[] msg = "three-level-firmware"u8.ToArray();
        byte[] sig = await signer.SignAsync(msg);

        Assert.True(HssSigner.Verify(pub, msg, sig));

        // Independent oracle: BouncyCastle must accept our 3-level HSS signature.
        var bcPub = Bc.HssPublicKeyParameters.GetInstance(pub);
        var bcSig = Bc.HssSignature.GetInstance(sig, parameters.LevelCount);
        Assert.True(Bc.Hss.VerifySignature(bcPub, bcSig, msg));
    }

    [Fact]
    public async Task Hss_CrossesMultipleSubtreeBoundaries()
    {
        // Small = h5/h5 → bottom subtree holds 32. Signing 70 forces TWO re-keys (at 32 and 64).
        using var signer = await HssSigner.CreateAsync(HssParameters.Small, new InMemoryStateStore(), "k");
        byte[] pub = signer.PublicKey();

        for (int i = 0; i < 70; i++)
        {
            byte[] msg = System.Text.Encoding.UTF8.GetBytes($"m{i}");
            byte[] sig = await signer.SignAsync(msg);
            Assert.True(HssSigner.Verify(pub, msg, sig), $"verify failed at signature {i}");
        }

        Assert.Equal(HssParameters.Small.MaxSignatures - 70, signer.SignaturesRemaining);
    }

    [Fact]
    public async Task Hss_SingleLevel_ExhaustsExactlyAtCapacity()
    {
        var parameters = new HssParameters(LmsParameters.H5W8); // L=1, capacity 32, cannot re-key.
        using var signer = await HssSigner.CreateAsync(parameters, new InMemoryStateStore(), "k");
        Assert.Equal(32, signer.MaxSignatures);

        for (int i = 0; i < 32; i++)
        {
            await signer.SignAsync(System.Text.Encoding.UTF8.GetBytes($"m{i}"));
        }

        Assert.Equal(0, signer.SignaturesRemaining);
        await Assert.ThrowsAsync<LmsKeyExhaustedException>(
            async () => await signer.SignAsync("overflow"u8.ToArray()));
    }

    // ---- State safety under stress ----

    [Fact]
    public async Task Cas_OnlyOneOfManyConcurrentSignersWins()
    {
        var store = new InMemoryStateStore();
        using (await HssSigner.CreateAsync(HssParameters.Small, store, "shared")) { }

        // Five signers all loaded at the same version; exactly one may advance the store.
        var signers = new List<HssSigner>();
        for (int i = 0; i < 5; i++)
        {
            signers.Add(await HssSigner.LoadAsync(store, "shared"));
        }

        int succeeded = 0;
        int rejected = 0;
        foreach (var s in signers)
        {
            try
            {
                await s.SignAsync("x"u8.ToArray());
                succeeded++;
            }
            catch (LmsStateException)
            {
                rejected++;
            }
            finally
            {
                s.Dispose();
            }
        }

        Assert.Equal(1, succeeded);
        Assert.Equal(4, rejected);
    }

    [Fact]
    public async Task FileStore_WritesBackupAfterUpdate()
    {
        string dir = Path.Combine(Path.GetTempPath(), "lms-bak-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new FileStateStore(dir);
            using var signer = await HssSigner.CreateAsync(HssParameters.Small, store, "fw");
            await signer.SignAsync("a"u8.ToArray()); // version 1 -> 2 keeps a .bak of v1
            await signer.SignAsync("b"u8.ToArray()); // version 2 -> 3

            Assert.Single(Directory.GetFiles(dir, "*.lms.state"));
            Assert.Single(Directory.GetFiles(dir, "*.lms.state.bak"));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task SignaturesRemaining_DecrementsMonotonically()
    {
        using var signer = await HssSigner.CreateAsync(HssParameters.Small, new InMemoryStateStore(), "k");
        long previous = signer.SignaturesRemaining;
        for (int i = 0; i < 40; i++)
        {
            await signer.SignAsync(System.Text.Encoding.UTF8.GetBytes($"m{i}"));
            Assert.Equal(previous - 1, signer.SignaturesRemaining);
            previous = signer.SignaturesRemaining;
        }
    }
}
