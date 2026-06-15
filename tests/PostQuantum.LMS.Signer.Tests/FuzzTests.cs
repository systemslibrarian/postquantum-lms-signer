using PostQuantum.Lms;
using PostQuantum.Lms.Hybrid;
using PostQuantum.Lms.Internal;
using PostQuantum.Lms.State;

namespace PostQuantum.Lms.Tests;

/// <summary>
/// Negative-corpus / fuzz tests: hostile and malformed input must <b>fail closed</b> — verifiers
/// return <c>false</c> (never throw, never accept), and decoders throw only their documented exception
/// type (never an unhandled crash, OOM, or hang). Seeds are fixed for reproducibility.
/// </summary>
public sealed class FuzzTests
{
    private static byte[] RandomBytes(Random rng, int maxLen)
    {
        byte[] b = new byte[rng.Next(0, maxLen)];
        rng.NextBytes(b);
        return b;
    }

    [Fact]
    public void Verifiers_NeverThrow_OnArbitraryBytes()
    {
        var rng = new Random(0xC0FFEE);
        for (int i = 0; i < 5000; i++)
        {
            byte[] pub = RandomBytes(rng, 128);
            byte[] msg = RandomBytes(rng, 64);
            byte[] sig = RandomBytes(rng, 4096);

            // Must return a bool, never throw, never hang.
            _ = HssSigner.Verify(pub, msg, sig);
            _ = LmsSigner.Verify(pub, msg, sig);
        }
    }

    [Fact]
    public async Task MutatedValidSignature_AlwaysFailsClosed()
    {
        using var signer = await HssSigner.CreateAsync(HssParameters.Small, new InMemoryStateStore(), "k");
        byte[] pub = signer.PublicKey();
        byte[] message = "fuzz-base-message"u8.ToArray();
        byte[] valid = await signer.SignAsync(message);
        Assert.True(HssSigner.Verify(pub, message, valid));

        var rng = new Random(42);
        for (int i = 0; i < 3000; i++)
        {
            byte[] mutated = (byte[])valid.Clone();
            // Flip 1–3 random bytes.
            int flips = rng.Next(1, 4);
            for (int f = 0; f < flips; f++)
            {
                mutated[rng.Next(mutated.Length)] ^= (byte)(1 << rng.Next(8));
            }

            Assert.False(HssSigner.Verify(pub, message, mutated), "A mutated signature verified — fail-closed violated.");

            // Random truncation must also fail without throwing.
            int cut = rng.Next(0, valid.Length);
            Assert.False(HssSigner.Verify(pub, message, valid.AsSpan(0, cut).ToArray()));
        }

        // The original is still valid (we never mutated it in place).
        Assert.True(HssSigner.Verify(pub, message, valid));
    }

    [Fact]
    public void HssStateDeserialize_ThrowsOnlyLmsStateException_OnGarbage()
    {
        var rng = new Random(7);
        for (int i = 0; i < 5000; i++)
        {
            byte[] garbage = RandomBytes(rng, 256);
            try
            {
                _ = HssEngine.Deserialize(garbage);
                // Succeeding on random bytes is acceptable (it parsed something coherent);
                // what must never happen is an undocumented exception type.
            }
            catch (LmsStateException)
            {
                // expected for malformed state
            }
        }
    }

    [Fact]
    public void HybridDecoders_FailClosed_OnGarbage()
    {
        var rng = new Random(99);
        for (int i = 0; i < 5000; i++)
        {
            byte[] garbage = RandomBytes(rng, 512);

            // Composite decode: only ArgumentException, or a successful split.
            try { _ = HybridSignature.Decode(garbage); }
            catch (ArgumentException) { }

            // Public-key decode: only ArgumentException, or success.
            try { _ = HybridPublicKey.Decode(garbage); }
            catch (ArgumentException) { }
        }
    }

    [Fact]
    public async Task FileStore_RejectsRandomFileContents()
    {
        string dir = Path.Combine(Path.GetTempPath(), "lms-fuzz-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var store = new FileStateStore(dir);
            // Seed a real key so a state file exists with the right name, then corrupt it repeatedly.
            using (await HssSigner.CreateAsync(HssParameters.Small, store, "fw")) { }
            string file = Directory.GetFiles(dir, "*.lms.state").Single();

            var rng = new Random(123);
            for (int i = 0; i < 200; i++)
            {
                await File.WriteAllBytesAsync(file, RandomBytes(rng, 300));
                await Assert.ThrowsAsync<LmsStateException>(async () => await HssSigner.LoadAsync(store, "fw"));
            }
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}
