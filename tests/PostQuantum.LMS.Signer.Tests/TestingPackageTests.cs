using PostQuantum.Lms.State;
using PostQuantum.Lms.Testing;

namespace PostQuantum.Lms.Tests;

public sealed class TestingPackageTests
{
    [Fact]
    public void KnownAnswerVectors_AllPass()
    {
        // Pinned, BouncyCastle-cross-validated LMS vector. Guards the wire format against regressions.
        KnownAnswerVectors.AssertAll();
        Assert.NotEmpty(KnownAnswerVectors.All);
    }

    [Fact]
    public async Task InMemoryStore_ConformsToContract()
        => await StateStoreConformance.AssertConformsAsync(new InMemoryStateStore());

    [Fact]
    public async Task FileStore_ConformsToContract()
    {
        string dir = Path.Combine(Path.GetTempPath(), "lms-conf-" + Guid.NewGuid().ToString("N"));
        try
        {
            await StateStoreConformance.AssertConformsAsync(new FileStateStore(dir));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task BuiltInStores_PreventReuse()
    {
        await StateStoreConformance.AssertPreventsReuseAsync(new InMemoryStateStore());
    }
}
