using PostQuantum.Lms;
using PostQuantum.Lms.Sqlite;
using PostQuantum.Lms.Testing;

namespace PostQuantum.Lms.Tests;

public sealed class SqliteStateStoreTests : IDisposable
{
    private readonly string _dir;
    private readonly string _connectionString;

    public SqliteStateStoreTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "lms-sqlite-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _connectionString = $"Data Source={Path.Combine(_dir, "state.db")}";
    }

    [Fact]
    public async Task ConformsToStateStoreContract()
    {
        using var store = new SqliteStateStore(_connectionString);
        await StateStoreConformance.AssertConformsAsync(store);
    }

    [Fact]
    public async Task PreventsReuse()
    {
        using var store = new SqliteStateStore(_connectionString);
        await StateStoreConformance.AssertPreventsReuseAsync(store);
    }

    [Fact]
    public async Task BacksHssSigner_AcrossReload()
    {
        byte[] pub;
        var sigs = new List<byte[]>();

        using (var store = new SqliteStateStore(_connectionString))
        using (var signer = await HssSigner.CreateAsync(HssParameters.Small, store, "fw"))
        {
            pub = signer.PublicKey();
            for (int i = 0; i < 5; i++)
            {
                sigs.Add(await signer.SignAsync(System.Text.Encoding.UTF8.GetBytes($"m{i}")));
            }
        }

        // Reopen the database and continue — the index must not restart.
        using (var store = new SqliteStateStore(_connectionString))
        using (var reloaded = await HssSigner.LoadAsync(store, "fw"))
        {
            Assert.Equal(HssParameters.Small.MaxSignatures - 5, reloaded.SignaturesRemaining);
            sigs.Add(await reloaded.SignAsync("m5"u8.ToArray()));
        }

        for (int i = 0; i < sigs.Count; i++)
        {
            Assert.True(HssSigner.Verify(pub, System.Text.Encoding.UTF8.GetBytes($"m{i}"), sigs[i]));
        }
    }

    [Fact]
    public void RejectsUnsafeTableName()
        => Assert.Throws<ArgumentException>(() => new SqliteStateStore(_connectionString, "bad; DROP TABLE x"));

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { /* best effort */ }
    }
}
