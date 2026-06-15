using System.Data;
using Microsoft.Data.Sqlite;
using PostQuantum.Lms.State;

namespace PostQuantum.Lms.Sqlite;

/// <summary>
/// A SQLite-backed <see cref="IStateStore"/> with crash-safe, compare-and-swap semantics — a reference
/// relational backend for single-host (multi-process) signing, and a template for any SQL database.
/// </summary>
/// <remarks>
/// <para>State lives in one table: <c>(key_id TEXT PRIMARY KEY, version INTEGER, data BLOB)</c>. Each save
/// runs in a <c>BEGIN IMMEDIATE</c> transaction (serializing writers via SQLite's file lock) and advances
/// the row only when the stored version matches <c>expectedVersion</c> — a conditional <c>UPDATE … WHERE
/// version = @expected</c> whose affected-row count is the compare-and-swap result. A losing writer is
/// rejected with <see cref="LmsStateException"/> rather than allowed to reuse a one-time-key index.</para>
/// <para><b>Porting:</b> the exact same pattern works on PostgreSQL or SQL Server — swap the provider and
/// keep the conditional-UPDATE/affected-rows CAS. For genuinely multi-host deployments, prefer a server
/// database (or an HSM/hardware counter) over a SQLite file on a network share.</para>
/// <para>Always validate a custom store with <c>StateStoreConformance</c> from the Testing package before
/// trusting a production key to it.</para>
/// </remarks>
public sealed class SqliteStateStore : IStateStore, IDisposable
{
    private readonly string _connectionString;
    private readonly string _table;
    private readonly SemaphoreSlim _initGate = new(1, 1);
    private bool _initialized;

    /// <summary>Creates a store over the given SQLite connection string and table name.</summary>
    /// <param name="connectionString">e.g. <c>Data Source=/var/lib/lms/signer.db</c>.</param>
    /// <param name="tableName">Table to store state in. Must be a simple identifier ([A-Za-z0-9_]).</param>
    public SqliteStateStore(string connectionString, string tableName = "lms_signer_state")
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        ArgumentException.ThrowIfNullOrWhiteSpace(tableName);
        if (!IsSafeIdentifier(tableName))
        {
            throw new ArgumentException("Table name must contain only letters, digits, and underscores.", nameof(tableName));
        }

        _connectionString = connectionString;
        _table = tableName;
    }

    /// <inheritdoc />
    public async ValueTask<LoadedState?> LoadAsync(string keyId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(keyId);
        await EnsureInitializedAsync(cancellationToken).ConfigureAwait(false);

        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);

        await using var command = connection.CreateCommand();
        command.CommandText = $"SELECT version, data FROM {_table} WHERE key_id = $k;";
        command.Parameters.AddWithValue("$k", keyId);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        long version = reader.GetInt64(0);
        byte[] data = (byte[])reader.GetValue(1);
        return new LoadedState(data, version);
    }

    /// <inheritdoc />
    public async ValueTask<long> SaveAsync(string keyId, ReadOnlyMemory<byte> data, long expectedVersion, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(keyId);
        await EnsureInitializedAsync(cancellationToken).ConfigureAwait(false);

        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);

        // BEGIN IMMEDIATE takes the write lock up front so concurrent savers serialize rather than race.
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(
            IsolationLevel.Serializable, cancellationToken).ConfigureAwait(false);

        long newVersion = expectedVersion + 1;
        byte[] bytes = data.ToArray();

        if (expectedVersion == 0)
        {
            await using var insert = connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText = $"INSERT INTO {_table} (key_id, version, data) VALUES ($k, 1, $d);";
            insert.Parameters.AddWithValue("$k", keyId);
            insert.Parameters.AddWithValue("$d", bytes);
            try
            {
                await insert.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (SqliteException ex) when (ex.SqliteErrorCode == 19) // SQLITE_CONSTRAINT (key already exists)
            {
                throw Concurrency(keyId, expectedVersion);
            }
        }
        else
        {
            await using var update = connection.CreateCommand();
            update.Transaction = transaction;
            update.CommandText =
                $"UPDATE {_table} SET version = $nv, data = $d WHERE key_id = $k AND version = $ev;";
            update.Parameters.AddWithValue("$nv", newVersion);
            update.Parameters.AddWithValue("$d", bytes);
            update.Parameters.AddWithValue("$k", keyId);
            update.Parameters.AddWithValue("$ev", expectedVersion);

            int affected = await update.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            if (affected == 0)
            {
                throw Concurrency(keyId, expectedVersion);
            }
        }

        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return newVersion;
    }

    private async Task EnsureInitializedAsync(CancellationToken cancellationToken)
    {
        if (_initialized)
        {
            return;
        }

        await _initGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_initialized)
            {
                return;
            }

            EnsureDataDirectoryExists();

            await using var connection = new SqliteConnection(_connectionString);
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await using var command = connection.CreateCommand();
            command.CommandText =
                $"CREATE TABLE IF NOT EXISTS {_table} (" +
                "key_id TEXT PRIMARY KEY, version INTEGER NOT NULL, data BLOB NOT NULL);";
            await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            _initialized = true;
        }
        finally
        {
            _initGate.Release();
        }
    }

    private void EnsureDataDirectoryExists()
    {
        string source = new SqliteConnectionStringBuilder(_connectionString).DataSource;
        if (string.IsNullOrEmpty(source) || source.Equals(":memory:", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        string? directory = Path.GetDirectoryName(Path.GetFullPath(source));
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }
    }

    private static bool IsSafeIdentifier(string value)
    {
        foreach (char c in value)
        {
            if (!char.IsLetterOrDigit(c) && c != '_')
            {
                return false;
            }
        }

        return value.Length > 0;
    }

    private static LmsStateException Concurrency(string keyId, long expectedVersion)
        => new($"Concurrent state modification on key '{keyId}' (expected version {expectedVersion}); " +
               "aborting to prevent one-time-key reuse.");

    /// <summary>Releases the internal initialization lock.</summary>
    public void Dispose()
    {
        _initGate.Wait();
        try { }
        finally
        {
            _initGate.Release();
            _initGate.Dispose();
        }
    }
}
