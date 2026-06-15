using System.Collections.Concurrent;

namespace PostQuantum.Lms.State;

/// <summary>
/// A thread-safe, process-local <see cref="IStateStore"/>. Useful for tests and ephemeral signing,
/// but <b>NOT</b> crash-safe: state lives only in memory and is lost on process exit. Never use this
/// for a long-lived production key — a restart would reset the index and reuse one-time keys.
/// The Analyzers package flags this usage outside tests.
/// </summary>
public sealed class InMemoryStateStore : IStateStore
{
    private readonly ConcurrentDictionary<string, (byte[] Data, long Version)> _store = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public ValueTask<LoadedState?> LoadAsync(string keyId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(keyId);
        return _store.TryGetValue(keyId, out var entry)
            ? new ValueTask<LoadedState?>(new LoadedState((byte[])entry.Data.Clone(), entry.Version))
            : new ValueTask<LoadedState?>((LoadedState?)null);
    }

    /// <inheritdoc />
    public ValueTask<long> SaveAsync(string keyId, ReadOnlyMemory<byte> data, long expectedVersion, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(keyId);
        byte[] copy = data.ToArray();
        long newVersion = expectedVersion + 1;

        _store.AddOrUpdate(
            keyId,
            _ =>
            {
                if (expectedVersion != 0)
                {
                    throw Concurrency(keyId, expectedVersion, 0);
                }

                return (copy, newVersion);
            },
            (_, existing) =>
            {
                if (existing.Version != expectedVersion)
                {
                    throw Concurrency(keyId, expectedVersion, existing.Version);
                }

                return (copy, newVersion);
            });

        return new ValueTask<long>(newVersion);
    }

    private static LmsStateException Concurrency(string keyId, long expected, long actual)
        => new($"Concurrent state modification on key '{keyId}' (expected version {expected}, found {actual}); " +
               "aborting to prevent one-time-key reuse.");
}
