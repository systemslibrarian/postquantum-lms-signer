namespace PostQuantum.Lms.State;

/// <summary>A loaded state blob together with its monotonic version (for optimistic concurrency).</summary>
public sealed class LoadedState
{
    /// <summary>The opaque persisted signer state.</summary>
    public byte[] Data { get; }

    /// <summary>The version observed at load time. Pass this back as <c>expectedVersion</c> when saving.</summary>
    public long Version { get; }

    /// <summary>Creates a loaded-state record.</summary>
    public LoadedState(byte[] data, long version)
    {
        Data = data;
        Version = version;
    }
}

/// <summary>
/// Durable, atomic persistence for signer state. This is the linchpin of state safety: the signer
/// always advances and persists the one-time-key index <b>before</b> a signature is released, so a
/// crash can at worst waste a key, never reuse one.
/// </summary>
/// <remarks>
/// <para>Implementations <b>must</b> guarantee:</para>
/// <list type="bullet">
///   <item><b>Atomicity</b> — a save is all-or-nothing; readers never observe a torn write.</item>
///   <item><b>Durability</b> — the data is on stable storage before <see cref="SaveAsync"/> returns.</item>
///   <item><b>Compare-and-swap</b> — a save succeeds only if the stored version equals
///   <c>expectedVersion</c>; otherwise it throws <see cref="LmsStateException"/>. This is what makes
///   it safe for multiple processes/nodes to back the same key: a losing writer is told to stop
///   rather than silently reuse an index.</item>
/// </list>
/// <para>A non-existent key has version 0. The first successful save returns version 1.</para>
/// </remarks>
public interface IStateStore
{
    /// <summary>Loads the current state, or <see langword="null"/> if the key does not exist.</summary>
    public ValueTask<LoadedState?> LoadAsync(string keyId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically and durably persists <paramref name="data"/> for <paramref name="keyId"/>, but only
    /// if the currently stored version equals <paramref name="expectedVersion"/>. Returns the new version.
    /// </summary>
    /// <exception cref="LmsStateException">
    /// The stored version did not match <paramref name="expectedVersion"/> (concurrent modification) —
    /// aborting protects against one-time-key reuse.
    /// </exception>
    public ValueTask<long> SaveAsync(string keyId, ReadOnlyMemory<byte> data, long expectedVersion, CancellationToken cancellationToken = default);
}
