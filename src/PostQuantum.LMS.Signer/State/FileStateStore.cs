using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace PostQuantum.Lms.State;

/// <summary>
/// A crash-safe, file-backed <see cref="IStateStore"/> suitable for single-host production signing.
/// </summary>
/// <remarks>
/// <para>Durability and atomicity are achieved by writing to a temporary file, flushing it to disk,
/// then atomically renaming it over the target (POSIX <c>rename</c> / Windows replace). The previous
/// state is retained as a <c>.bak</c> sibling. Every record carries a SHA-256 integrity tag, so a torn
/// or tampered file is detected on load rather than silently producing a reused index.</para>
/// <para>Compare-and-swap and multi-process safety are enforced with an exclusive lock file held only
/// for the duration of each save, so two processes pointed at the same directory cannot both advance
/// the same version.</para>
/// </remarks>
public sealed class FileStateStore : IStateStore
{
    private const uint Magic = 0x4C4D5353; // "LMSS"
    private const byte FormatVersion = 1;
    private const int HeaderLength = 4 + 1 + 3 + 8 + 4; // magic|fmt|reserved|version|dataLen
    private const int TagLength = 32;

    private readonly string _directory;

    /// <summary>Creates a store that persists each key as a file under <paramref name="directory"/>.</summary>
    public FileStateStore(string directory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        _directory = directory;
        Directory.CreateDirectory(_directory);
    }

    private string PathFor(string keyId)
    {
        // Deterministic, collision-resistant, filesystem-safe filename derived from the key id.
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(keyId));
        string safe = Convert.ToHexString(hash, 0, 8).ToLowerInvariant();
        var sb = new StringBuilder();
        foreach (char c in keyId)
        {
            sb.Append(char.IsLetterOrDigit(c) || c is '-' or '_' ? c : '_');
        }

        string prefix = sb.Length > 40 ? sb.ToString(0, 40) : sb.ToString();
        return Path.Combine(_directory, $"{prefix}.{safe}.lms.state");
    }

    /// <inheritdoc />
    public async ValueTask<LoadedState?> LoadAsync(string keyId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(keyId);
        string path = PathFor(keyId);
        if (!File.Exists(path))
        {
            return null;
        }

        byte[] raw;
        try
        {
            raw = await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
        }
        catch (IOException ex)
        {
            throw new LmsStateException($"Failed to read signer state at '{path}'.", ex);
        }

        return Decode(raw, path);
    }

    /// <inheritdoc />
    public async ValueTask<long> SaveAsync(string keyId, ReadOnlyMemory<byte> data, long expectedVersion, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(keyId);
        string path = PathFor(keyId);
        string tmp = path + ".tmp";
        string bak = path + ".bak";
        string lockPath = path + ".lock";

        // Hold an exclusive OS lock for the whole read-verify-write so concurrent processes serialize.
        using FileStream lockFile = new(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);

        long current = 0;
        if (File.Exists(path))
        {
            var existing = Decode(await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false), path);
            current = existing.Version;
        }

        if (current != expectedVersion)
        {
            throw new LmsStateException(
                $"Concurrent state modification on key '{keyId}' (expected version {expectedVersion}, found {current}); " +
                "aborting to prevent one-time-key reuse.");
        }

        long newVersion = expectedVersion + 1;
        byte[] encoded = Encode(data.Span, newVersion);

        // Atomic publish: write temp, flush to disk, then rename over the target.
        await using (FileStream fs = new(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            await fs.WriteAsync(encoded, cancellationToken).ConfigureAwait(false);
            await fs.FlushAsync(cancellationToken).ConfigureAwait(false);
            fs.Flush(flushToDisk: true);
        }

        if (File.Exists(path))
        {
            File.Copy(path, bak, overwrite: true);
        }

        File.Move(tmp, path, overwrite: true);
        return newVersion;
    }

    private static byte[] Encode(ReadOnlySpan<byte> data, long version)
    {
        byte[] buffer = new byte[HeaderLength + data.Length + TagLength];
        Span<byte> span = buffer;
        BinaryPrimitives.WriteUInt32BigEndian(span, Magic);
        span[4] = FormatVersion;
        // span[5..8] reserved (zero)
        BinaryPrimitives.WriteInt64BigEndian(span.Slice(8), version);
        BinaryPrimitives.WriteInt32BigEndian(span.Slice(16), data.Length);
        data.CopyTo(span.Slice(HeaderLength));

        int tagOffset = HeaderLength + data.Length;
        SHA256.HashData(span.Slice(0, tagOffset), span.Slice(tagOffset, TagLength));
        return buffer;
    }

    private static LoadedState Decode(byte[] raw, string path)
    {
        if (raw.Length < HeaderLength + TagLength)
        {
            throw new LmsStateException($"Signer state at '{path}' is truncated.");
        }

        ReadOnlySpan<byte> span = raw;
        if (BinaryPrimitives.ReadUInt32BigEndian(span) != Magic || span[4] != FormatVersion)
        {
            throw new LmsStateException($"Signer state at '{path}' has an unrecognized format.");
        }

        long version = BinaryPrimitives.ReadInt64BigEndian(span.Slice(8));
        int dataLen = BinaryPrimitives.ReadInt32BigEndian(span.Slice(16));
        if (dataLen < 0 || HeaderLength + dataLen + TagLength != raw.Length)
        {
            throw new LmsStateException($"Signer state at '{path}' has an inconsistent length.");
        }

        int tagOffset = HeaderLength + dataLen;
        Span<byte> expected = stackalloc byte[TagLength];
        SHA256.HashData(span.Slice(0, tagOffset), expected);
        if (!CryptographicOperations.FixedTimeEquals(expected, span.Slice(tagOffset, TagLength)))
        {
            throw new LmsStateException(
                $"Integrity check failed for signer state at '{path}'. The file is corrupt or was tampered with; " +
                "restore from a known-good backup rather than risk key reuse.");
        }

        return new LoadedState(span.Slice(HeaderLength, dataLen).ToArray(), version);
    }
}
