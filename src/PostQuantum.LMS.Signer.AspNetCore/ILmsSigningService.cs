namespace PostQuantum.Lms.AspNetCore;

/// <summary>
/// A long-lived signing service that owns a single stateful HSS key and serializes access to it.
/// Register it with <see cref="ServiceCollectionExtensions.AddLmsSigner"/> and resolve it as a singleton.
/// </summary>
public interface ILmsSigningService
{
    /// <summary>
    /// Signs <paramref name="message"/>, durably advancing the key state before the signature is released.
    /// </summary>
    /// <param name="message">The message (typically a digest of the artifact) to sign.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The HSS signature in RFC 8554 wire format.</returns>
    public Task<byte[]> SignAsync(byte[] message, CancellationToken cancellationToken);

    /// <summary>Returns the HSS public key (RFC 8554 wire format) to distribute to verifiers.</summary>
    /// <returns>The HSS public key bytes.</returns>
    public byte[] PublicKey();

    /// <summary>The number of signatures still available before the key is exhausted.</summary>
    public long SignaturesRemaining { get; }
}
