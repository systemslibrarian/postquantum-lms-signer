namespace PostQuantum.Lms.Hybrid;

/// <summary>
/// A stateless signing primitive (e.g. ML-DSA / FIPS 204) used as the second leg of a hybrid composite
/// signature. Keeping this behind an interface decouples the composite logic from any one crypto backend.
/// </summary>
public interface IStatelessSigner
{
    /// <summary>Signs <paramref name="message"/> and returns the detached signature bytes.</summary>
    /// <param name="message">The message to sign.</param>
    /// <returns>The signature bytes.</returns>
    public byte[] Sign(byte[] message);
}

/// <summary>Verifies signatures produced by an <see cref="IStatelessSigner"/>.</summary>
public interface IStatelessVerifier
{
    /// <summary>Verifies <paramref name="signature"/> over <paramref name="message"/>.</summary>
    /// <param name="message">The message that was signed.</param>
    /// <param name="signature">The detached signature to check.</param>
    /// <returns><see langword="true"/> if the signature is valid; otherwise <see langword="false"/>.</returns>
    public bool Verify(byte[] message, byte[] signature);
}
