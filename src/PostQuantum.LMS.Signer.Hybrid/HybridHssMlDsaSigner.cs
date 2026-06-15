using Org.BouncyCastle.Crypto.Parameters;

namespace PostQuantum.Lms.Hybrid;

/// <summary>
/// A defense-in-depth composite signer: every signature is the concatenation of a stateful HSS signature
/// (post-quantum, hash-based) and a stateless ML-DSA signature (post-quantum, lattice-based). A verifier
/// requires <b>both</b> to pass, so a break in either family alone does not forge a signature.
/// </summary>
/// <remarks>
/// <para>The HSS leg is the headline asset and carries the never-reuse state guarantees of the core
/// library; the ML-DSA leg is stateless and hedges against an unforeseen weakness in either primitive.</para>
/// <para>Generate and manage the ML-DSA key with <see cref="MlDsaKeyPair"/>, and distribute a single
/// <see cref="HybridPublicKey"/> bundle (via <see cref="PublicKey"/>) to verifiers.</para>
/// </remarks>
public sealed class HybridHssMlDsaSigner
{
    private readonly HssSigner _hssSigner;
    private readonly IStatelessSigner _mlDsaSigner;
    private readonly MLDsaParameters? _mlDsaParameters;
    private readonly byte[]? _mlDsaPublicKey;

    /// <summary>
    /// Creates a composite signer over an HSS signer and any stateless (ML-DSA) signer. This backend-agnostic
    /// overload suits testing or custom ML-DSA backends; use the <see cref="MlDsaKeyPair"/> overload to also
    /// export a <see cref="HybridPublicKey"/> bundle.
    /// </summary>
    /// <param name="hssSigner">The stateful HSS signer.</param>
    /// <param name="mlDsaSigner">The stateless second-leg signer.</param>
    public HybridHssMlDsaSigner(HssSigner hssSigner, IStatelessSigner mlDsaSigner)
    {
        ArgumentNullException.ThrowIfNull(hssSigner);
        ArgumentNullException.ThrowIfNull(mlDsaSigner);
        _hssSigner = hssSigner;
        _mlDsaSigner = mlDsaSigner;
    }

    /// <summary>
    /// Creates a composite signer over an HSS signer and an ML-DSA key pair, retaining the ML-DSA public
    /// material so <see cref="PublicKey"/> can produce a portable verification bundle.
    /// </summary>
    public HybridHssMlDsaSigner(HssSigner hssSigner, MlDsaKeyPair mlDsaKeyPair)
    {
        ArgumentNullException.ThrowIfNull(hssSigner);
        ArgumentNullException.ThrowIfNull(mlDsaKeyPair);
        _hssSigner = hssSigner;
        _mlDsaSigner = mlDsaKeyPair.CreateSigner();
        _mlDsaParameters = mlDsaKeyPair.Parameters;
        _mlDsaPublicKey = mlDsaKeyPair.PublicKey;
    }

    /// <summary>HSS signatures still available — the stateful leg is the limiting factor.</summary>
    public long SignaturesRemaining => _hssSigner.SignaturesRemaining;

    /// <summary>
    /// The portable hybrid public-key bundle (HSS + ML-DSA) for distribution to verifiers. Only available
    /// when the signer was constructed with an <see cref="MlDsaKeyPair"/>.
    /// </summary>
    /// <exception cref="InvalidOperationException">The signer was built without ML-DSA public-key material.</exception>
    public HybridPublicKey PublicKey()
    {
        if (_mlDsaPublicKey is null || _mlDsaParameters is null)
        {
            throw new InvalidOperationException(
                "This signer was constructed without ML-DSA public-key material. Use the MlDsaKeyPair " +
                "constructor to export a HybridPublicKey.");
        }

        return new HybridPublicKey(_hssSigner.PublicKey(), _mlDsaParameters, _mlDsaPublicKey);
    }

    /// <summary>
    /// Signs <paramref name="message"/> with both legs and returns the length-prefixed composite signature.
    /// </summary>
    /// <param name="message">The message to sign.</param>
    /// <returns>The composite signature (<see cref="HybridSignature"/> wire format).</returns>
    public async Task<byte[]> SignAsync(byte[] message)
    {
        ArgumentNullException.ThrowIfNull(message);

        // Sign with the stateful leg first: it durably advances state before releasing its signature.
        byte[] hssSignature = await _hssSigner.SignAsync(message).ConfigureAwait(false);
        byte[] mlDsaSignature = _mlDsaSigner.Sign(message);
        return HybridSignature.Encode(hssSignature, mlDsaSignature);
    }

    /// <summary>
    /// Verifies a composite signature: returns <see langword="true"/> only if BOTH the HSS leg and the
    /// ML-DSA leg verify over <paramref name="message"/>.
    /// </summary>
    /// <param name="hssPublicKey">The HSS public key (RFC 8554 wire format).</param>
    /// <param name="mlDsaVerifier">The stateless verifier holding the ML-DSA public key.</param>
    /// <param name="message">The signed message.</param>
    /// <param name="compositeSignature">The composite signature to verify.</param>
    /// <returns><see langword="true"/> if both legs verify; otherwise <see langword="false"/>.</returns>
    public static bool Verify(
        byte[] hssPublicKey,
        IStatelessVerifier mlDsaVerifier,
        byte[] message,
        byte[] compositeSignature)
    {
        ArgumentNullException.ThrowIfNull(hssPublicKey);
        ArgumentNullException.ThrowIfNull(mlDsaVerifier);
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(compositeSignature);

        byte[] hssSignature;
        byte[] mlDsaSignature;
        try
        {
            (hssSignature, mlDsaSignature) = HybridSignature.Decode(compositeSignature);
        }
        catch (ArgumentException)
        {
            return false;
        }

        bool hssOk = HssSigner.Verify(hssPublicKey, message, hssSignature);
        bool mlDsaOk = mlDsaVerifier.Verify(message, mlDsaSignature);
        return hssOk && mlDsaOk;
    }

    /// <summary>
    /// Convenience overload that builds an ML-DSA verifier from a raw encoded ML-DSA public key and
    /// parameter set, then delegates to <see cref="Verify(byte[], IStatelessVerifier, byte[], byte[])"/>.
    /// </summary>
    /// <param name="hssPublicKey">The HSS public key (RFC 8554 wire format).</param>
    /// <param name="mlDsaParameters">The ML-DSA parameter set the public key belongs to.</param>
    /// <param name="mlDsaPublicKey">The raw encoded ML-DSA public key.</param>
    /// <param name="message">The signed message.</param>
    /// <param name="compositeSignature">The composite signature to verify.</param>
    /// <returns><see langword="true"/> if both legs verify; otherwise <see langword="false"/>.</returns>
    public static bool Verify(
        byte[] hssPublicKey,
        MLDsaParameters mlDsaParameters,
        byte[] mlDsaPublicKey,
        byte[] message,
        byte[] compositeSignature)
    {
        ArgumentNullException.ThrowIfNull(mlDsaParameters);
        ArgumentNullException.ThrowIfNull(mlDsaPublicKey);
        IStatelessVerifier verifier = MlDsaVerifier.FromEncoded(mlDsaParameters, mlDsaPublicKey);
        return Verify(hssPublicKey, verifier, message, compositeSignature);
    }
}
