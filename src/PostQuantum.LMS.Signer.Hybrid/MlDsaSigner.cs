using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace PostQuantum.Lms.Hybrid;

/// <summary>
/// A BouncyCastle-backed ML-DSA (FIPS 204) implementation of <see cref="IStatelessSigner"/>.
/// </summary>
/// <remarks>
/// <para>This wraps <see cref="MLDsaSigner"/> over a private key. The companion
/// <see cref="MlDsaVerifier"/> verifies with a public key.</para>
/// <para>TODO: Add first-class ML-DSA key generation/management (seed handling, secure storage,
/// rotation). For now keys are supplied as already-decoded BouncyCastle parameter objects so the
/// hybrid composite logic can be exercised end-to-end.</para>
/// </remarks>
public sealed class MlDsaSigner : IStatelessSigner
{
    private readonly MLDsaPrivateKeyParameters _privateKey;

    /// <summary>Creates an ML-DSA signer over an existing private key.</summary>
    /// <param name="privateKey">The ML-DSA private key parameters.</param>
    public MlDsaSigner(MLDsaPrivateKeyParameters privateKey)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        _privateKey = privateKey;
    }

    /// <summary>
    /// Creates an ML-DSA signer from a raw encoded private key for the given parameter set
    /// (e.g. <see cref="MLDsaParameters.ml_dsa_65"/>).
    /// </summary>
    /// <param name="parameters">The ML-DSA parameter set.</param>
    /// <param name="encodedPrivateKey">The raw encoded private key.</param>
    /// <returns>A ready-to-use signer.</returns>
    public static MlDsaSigner FromEncoded(MLDsaParameters parameters, byte[] encodedPrivateKey)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(encodedPrivateKey);
        return new MlDsaSigner(MLDsaPrivateKeyParameters.FromEncoding(parameters, encodedPrivateKey));
    }

    /// <inheritdoc />
    public byte[] Sign(byte[] message)
    {
        ArgumentNullException.ThrowIfNull(message);
        var signer = new MLDsaSigner(_privateKey.Parameters, deterministic: false);
        signer.Init(forSigning: true, _privateKey);
        signer.BlockUpdate(message, 0, message.Length);
        return signer.GenerateSignature();
    }
}

/// <summary>A BouncyCastle-backed ML-DSA implementation of <see cref="IStatelessVerifier"/>.</summary>
public sealed class MlDsaVerifier : IStatelessVerifier
{
    private readonly MLDsaPublicKeyParameters _publicKey;

    /// <summary>Creates an ML-DSA verifier over an existing public key.</summary>
    /// <param name="publicKey">The ML-DSA public key parameters.</param>
    public MlDsaVerifier(MLDsaPublicKeyParameters publicKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        _publicKey = publicKey;
    }

    /// <summary>Creates an ML-DSA verifier from a raw encoded public key for the given parameter set.</summary>
    /// <param name="parameters">The ML-DSA parameter set.</param>
    /// <param name="encodedPublicKey">The raw encoded public key.</param>
    /// <returns>A ready-to-use verifier.</returns>
    public static MlDsaVerifier FromEncoded(MLDsaParameters parameters, byte[] encodedPublicKey)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(encodedPublicKey);
        return new MlDsaVerifier(MLDsaPublicKeyParameters.FromEncoding(parameters, encodedPublicKey));
    }

    /// <inheritdoc />
    public bool Verify(byte[] message, byte[] signature)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(signature);
        var verifier = new MLDsaSigner(_publicKey.Parameters, deterministic: false);
        verifier.Init(forSigning: false, _publicKey);
        verifier.BlockUpdate(message, 0, message.Length);
        return verifier.VerifySignature(signature);
    }
}
