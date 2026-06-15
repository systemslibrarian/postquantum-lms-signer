using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace PostQuantum.Lms.Hybrid;

/// <summary>
/// An ML-DSA (FIPS 204) key pair — the stateless second leg of a hybrid signature. Unlike the HSS key,
/// an ML-DSA key is <b>stateless</b>: it can be safely backed up, copied, and reloaded without any reuse
/// risk, so it is managed as an ordinary private key (export it and store it securely; there is no state
/// machine to coordinate).
/// </summary>
public sealed class MlDsaKeyPair
{
    private readonly MLDsaPrivateKeyParameters _privateKey;

    /// <summary>The ML-DSA parameter set this key belongs to.</summary>
    public MLDsaParameters Parameters { get; }

    /// <summary>The raw encoded ML-DSA public key (distribute this to verifiers).</summary>
    public byte[] PublicKey { get; }

    private MlDsaKeyPair(MLDsaPrivateKeyParameters privateKey)
    {
        _privateKey = privateKey;
        Parameters = privateKey.Parameters;
        PublicKey = privateKey.GetPublicKey().GetEncoded();
    }

    /// <summary>Generates a new ML-DSA key pair. Defaults to <c>ML-DSA-65</c> (NIST Level 3).</summary>
    public static MlDsaKeyPair Generate(MLDsaParameters? parameters = null)
    {
        MLDsaParameters set = parameters ?? MLDsaParameters.ml_dsa_65;
        var generator = new MLDsaKeyPairGenerator();
        generator.Init(new MLDsaKeyGenerationParameters(new SecureRandom(), set));
        AsymmetricCipherKeyPair pair = generator.GenerateKeyPair();
        return new MlDsaKeyPair((MLDsaPrivateKeyParameters)pair.Private);
    }

    /// <summary>Imports a key pair from a previously exported encoded private key.</summary>
    public static MlDsaKeyPair ImportPrivateKey(MLDsaParameters parameters, byte[] encodedPrivateKey)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(encodedPrivateKey);
        return new MlDsaKeyPair(MLDsaPrivateKeyParameters.FromEncoding(parameters, encodedPrivateKey));
    }

    /// <summary>Exports the encoded private key so the caller can store it securely (e.g. in an HSM or vault).</summary>
    public byte[] ExportPrivateKey() => _privateKey.GetEncoded();

    /// <summary>Creates a signer bound to this key pair's private key.</summary>
    public MlDsaSigner CreateSigner() => new(_privateKey);

    /// <summary>Creates a verifier bound to this key pair's public key.</summary>
    public MlDsaVerifier CreateVerifier() => new(_privateKey.GetPublicKey());
}
