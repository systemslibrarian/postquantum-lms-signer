using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;
using PostQuantum.Lms;
using PostQuantum.Lms.Internal;
using Bc = Org.BouncyCastle.Pqc.Crypto.Lms;

namespace PostQuantum.Lms.Benchmarks;

/// <summary>
/// Head-to-head benchmarks of this library's pure-managed LMS core against BouncyCastle, for the
/// firmware-oriented parameter set LMS_SHA256_M32_H10 + LMOTS_SHA256_N32_W8. Run with:
/// <c>dotnet run -c Release --project benchmarks/PostQuantum.LMS.Signer.Benchmarks</c>.
/// </summary>
[ShortRunJob(RuntimeMoniker.Net80)]
[MemoryDiagnoser]
public class LmsBenchmarks
{
    private const LmsAlgorithm LmsAlg = LmsAlgorithm.Sha256M32H10;
    private const LmOtsAlgorithm OtsAlg = LmOtsAlgorithm.Sha256N32W8;

    private readonly byte[] _identifier = new byte[16];
    private readonly byte[] _seed = new byte[32];
    private readonly byte[] _message = "firmware-image-payload"u8.ToArray();
    private readonly byte[] _randomizer = new byte[32];

    private LmsTree _ours = null!;
    private byte[] _ourPub = null!;
    private byte[] _ourSig = null!;

    private Bc.LmsPrivateKeyParameters _bcPriv = null!;
    private byte[] _bcPub = null!;
    private byte[] _bcSig = null!;

    [GlobalSetup]
    public void Setup()
    {
        for (int i = 0; i < _identifier.Length; i++) { _identifier[i] = (byte)i; }
        for (int i = 0; i < _seed.Length; i++) { _seed[i] = (byte)(0x80 + i); }
        for (int i = 0; i < _randomizer.Length; i++) { _randomizer[i] = (byte)(0x10 + i); }

        _ours = LmsTree.Build(LmsAlg, OtsAlg, _identifier, _seed);
        _ourPub = _ours.PublicKey();
        _ourSig = _ours.Sign(0, _message, _randomizer);

        _bcPriv = Bc.Lms.GenerateKeys(Bc.LMSigParameters.lms_sha256_n32_h10, Bc.LMOtsParameters.sha256_n32_w8, 0, _identifier, _seed);
        _bcPub = _bcPriv.GetPublicKey().GetEncoded();
        _bcSig = Bc.Lms.GenerateSign(_bcPriv, _message).GetEncoded();
    }

    [Benchmark(Description = "KeyGen (build h=10 tree) — ours")]
    public byte[] Ours_KeyGen() => LmsTree.Build(LmsAlg, OtsAlg, _identifier, _seed).PublicKey();

    [Benchmark(Description = "KeyGen (build h=10 tree) — BouncyCastle")]
    public byte[] Bc_KeyGen()
        => Bc.Lms.GenerateKeys(Bc.LMSigParameters.lms_sha256_n32_h10, Bc.LMOtsParameters.sha256_n32_w8, 0, _identifier, _seed)
              .GetPublicKey().GetEncoded();

    [Benchmark(Description = "Sign — ours")]
    public byte[] Ours_Sign() => _ours.Sign(0, _message, _randomizer);

    [Benchmark(Description = "Sign — BouncyCastle")]
    public byte[] Bc_Sign() => Bc.Lms.GenerateSign(_bcPriv, _message).GetEncoded();

    [Benchmark(Description = "Verify — ours")]
    public bool Ours_Verify() => LmsTree.Verify(_ourPub, _message, _ourSig);

    [Benchmark(Description = "Verify — BouncyCastle")]
    public bool Bc_Verify()
    {
        var pub = Bc.LmsPublicKeyParameters.GetInstance(_bcPub);
        return Bc.Lms.VerifySignature(pub, _bcSig, _message);
    }
}
