using PostQuantum.Lms;
using PostQuantum.Lms.State;

// End-to-end firmware-signing demo:
//   1. generate (or reload) a crash-safe HSS signing key,
//   2. sign an artifact (the state index is persisted BEFORE the signature is released),
//   3. verify with the public key alone.
//
// Run:  dotnet run --project samples/FirmwareSigning.Console -- path/to/firmware.bin
// (with no argument it signs a generated demo artifact).

string stateDir = Path.Combine(AppContext.BaseDirectory, "signer-state");
const string keyId = "firmware-demo";
var store = new FileStateStore(stateDir);

string artifactPath = args.Length > 0 ? args[0] : CreateDemoArtifact();
byte[] image = File.ReadAllBytes(artifactPath);
Console.WriteLine($"Artifact : {artifactPath} ({image.Length} bytes)");

// Create the key on first run; reload it on subsequent runs so the index never restarts.
// HssParameters.Small (1024 sigs) keeps the demo instant; production should use FirmwareDefault (~1M).
bool exists = await store.LoadAsync(keyId) is not null;
using HssSigner signer = exists
    ? await HssSigner.LoadAsync(store, keyId)
    : await HssSigner.CreateAsync(HssParameters.Small, store, keyId);

Console.WriteLine(exists ? "Loaded existing key." : "Generated new key.");

byte[] publicKey = signer.PublicKey();
string pubPath = Path.Combine(stateDir, keyId + ".pub");
await File.WriteAllBytesAsync(pubPath, publicKey);

byte[] signature = await signer.SignAsync(image);
string sigPath = artifactPath + ".sig";
await File.WriteAllBytesAsync(sigPath, signature);
Console.WriteLine($"Signed -> {sigPath} ({signature.Length} bytes)");
Console.WriteLine($"Signatures remaining: {signer.SignaturesRemaining:N0} / {signer.MaxSignatures:N0}");

// Verification needs only the public key — no state.
bool ok = HssSigner.Verify(publicKey, image, signature);
Console.WriteLine(ok ? "VERIFIED" : "VERIFICATION FAILED");

// Demonstrate tamper detection.
byte[] tampered = (byte[])image.Clone();
tampered[0] ^= 0xFF;
Console.WriteLine($"Tampered image verifies? {HssSigner.Verify(publicKey, tampered, signature)} (expected False)");

return ok ? 0 : 1;

static string CreateDemoArtifact()
{
    string path = Path.Combine(AppContext.BaseDirectory, "demo-firmware.bin");
    File.WriteAllText(path, "DEMO FIRMWARE IMAGE v1.0.0 — replace with a real artifact.\n");
    return path;
}
