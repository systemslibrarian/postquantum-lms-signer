// Sample firmware signer scaffolded by `dotnet new pqlms-firmware-signer`.
//
// Demonstrates the core PostQuantum.LMS.Signer workflow:
//   1. keygen  — create a crash-safe HSS key backed by FileStateStore
//   2. sign    — sign a file (state is durably advanced before the signature is released)
//   3. verify  — verify a file against a distributed public key
//
// State safety note: NEVER restore the state directory from a backup or VM snapshot and keep signing —
// doing so can reuse a one-time key and catastrophically break the scheme. See CLAUDE.md "DANGER".

using System.Security.Cryptography;
using PostQuantum.Lms;
using PostQuantum.Lms.State;

const string KeyId = "firmware-signing-key";
string stateDir = Path.Combine(AppContext.BaseDirectory, "lms-state");

if (args.Length < 1)
{
    Console.Error.WriteLine("Usage:");
    Console.Error.WriteLine("  FirmwareSigner keygen");
    Console.Error.WriteLine("  FirmwareSigner sign   <file> <signature-out>");
    Console.Error.WriteLine("  FirmwareSigner verify <file> <signature> <publickey>");
    return 1;
}

var store = new FileStateStore(stateDir);

switch (args[0])
{
    case "keygen":
    {
        using var signer = await HssSigner.CreateAsync(HssParameters.FirmwareDefault, store, KeyId);
        string pubPath = Path.Combine(AppContext.BaseDirectory, "firmware.pub");
        await File.WriteAllBytesAsync(pubPath, signer.PublicKey());
        Console.WriteLine($"Created key '{KeyId}'. Public key written to {pubPath}.");
        Console.WriteLine($"Capacity: {signer.MaxSignatures} signatures.");
        return 0;
    }

    case "sign":
    {
        if (args.Length < 3)
        {
            Console.Error.WriteLine("sign requires <file> <signature-out>.");
            return 1;
        }

        using var signer = await HssSigner.LoadAsync(store, KeyId);
        byte[] digest = SHA256.HashData(await File.ReadAllBytesAsync(args[1]));
        byte[] signature = await signer.SignAsync(digest);
        await File.WriteAllBytesAsync(args[2], signature);
        Console.WriteLine($"Signed {args[1]} -> {args[2]} ({signer.SignaturesRemaining} signatures remaining).");
        return 0;
    }

    case "verify":
    {
        if (args.Length < 4)
        {
            Console.Error.WriteLine("verify requires <file> <signature> <publickey>.");
            return 1;
        }

        byte[] digest = SHA256.HashData(await File.ReadAllBytesAsync(args[1]));
        byte[] signature = await File.ReadAllBytesAsync(args[2]);
        byte[] publicKey = await File.ReadAllBytesAsync(args[3]);
        bool ok = HssSigner.Verify(publicKey, digest, signature);
        Console.WriteLine(ok ? "VALID" : "INVALID");
        return ok ? 0 : 2;
    }

    default:
        Console.Error.WriteLine($"Unknown command '{args[0]}'.");
        return 1;
}
