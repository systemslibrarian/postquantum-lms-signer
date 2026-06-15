using PostQuantum.Lms.State;

namespace PostQuantum.Lms.Cli;

/// <summary>The <c>pqlms</c> command-line application. Hand-rolled parser keeps the tool dependency-free and AOT-friendly.</summary>
internal static class CliApp
{
    public static async Task<int> RunAsync(string[] args)
    {
        if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
        {
            PrintUsage();
            return args.Length == 0 ? 1 : 0;
        }

        try
        {
            var opts = ArgMap.Parse(args.AsSpan(1));
            return args[0] switch
            {
                "keygen" => await KeygenAsync(opts).ConfigureAwait(false),
                "sign" => await SignAsync(opts).ConfigureAwait(false),
                "verify" => Verify(opts),
                "inspect" => await InspectAsync(opts).ConfigureAwait(false),
                "pubkey" => await PubkeyAsync(opts).ConfigureAwait(false),
                _ => Unknown(args[0]),
            };
        }
        catch (LmsKeyExhaustedException ex)
        {
            return Error($"Key exhausted: {ex.Message}");
        }
        catch (LmsStateException ex)
        {
            return Error($"State error: {ex.Message}");
        }
        catch (CliUsageException ex)
        {
            return Error(ex.Message);
        }
    }

    private static async Task<int> KeygenAsync(ArgMap o)
    {
        string store = o.Require("store");
        string keyId = o.Require("key-id");
        HssParameters parameters = ResolveParams(o.Get("params") ?? "firmware-default");

        Warn("Stateful keys: the state directory IS the key. NEVER restore it from a backup or VM snapshot " +
             "while signing continues elsewhere — that can reuse a one-time key and destroy security.");

        using var signer = await HssSigner.CreateAsync(parameters, new FileStateStore(store), keyId).ConfigureAwait(false);
        byte[] pub = signer.PublicKey();

        Console.WriteLine($"Created HSS key '{keyId}' in '{store}'.");
        Console.WriteLine($"  Capacity : {signer.MaxSignatures:N0} signatures");
        Console.WriteLine($"  Levels   : {parameters.LevelCount}");
        Console.WriteLine($"  PublicKey: {Convert.ToHexString(pub).ToLowerInvariant()}");

        string? pubOut = o.Get("pubkey-out");
        if (pubOut is not null)
        {
            await File.WriteAllBytesAsync(pubOut, pub).ConfigureAwait(false);
            Console.WriteLine($"  Wrote public key to '{pubOut}'.");
        }

        return 0;
    }

    private static async Task<int> SignAsync(ArgMap o)
    {
        string store = o.Require("store");
        string keyId = o.Require("key-id");
        string input = o.Require("in");
        string output = o.Get("out") ?? input + ".sig";

        byte[] message = await File.ReadAllBytesAsync(input).ConfigureAwait(false);
        using var signer = await HssSigner.LoadAsync(new FileStateStore(store), keyId).ConfigureAwait(false);

        if (signer.SignaturesRemaining <= 0)
        {
            return Error("This key is exhausted; no signatures remain.");
        }

        byte[] signature = await signer.SignAsync(message).ConfigureAwait(false);
        await File.WriteAllBytesAsync(output, signature).ConfigureAwait(false);

        Console.WriteLine($"Signed '{input}' -> '{output}' ({signature.Length} bytes).");
        Console.WriteLine($"  Signatures remaining: {signer.SignaturesRemaining:N0}");
        return 0;
    }

    private static int Verify(ArgMap o)
    {
        string pubFile = o.Require("pubkey");
        string input = o.Require("in");
        string sigFile = o.Require("sig");
        string scheme = o.Get("scheme") ?? "hss";

        byte[] pub = File.ReadAllBytes(pubFile);
        byte[] message = File.ReadAllBytes(input);
        byte[] signature = File.ReadAllBytes(sigFile);

        bool ok = scheme.Equals("lms", StringComparison.OrdinalIgnoreCase)
            ? LmsSigner.Verify(pub, message, signature)
            : HssSigner.Verify(pub, message, signature);

        Console.WriteLine(ok ? "VALID: signature verified." : "INVALID: signature did NOT verify.");
        return ok ? 0 : 2;
    }

    private static async Task<int> InspectAsync(ArgMap o)
    {
        string store = o.Require("store");
        string keyId = o.Require("key-id");
        using var signer = await HssSigner.LoadAsync(new FileStateStore(store), keyId).ConfigureAwait(false);

        long used = signer.MaxSignatures - signer.SignaturesRemaining;
        double pct = signer.MaxSignatures == 0 ? 0 : 100.0 * used / signer.MaxSignatures;
        Console.WriteLine($"Key '{keyId}' @ '{store}'");
        Console.WriteLine($"  Capacity  : {signer.MaxSignatures:N0}");
        Console.WriteLine($"  Used      : {used:N0} ({pct:F4}%)");
        Console.WriteLine($"  Remaining : {signer.SignaturesRemaining:N0}");
        Console.WriteLine($"  PublicKey : {Convert.ToHexString(signer.PublicKey()).ToLowerInvariant()}");
        return 0;
    }

    private static async Task<int> PubkeyAsync(ArgMap o)
    {
        string store = o.Require("store");
        string keyId = o.Require("key-id");
        string output = o.Require("out");
        using var signer = await HssSigner.LoadAsync(new FileStateStore(store), keyId).ConfigureAwait(false);
        await File.WriteAllBytesAsync(output, signer.PublicKey()).ConfigureAwait(false);
        Console.WriteLine($"Wrote public key for '{keyId}' to '{output}'.");
        return 0;
    }

    private static HssParameters ResolveParams(string name) => name.ToLowerInvariant() switch
    {
        "firmware-default" or "default" => HssParameters.FirmwareDefault,
        "single-level" or "single" => HssParameters.SingleLevel,
        "small" => HssParameters.Small,
        _ => throw new CliUsageException($"Unknown --params '{name}'. Use firmware-default, single-level, or small."),
    };

    private static int Unknown(string command) => Error($"Unknown command '{command}'. Run 'pqlms --help'.");

    private static int Error(string message)
    {
        Console.Error.WriteLine("error: " + message);
        return 1;
    }

    private static void Warn(string message) => Console.Error.WriteLine("warning: " + message);

    private static void PrintUsage()
    {
        Console.WriteLine(
            """
            pqlms — PostQuantum.LMS.Signer CLI (NIST SP 800-208 / RFC 8554 LMS & HSS)

            USAGE:
              pqlms keygen  --store <dir> --key-id <id> [--params firmware-default|single-level|small] [--pubkey-out <file>]
              pqlms sign    --store <dir> --key-id <id> --in <file> [--out <file.sig>]
              pqlms verify  --pubkey <file> --in <file> --sig <file> [--scheme hss|lms]
              pqlms inspect --store <dir> --key-id <id>
              pqlms pubkey  --store <dir> --key-id <id> --out <file>

            NOTES:
              • The --store directory holds crash-safe signer STATE. Treat it as the private key.
              • Never copy/restore state while another signer is using the same key (one-time-key reuse).
              • Default parameters: two-level HSS, SHA-256, h=10/10, w=8 (~1,048,576 signatures).

            To God be the glory.
            """);
    }
}

/// <summary>Minimal <c>--key value</c> argument map.</summary>
internal sealed class ArgMap
{
    private readonly Dictionary<string, string> _values = new(StringComparer.OrdinalIgnoreCase);

    public static ArgMap Parse(ReadOnlySpan<string> args)
    {
        var map = new ArgMap();
        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i];
            if (!a.StartsWith("--", StringComparison.Ordinal))
            {
                throw new CliUsageException($"Unexpected argument '{a}'. Options must be '--name value'.");
            }

            string key = a[2..];
            if (i + 1 >= args.Length)
            {
                throw new CliUsageException($"Option '--{key}' requires a value.");
            }

            map._values[key] = args[++i];
        }

        return map;
    }

    public string? Get(string key) => _values.TryGetValue(key, out string? v) ? v : null;

    public string Require(string key) => Get(key) ?? throw new CliUsageException($"Missing required option '--{key}'.");
}

/// <summary>Raised for user-facing argument errors.</summary>
internal sealed class CliUsageException(string message) : Exception(message);
