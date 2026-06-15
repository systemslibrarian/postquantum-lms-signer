using PostQuantum.Lms;
using PostQuantum.Lms.AspNetCore;

// Minimal signing service exposing LMS/HSS over HTTP.
//   POST /sign     — body = artifact bytes, returns the HSS signature
//   GET  /pubkey   — the HSS public key (distribute to verifiers)
//   GET  /status   — remaining signature budget
//   GET  /health   — capacity health check (Healthy / Degraded / Unhealthy)
//
// Run: dotnet run --project samples/FirmwareSigning.Web

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddLmsSigner(options =>
{
    options.KeyId = "firmware";
    options.StateDirectory = Path.Combine(builder.Environment.ContentRootPath, "signer-state");
    options.Parameters = HssParameters.FirmwareDefault; // ~1,048,576 signatures
    options.WarnWhenRemainingAtOrBelow = 10_000;
    // For a multi-node deployment, supply a CAS-capable shared store instead of the default file store:
    //   options.StateStoreFactory = sp => new MyRedisStateStore(...);
});

builder.Services.AddHealthChecks().AddCheck<LmsSignerHealthCheck>("lms-signer");

var app = builder.Build();

app.MapGet("/pubkey", (ILmsSigningService signer) =>
    Results.Bytes(signer.PublicKey(), "application/octet-stream", "firmware.pub"));

app.MapPost("/sign", async (HttpRequest request, ILmsSigningService signer, CancellationToken ct) =>
{
    using var buffer = new MemoryStream();
    await request.Body.CopyToAsync(buffer, ct);
    byte[] signature = await signer.SignAsync(buffer.ToArray(), ct);
    return Results.Bytes(signature, "application/octet-stream");
});

app.MapGet("/status", (ILmsSigningService signer) =>
    Results.Ok(new { signaturesRemaining = signer.SignaturesRemaining }));

app.MapHealthChecks("/health");

app.Run();
