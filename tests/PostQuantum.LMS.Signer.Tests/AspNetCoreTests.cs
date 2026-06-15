using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using PostQuantum.Lms;
using PostQuantum.Lms.AspNetCore;
using PostQuantum.Lms.State;

namespace PostQuantum.Lms.Tests;

public sealed class AspNetCoreTests
{
    [Fact]
    public async Task AddLmsSigner_DefaultFileStore_SignsAndVerifies()
    {
        string dir = Path.Combine(Path.GetTempPath(), "lms-di-" + Guid.NewGuid().ToString("N"));
        try
        {
            var services = new ServiceCollection();
            services.AddLmsSigner(o =>
            {
                o.KeyId = "svc";
                o.StateDirectory = dir;
                o.Parameters = HssParameters.Small;
            });
            await using var provider = services.BuildServiceProvider();

            var signer = provider.GetRequiredService<ILmsSigningService>();
            byte[] message = "di-message"u8.ToArray();
            byte[] sig = await signer.SignAsync(message, default);

            Assert.True(HssSigner.Verify(signer.PublicKey(), message, sig));
            Assert.Equal(HssParameters.Small.MaxSignatures - 1, signer.SignaturesRemaining);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task AddLmsSigner_CustomStoreOverload_UsesProvidedStore()
    {
        var sharedStore = new InMemoryStateStore();
        var services = new ServiceCollection();
        services.AddLmsSigner(
            o => { o.KeyId = "custom"; o.Parameters = HssParameters.Small; },
            _ => sharedStore);
        await using var provider = services.BuildServiceProvider();

        var signer = provider.GetRequiredService<ILmsSigningService>();
        byte[] sig = await signer.SignAsync("m"u8.ToArray(), default);
        Assert.True(HssSigner.Verify(signer.PublicKey(), "m"u8.ToArray(), sig));

        // The custom store actually holds the state: a fresh signer loaded from it continues, not restarts.
        using var reloaded = await HssSigner.LoadAsync(sharedStore, "custom");
        Assert.Equal(HssParameters.Small.MaxSignatures - 1, reloaded.SignaturesRemaining);
    }

    [Fact]
    public void AddLmsSigner_BlankKeyId_FailsValidation()
    {
        var services = new ServiceCollection();
        services.AddLmsSigner(o => o.KeyId = "");
        using var provider = services.BuildServiceProvider();

        Assert.Throws<OptionsValidationException>(() => _ = provider.GetRequiredService<IOptions<LmsSignerOptions>>().Value);
    }

    [Fact]
    public async Task HealthCheck_ReportsDegraded_WhenBudgetLow_AndHealthy_WhenDisabled()
    {
        var store = new InMemoryStateStore();
        var services = new ServiceCollection();
        services.AddLmsSigner(
            o =>
            {
                o.KeyId = "hc";
                o.Parameters = HssParameters.Small;           // capacity 1024
                o.WarnWhenRemainingAtOrBelow = long.MaxValue; // force the low-budget path
            },
            _ => store);
        await using var provider = services.BuildServiceProvider();

        var check = new LmsSignerHealthCheck(
            provider.GetRequiredService<ILmsSigningService>(),
            provider.GetRequiredService<IOptions<LmsSignerOptions>>());

        HealthCheckResult degraded = await check.CheckHealthAsync(new HealthCheckContext());
        Assert.Equal(HealthStatus.Degraded, degraded.Status);
        Assert.Equal(HssParameters.Small.MaxSignatures, Convert.ToInt64(degraded.Data["signaturesRemaining"]));
    }

    [Fact]
    public async Task HealthCheck_ReportsHealthy_WhenBudgetAmple()
    {
        var store = new InMemoryStateStore();
        var services = new ServiceCollection();
        services.AddLmsSigner(
            o => { o.KeyId = "hc2"; o.Parameters = HssParameters.Small; o.WarnWhenRemainingAtOrBelow = 0; },
            _ => store);
        await using var provider = services.BuildServiceProvider();

        var check = new LmsSignerHealthCheck(
            provider.GetRequiredService<ILmsSigningService>(),
            provider.GetRequiredService<IOptions<LmsSignerOptions>>());

        HealthCheckResult healthy = await check.CheckHealthAsync(new HealthCheckContext());
        Assert.Equal(HealthStatus.Healthy, healthy.Status);
    }
}
