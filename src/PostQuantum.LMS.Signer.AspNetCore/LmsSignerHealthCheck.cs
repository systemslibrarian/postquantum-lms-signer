using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;

namespace PostQuantum.Lms.AspNetCore;

/// <summary>
/// A health check that surfaces the signing key's remaining capacity so capacity exhaustion is caught by
/// operations long before it becomes an outage. Register it with the standard ASP.NET Core health-check
/// pipeline, e.g.:
/// <code>services.AddHealthChecks().AddCheck&lt;LmsSignerHealthCheck&gt;("lms-signer");</code>
/// </summary>
/// <remarks>
/// Reports <see cref="HealthStatus.Healthy"/> normally, <see cref="HealthStatus.Degraded"/> when the
/// remaining budget falls at or below <see cref="LmsSignerOptions.WarnWhenRemainingAtOrBelow"/> (rotate
/// soon), and <see cref="HealthStatus.Unhealthy"/> if the key is exhausted or its state cannot be read.
/// </remarks>
public sealed class LmsSignerHealthCheck : IHealthCheck
{
    private readonly ILmsSigningService _signingService;
    private readonly LmsSignerOptions _options;

    /// <summary>Creates the health check.</summary>
    public LmsSignerHealthCheck(ILmsSigningService signingService, IOptions<LmsSignerOptions> options)
    {
        ArgumentNullException.ThrowIfNull(signingService);
        ArgumentNullException.ThrowIfNull(options);
        _signingService = signingService;
        _options = options.Value;
    }

    /// <inheritdoc />
    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        try
        {
            long remaining = _signingService.SignaturesRemaining;
            var data = new Dictionary<string, object>
            {
                ["keyId"] = _options.KeyId,
                ["signaturesRemaining"] = remaining,
            };

            if (remaining <= 0)
            {
                return Task.FromResult(HealthCheckResult.Unhealthy(
                    "LMS/HSS signing key is exhausted; rotate to a new key.", data: data));
            }

            if (_options.WarnWhenRemainingAtOrBelow > 0 && remaining <= _options.WarnWhenRemainingAtOrBelow)
            {
                return Task.FromResult(HealthCheckResult.Degraded(
                    $"LMS/HSS signing key is running low ({remaining} remaining); plan rotation.", data: data));
            }

            return Task.FromResult(HealthCheckResult.Healthy(
                $"LMS/HSS signing key healthy ({remaining} signatures remaining).", data));
        }
        catch (LmsException ex)
        {
            return Task.FromResult(HealthCheckResult.Unhealthy(
                "LMS/HSS signer state could not be read (possible corruption or misconfiguration).", ex));
        }
    }
}
