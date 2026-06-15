using Microsoft.Extensions.DependencyInjection;

namespace PostQuantum.Lms.AspNetCore;

/// <summary>Dependency-injection registration helpers for the LMS/HSS signing service.</summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="LmsSignerOptions"/> and a singleton <see cref="ILmsSigningService"/>
    /// (backed by <see cref="HssSigningService"/>) in the service collection.
    /// </summary>
    /// <param name="services">The service collection to add to.</param>
    /// <param name="configure">A delegate to configure <see cref="LmsSignerOptions"/>.</param>
    /// <returns>The same <see cref="IServiceCollection"/> for chaining.</returns>
    public static IServiceCollection AddLmsSigner(this IServiceCollection services, Action<LmsSignerOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.AddOptions<LmsSignerOptions>().Configure(configure);
        services.AddSingleton<ILmsSigningService, HssSigningService>();
        return services;
    }
}
