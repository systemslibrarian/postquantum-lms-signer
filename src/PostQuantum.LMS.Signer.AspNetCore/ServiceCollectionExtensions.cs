using Microsoft.Extensions.DependencyInjection;
using PostQuantum.Lms.State;

namespace PostQuantum.Lms.AspNetCore;

/// <summary>Dependency-injection registration helpers for the LMS/HSS signing service.</summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="LmsSignerOptions"/> and a singleton <see cref="ILmsSigningService"/>
    /// (backed by <see cref="HssSigningService"/>). By default the signer is backed by a crash-safe
    /// <see cref="FileStateStore"/> at <see cref="LmsSignerOptions.StateDirectory"/>; set
    /// <see cref="LmsSignerOptions.StateStoreFactory"/> to plug in a Redis/EF/HSM store instead.
    /// </summary>
    /// <param name="services">The service collection to add to.</param>
    /// <param name="configure">A delegate to configure <see cref="LmsSignerOptions"/>.</param>
    /// <returns>The same <see cref="IServiceCollection"/> for chaining.</returns>
    public static IServiceCollection AddLmsSigner(this IServiceCollection services, Action<LmsSignerOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.AddOptions<LmsSignerOptions>()
            .Configure(configure)
            .Validate(o => !string.IsNullOrWhiteSpace(o.KeyId), "LmsSignerOptions.KeyId must be set.")
            .Validate(
                o => o.StateStoreFactory is not null || !string.IsNullOrWhiteSpace(o.StateDirectory),
                "LmsSignerOptions requires either a StateDirectory or a StateStoreFactory.")
            .ValidateOnStart();

        services.AddSingleton<ILmsSigningService, HssSigningService>();
        return services;
    }

    /// <summary>
    /// Registers the signing service with an explicit custom <see cref="IStateStore"/> factory
    /// (e.g. Redis, EF Core, or an HSM-backed store). Validate the store with the conformance harness in
    /// PostQuantum.LMS.Signer.Testing before production use.
    /// </summary>
    /// <param name="services">The service collection to add to.</param>
    /// <param name="configure">A delegate to configure <see cref="LmsSignerOptions"/>.</param>
    /// <param name="storeFactory">A factory that builds the state store from the service provider.</param>
    /// <returns>The same <see cref="IServiceCollection"/> for chaining.</returns>
    public static IServiceCollection AddLmsSigner(
        this IServiceCollection services,
        Action<LmsSignerOptions> configure,
        Func<IServiceProvider, IStateStore> storeFactory)
    {
        ArgumentNullException.ThrowIfNull(configure);
        ArgumentNullException.ThrowIfNull(storeFactory);

        return services.AddLmsSigner(options =>
        {
            configure(options);
            options.StateStoreFactory = storeFactory;
        });
    }
}
