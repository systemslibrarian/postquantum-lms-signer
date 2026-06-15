using PostQuantum.Lms.State;

namespace PostQuantum.Lms.AspNetCore;

/// <summary>
/// Configuration for the registered <see cref="ILmsSigningService"/>. Bind this from configuration or
/// set it inline in <see cref="ServiceCollectionExtensions.AddLmsSigner(Microsoft.Extensions.DependencyInjection.IServiceCollection, System.Action{LmsSignerOptions})"/>.
/// </summary>
public sealed class LmsSignerOptions
{
    /// <summary>
    /// The logical key identifier used to create or load the signing key in the backing state store.
    /// Must be stable for the lifetime of the key — changing it points the service at a different key.
    /// </summary>
    public string KeyId { get; set; } = "default";

    /// <summary>
    /// The directory backing the default crash-safe <see cref="FileStateStore"/>. Ignored when
    /// <see cref="StateStoreFactory"/> is set. Must live on durable, single-writer storage — see
    /// <c>docs/operations.md</c> and the state-safety notes in the README.
    /// </summary>
    public string StateDirectory { get; set; } = "lms-state";

    /// <summary>
    /// Optional factory for a custom <see cref="IStateStore"/> (e.g. Redis, EF Core, or an HSM-backed
    /// store). When set, it takes precedence over <see cref="StateDirectory"/>. Validate any custom store
    /// with the conformance harness in PostQuantum.LMS.Signer.Testing before trusting a key to it.
    /// </summary>
    public Func<IServiceProvider, IStateStore>? StateStoreFactory { get; set; }

    /// <summary>
    /// The HSS parameters used when the key is first created. Ignored once a key already exists at
    /// <see cref="KeyId"/> (the persisted parameters win). Defaults to <see cref="HssParameters.FirmwareDefault"/>.
    /// </summary>
    public HssParameters Parameters { get; set; } = HssParameters.FirmwareDefault;

    /// <summary>
    /// When the remaining signature budget falls at or below this value, the service logs a warning after
    /// each signature so operators can plan key rotation. Set to 0 to disable. Defaults to 1024.
    /// </summary>
    public long WarnWhenRemainingAtOrBelow { get; set; } = 1024;
}
