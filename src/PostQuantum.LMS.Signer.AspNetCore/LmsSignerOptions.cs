namespace PostQuantum.Lms.AspNetCore;

/// <summary>
/// Configuration for the registered <see cref="ILmsSigningService"/>. Bind this from configuration or
/// set it inline in <see cref="ServiceCollectionExtensions.AddLmsSigner"/>.
/// </summary>
public sealed class LmsSignerOptions
{
    /// <summary>
    /// The logical key identifier used to create or load the signing key in the backing state store.
    /// Must be stable for the lifetime of the key — changing it points the service at a different key.
    /// </summary>
    public string KeyId { get; set; } = "default";

    /// <summary>
    /// The directory backing the crash-safe <see cref="State.FileStateStore"/> that persists signer state.
    /// This directory must live on durable, single-writer storage — see the state-safety notes in CLAUDE.md.
    /// </summary>
    public string StateDirectory { get; set; } = "lms-state";

    /// <summary>
    /// The HSS parameters used when the key is first created. Ignored once a key already exists at
    /// <see cref="KeyId"/> (the persisted parameters win). Defaults to <see cref="HssParameters.FirmwareDefault"/>.
    /// </summary>
    public HssParameters Parameters { get; set; } = HssParameters.FirmwareDefault;
}
