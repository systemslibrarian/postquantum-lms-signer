using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using PostQuantum.Lms.State;

namespace PostQuantum.Lms.AspNetCore;

/// <summary>
/// The default <see cref="ILmsSigningService"/>: lazily creates-or-loads a single <see cref="HssSigner"/>
/// backed by an <see cref="IStateStore"/> (a <see cref="FileStateStore"/> by default, or a custom store
/// via <see cref="LmsSignerOptions.StateStoreFactory"/>), serializing all access through a semaphore.
/// </summary>
/// <remarks>
/// Initialization is deferred until the first call so registration never performs I/O. The signer itself
/// persists state before releasing a signature, so this service adds single-instance ownership, thread
/// coordination, and an operator-facing low-budget warning. See <c>docs/operations.md</c>.
/// </remarks>
public sealed class HssSigningService : ILmsSigningService, IDisposable
{
    private readonly IServiceProvider _services;
    private readonly LmsSignerOptions _options;
    private readonly ILogger _logger;
    private readonly SemaphoreSlim _gate = new(1, 1);

    private IStateStore? _store;
    private HssSigner? _signer;
    private bool _disposed;

    /// <summary>Creates the signing service.</summary>
    /// <param name="services">The application service provider (used to build a custom state store, if configured).</param>
    /// <param name="options">The configured <see cref="LmsSignerOptions"/>.</param>
    /// <param name="loggerFactory">An optional logger factory; falls back to a no-op logger when unavailable.</param>
    public HssSigningService(IServiceProvider services, IOptions<LmsSignerOptions> options, ILoggerFactory? loggerFactory = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(options);
        _services = services;
        _options = options.Value;
        _logger = (loggerFactory ?? NullLoggerFactory.Instance).CreateLogger<HssSigningService>();
    }

    /// <inheritdoc />
    public async Task<byte[]> SignAsync(byte[] message, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(message);
        ObjectDisposedException.ThrowIf(_disposed, this);

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            HssSigner signer = await EnsureSignerAsync(cancellationToken).ConfigureAwait(false);
            byte[] signature = await signer.SignAsync(message, cancellationToken).ConfigureAwait(false);
            WarnIfBudgetLow(signer.SignaturesRemaining);
            return signature;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <inheritdoc />
    public byte[] PublicKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _gate.Wait();
        try
        {
            return EnsureSignerAsync(CancellationToken.None).GetAwaiter().GetResult().PublicKey();
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <inheritdoc />
    public long SignaturesRemaining
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            _gate.Wait();
            try
            {
                return EnsureSignerAsync(CancellationToken.None).GetAwaiter().GetResult().SignaturesRemaining;
            }
            finally
            {
                _gate.Release();
            }
        }
    }

    private void WarnIfBudgetLow(long remaining)
    {
        if (_options.WarnWhenRemainingAtOrBelow > 0 && remaining <= _options.WarnWhenRemainingAtOrBelow)
        {
            _logger.LogWarning(
                "HSS key '{KeyId}' is running low: {Remaining} signatures remaining. Plan key rotation before exhaustion.",
                _options.KeyId, remaining);
        }
    }

    // Caller must hold _gate.
    private async Task<HssSigner> EnsureSignerAsync(CancellationToken cancellationToken)
    {
        if (_signer is not null)
        {
            return _signer;
        }

        _store ??= _options.StateStoreFactory?.Invoke(_services) ?? new FileStateStore(_options.StateDirectory);

        LoadedState? existing = await _store.LoadAsync(_options.KeyId, cancellationToken).ConfigureAwait(false);
        if (existing is null)
        {
            _logger.LogInformation("Creating new HSS signing key '{KeyId}'.", _options.KeyId);
            _signer = await HssSigner.CreateAsync(_options.Parameters, _store, _options.KeyId, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            _logger.LogInformation("Loading existing HSS signing key '{KeyId}'.", _options.KeyId);
            _signer = await HssSigner.LoadAsync(_store, _options.KeyId, cancellationToken).ConfigureAwait(false);
        }

        return _signer;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _signer?.Dispose();
        _gate.Dispose();
    }
}
