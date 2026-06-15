using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using PostQuantum.Lms.State;

namespace PostQuantum.Lms.AspNetCore;

/// <summary>
/// The default <see cref="ILmsSigningService"/>: lazily creates-or-loads a single <see cref="HssSigner"/>
/// backed by a <see cref="FileStateStore"/>, and serializes all access through a <see cref="SemaphoreSlim"/>.
/// </summary>
/// <remarks>
/// Initialization is deferred until the first call so that registration never performs I/O. The signer
/// itself already persists state before releasing a signature, so this service only adds single-instance
/// ownership and thread coordination.
/// </remarks>
public sealed class HssSigningService : ILmsSigningService, IDisposable
{
    private readonly LmsSignerOptions _options;
    private readonly ILogger _logger;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly FileStateStore _store;

    private HssSigner? _signer;
    private bool _disposed;

    /// <summary>Creates the signing service from bound options.</summary>
    /// <param name="options">The configured <see cref="LmsSignerOptions"/>.</param>
    /// <param name="loggerFactory">An optional logger factory; falls back to a no-op logger when unavailable.</param>
    public HssSigningService(IOptions<LmsSignerOptions> options, ILoggerFactory? loggerFactory = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options.Value;
        _logger = (loggerFactory ?? NullLoggerFactory.Instance).CreateLogger<HssSigningService>();
        _store = new FileStateStore(_options.StateDirectory);
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
            return await signer.SignAsync(message, cancellationToken).ConfigureAwait(false);
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
            HssSigner signer = EnsureSignerAsync(CancellationToken.None).GetAwaiter().GetResult();
            return signer.PublicKey();
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
                HssSigner signer = EnsureSignerAsync(CancellationToken.None).GetAwaiter().GetResult();
                return signer.SignaturesRemaining;
            }
            finally
            {
                _gate.Release();
            }
        }
    }

    // Caller must hold _gate.
    private async Task<HssSigner> EnsureSignerAsync(CancellationToken cancellationToken)
    {
        if (_signer is not null)
        {
            return _signer;
        }

        LoadedState? existing = await _store.LoadAsync(_options.KeyId, cancellationToken).ConfigureAwait(false);
        if (existing is null)
        {
            _logger.LogInformation("Creating new HSS signing key '{KeyId}' in '{Directory}'.", _options.KeyId, _options.StateDirectory);
            _signer = await HssSigner.CreateAsync(_options.Parameters, _store, _options.KeyId, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            _logger.LogInformation("Loading existing HSS signing key '{KeyId}' from '{Directory}'.", _options.KeyId, _options.StateDirectory);
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
