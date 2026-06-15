namespace PostQuantum.Lms;

/// <summary>Base type for all errors raised by the LMS/HSS signer.</summary>
public class LmsException : Exception
{
    /// <summary>Initializes a new instance with a message.</summary>
    public LmsException(string message) : base(message) { }

    /// <summary>Initializes a new instance with a message and inner exception.</summary>
    public LmsException(string message, Exception innerException) : base(message, innerException) { }
}

/// <summary>
/// Thrown when persisted signer state is missing, corrupt, or fails its integrity check.
/// Continuing past this error risks one-time-key reuse, so it is always fatal to the operation.
/// </summary>
public sealed class LmsStateException : LmsException
{
    /// <summary>Initializes a new instance with a message.</summary>
    public LmsStateException(string message) : base(message) { }

    /// <summary>Initializes a new instance with a message and inner exception.</summary>
    public LmsStateException(string message, Exception innerException) : base(message, innerException) { }
}

/// <summary>
/// Thrown when the key has produced every signature its parameters allow. The key is permanently
/// spent — generate a new key pair. This is a normal, expected end-of-life condition, not a bug.
/// </summary>
public sealed class LmsKeyExhaustedException : LmsException
{
    /// <summary>Initializes a new instance.</summary>
    public LmsKeyExhaustedException(string message) : base(message) { }
}

/// <summary>
/// Thrown when the signer detects an attempt to reuse a one-time key index — the single most
/// dangerous failure mode for stateful hash-based signatures. This is the anti-reuse guard firing;
/// it indicates state rollback (e.g. a restored VM snapshot or backup), a cloned key, or concurrent
/// signers sharing one key without a coordinating store. <b>Never</b> swallow this exception.
/// </summary>
public sealed class LmsStateReuseException : LmsException
{
    /// <summary>The one-time key index whose reuse was prevented.</summary>
    public long Index { get; }

    /// <summary>Initializes a new instance for the offending <paramref name="index"/>.</summary>
    public LmsStateReuseException(long index, string message) : base(message) => Index = index;
}
