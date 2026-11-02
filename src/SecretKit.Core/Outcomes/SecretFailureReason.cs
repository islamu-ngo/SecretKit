namespace SecretKit.Core;

/// <summary>Closed, material-free failure detail; never provider prose or replay permission.</summary>
public enum SecretFailureReason
{
    /// <summary>No finer failure evidence is available.</summary>
    None,
    /// <summary>The cooperative operation budget elapsed.</summary>
    DeadlineExceeded,
    /// <summary>The selected transport could not complete the operation.</summary>
    TransportFailure,
    /// <summary>The encoded response exceeded its admitted budget.</summary>
    ResponseTooLarge,
    /// <summary>The response did not satisfy the selected contract.</summary>
    InvalidResponse,
    /// <summary>The requested reference belongs to another authority.</summary>
    AuthorityMismatch,
    /// <summary>The explicitly selected credential was unavailable.</summary>
    CredentialUnavailable,
    /// <summary>The requested contract is not supported.</summary>
    UnsupportedContract,
    /// <summary>The encoded request exceeded its admitted budget.</summary>
    RequestTooLarge,
    /// <summary>The collection exceeded an admitted selection or material limit.</summary>
    CollectionLimitExceeded
}
