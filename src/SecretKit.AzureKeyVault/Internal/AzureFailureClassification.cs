using Azure;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault;

internal static class AzureFailureClassification
{
    internal static SecretStatus Status(Exception exception) => exception switch
    {
        RequestFailedException { Status: 401 or 403 } => SecretStatus.Denied,
        RequestFailedException { Status: 404 } => SecretStatus.Absent,
        RequestFailedException { Status: 409 } => SecretStatus.Conflict,
        RequestFailedException { Status: 429 } => SecretStatus.Throttled,
        RequestFailedException { Status: 400 } => SecretStatus.Invalid,
        RequestFailedException { Status: 0 or >= 500 } or HttpRequestException => SecretStatus.Unavailable,
        _ => SecretStatus.Unknown
    };
}
