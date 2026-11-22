using Azure;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault;

internal static class AzureFailureClassification
{
    internal static bool IsDefinitiveMutationRejection(int status) => status is
        (int)System.Net.HttpStatusCode.BadRequest or (int)System.Net.HttpStatusCode.Forbidden or
        (int)System.Net.HttpStatusCode.NotFound or (int)System.Net.HttpStatusCode.Conflict;

    internal static SecretStatus Status(Exception exception) => exception switch
    {
        RequestFailedException failure => Status(failure.Status),
        HttpRequestException => SecretStatus.Unavailable,
        _ => SecretStatus.Unknown
    };

    internal static SecretStatus Status(int status) => status switch
    {
        (int)System.Net.HttpStatusCode.Unauthorized or (int)System.Net.HttpStatusCode.Forbidden => SecretStatus.Denied,
        (int)System.Net.HttpStatusCode.NotFound => SecretStatus.Absent,
        (int)System.Net.HttpStatusCode.Conflict => SecretStatus.Conflict,
        (int)System.Net.HttpStatusCode.TooManyRequests => SecretStatus.Throttled,
        (int)System.Net.HttpStatusCode.BadRequest => SecretStatus.Invalid,
        0 or >= (int)System.Net.HttpStatusCode.InternalServerError => SecretStatus.Unavailable,
        _ => SecretStatus.Unknown
    };
}
