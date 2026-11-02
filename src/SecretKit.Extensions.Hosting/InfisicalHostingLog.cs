using Microsoft.Extensions.Logging;
using SecretKit.Core;

namespace SecretKit.Extensions.Hosting;

internal static partial class InfisicalHostingLog
{
    [LoggerMessage(EventId = 1, Level = LogLevel.Information,
        Message = "Infisical UniversalLogin: {Status}, {Reason}, {Dispatch}")]
    internal static partial void Authentication(ILogger logger, SecretStatus status,
        SecretFailureReason reason, DispatchEvidence dispatch);
}
