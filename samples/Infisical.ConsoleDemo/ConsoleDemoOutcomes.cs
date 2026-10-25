using SecretKit.Core;
using SecretKit.Infisical;

namespace SecretKit.Samples.Infisical.ConsoleDemo;

internal static class ConsoleDemoOutcomes
{
    internal static int WriteFailure(SecretStatus status, MutationReceipt? receipt = null)
    {
        int exitCode = status switch
        {
            SecretStatus.Invalid => 2,
            SecretStatus.Pending => 3,
            _ => 4
        };

        return DemoOutput.Write(status.ToString().ToLowerInvariant(), exitCode, receipt?.Evidence);
    }

    internal static int WriteChange(SecretOutcome<InfisicalStaticChange> result, MutationReceipt receipt)
    {
        if (!result.IsSuccess)
        {
            return WriteFailure(result.Status, receipt);
        }

        InfisicalStaticChange change = result.Value;
        return change.Disposition switch
        {
            InfisicalChangeDisposition.Applied =>
                DemoOutput.Write("applied", 0, receipt.Evidence, change.Version),
            InfisicalChangeDisposition.SubmittedForApproval =>
                DemoOutput.Write("pending", 3, receipt.Evidence),
            _ => DemoOutput.Write("unknown", 4, receipt.Evidence)
        };
    }
}
