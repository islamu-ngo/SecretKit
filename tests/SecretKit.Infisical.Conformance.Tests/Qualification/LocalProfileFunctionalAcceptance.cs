using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class LocalProfileFunctionalAcceptance
{
    internal static bool Accepts(LocalNativeReport report, LocalNativeBinding expected)
    {
        NativeWorkflow.ValidateBinding(expected);
        LocalProfileConformance.ValidateReport(report, expected);
        return report.CreateEffect == DispatchEvidence.Applied && report.Cases.All(c => c.Id switch
        {
            "read" or "read-native" or "inspect" or "repeat-revision" or "selected-revision" or
            "denied-read" or "runtime-write-denied" or "create" or "update-value" or "recreation" or
            "universal-login" or "get-token" or "renew-token" or "expired-token" or "explicit-recovery" =>
                c is { Status: "passed", Reason: "observed" },
            "network" => c is { Status: "passed", Reason: "selected-origin-system-trust-and-proxy" },
            "cleanup" => c is { Status: "passed", Reason: "owned-resource-cleanup" },
            "pending-approval" => c is { Status: "unavailable", Reason: "not-observed" },
            "deployment-binding" or "actor-binding" or "policy-binding" =>
                c is { Status: "unavailable", Reason: "authoritative-proof-unavailable" },
            _ => false
        });
    }
}
