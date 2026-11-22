namespace SecretKit.AzureKeyVault.Management;

internal readonly record struct ArmCallTarget(string Path, ArmMethodContract Contract)
{
    internal static ArmCallTarget At(ArmMethodContract contract, ManagementScope scope) =>
        new(scope.ResourceId, contract);

    // Keep the caller's complete SDK-built resource ID as the authority. Take only
    // the child/action suffix from the pinned method, never from a response URL.
    internal static ArmCallTarget Below(ArmMethodContract contract, ManagementScope scope, string? operationKind = null)
    {
        string parent = scope.ResourceId;
        string template = contract.RequestPath;
        if (template.StartsWith("/{scope}/", StringComparison.Ordinal))
        {
            string providerScope = scope is NotificationScope notification ? notification.Vault.ResourceId : parent;
            template = providerScope + template["/{scope}".Length..];
        }

        var segments = template.Split('/');
        var prefix = parent.Split('/');
        if (segments.Length <= prefix.Length) throw new ControlledTransport.BoundaryException();
        for (int i = 0; i < prefix.Length; i++)
        {
            if (!(segments[i].StartsWith('{') && segments[i].EndsWith('}')) &&
                !segments[i].Equals(prefix[i], StringComparison.OrdinalIgnoreCase))
                throw new ControlledTransport.BoundaryException();
        }
        var suffix = segments[prefix.Length..];
        for (int i = 0; i < suffix.Length; i++)
        {
            if (suffix[i] == "{operationKind}" && operationKind is not null)
            {
                suffix[i] = ManagementScope.Segment(operationKind);
                operationKind = null;
            }
            else if (suffix[i].Contains('{')) throw new ControlledTransport.BoundaryException();
        }
        if (operationKind is not null) throw new ControlledTransport.BoundaryException();
        return new(parent + "/" + string.Join('/', suffix), contract);
    }
}
