using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

internal interface IInfisicalRotationIdentityCatalogObserver
{
    ValueTask<RotationIdentityCatalogFacts> InspectIdentityCatalogAsync(RotationBackendCoordinate coordinate,
        IReadOnlyList<string> usernames, CancellationToken token);
}

internal sealed record RotationIdentityCatalogFacts(RotationBackendCoordinate Coordinate, string[] RequestedUsernames,
    MysqlRotationCatalogFacts? Mysql, MssqlRotationCatalogFacts? Mssql)
{
    public override string ToString() => "[RotationIdentityCatalogFacts]";
}

internal sealed record MysqlRotationCatalogFacts(string Database, bool AllHostsComplete,
    MysqlRotationAccountFacts[] Accounts, MysqlPasswordPolicyFacts PasswordPolicy)
{
    public override string ToString() => "[MysqlRotationCatalogFacts]";
}

internal sealed record MysqlRotationAccountFacts(string Username, string Host, string AuthenticationPlugin)
{
    public override string ToString() => "[MysqlRotationAccountFacts]";
}

internal sealed record MysqlPasswordPolicyFacts(bool IsComplete, string[] ActiveValidationPlugins,
    string[] InstalledValidationComponents, int? Policy, int? MinimumLength, bool? CheckUserName,
    int? MixedCaseCount, int? NumberCount, int? SpecialCharCount, string? DictionaryFile,
    int? ChangedCharactersPercentage)
{
    public override string ToString() => "[MysqlPasswordPolicyFacts]";
}

internal sealed record MssqlRotationCatalogFacts(string Database, bool ServerPrincipalsComplete,
    bool DatabasePrincipalsComplete, MssqlRotationLoginFacts[] ServerPrincipals,
    MssqlRotationUserFacts[] DatabasePrincipals)
{
    public override string ToString() => "[MssqlRotationCatalogFacts]";
}

internal sealed record MssqlRotationLoginFacts(string Name, byte[] Sid, string TypeDescription,
    bool? IsPolicyChecked, bool? IsExpirationChecked, bool IsDisabled)
{
    public override string ToString() => "[MssqlRotationLoginFacts]";
}

internal sealed record MssqlRotationUserFacts(string Name, byte[] Sid, string TypeDescription,
    string AuthenticationTypeDescription)
{
    public override string ToString() => "[MssqlRotationUserFacts]";
}

internal sealed record RotationCredentialIdentity(MysqlCredentialIdentity? Mysql, MssqlCredentialIdentity? Mssql)
{
    public override string ToString() => "[RotationCredentialIdentity]";
}

internal sealed record MysqlCredentialIdentity(string CurrentUser, string Database)
{
    public override string ToString() => "[MysqlCredentialIdentity]";
}

internal sealed record MssqlCredentialIdentity(string OriginalLogin, byte[] OriginalLoginSid,
    string ExecutionLogin, byte[] ExecutionLoginSid, string DatabaseUser, byte[] DatabaseUserSid, string Database)
{
    public override string ToString() => "[MssqlCredentialIdentity]";
}

internal static class RotationSqlIdentityEvidence
{
    internal static bool Bound(RotationIdentityCatalogFacts facts, RotationBackendCoordinate coordinate,
        IReadOnlyList<string> usernames)
    {
        if (facts is null || coordinate is null || usernames is null || usernames.Count != 2 ||
            usernames.Any(string.IsNullOrEmpty) || usernames.Distinct(StringComparer.Ordinal).Count() != 2 ||
            facts.Coordinate != coordinate || facts.RequestedUsernames is null ||
            !facts.RequestedUsernames.SequenceEqual(usernames, StringComparer.Ordinal))
            return false;
        if (coordinate.Profile == InfisicalRotationProfile.MysqlCredentials)
        {
            if (facts.Mssql is not null || facts.Mysql is not { AllHostsComplete: true } mysql ||
                mysql.Database != coordinate.Database || mysql.Accounts is null ||
                mysql.PasswordPolicy is not { } policy || !Discovery(policy.ActiveValidationPlugins) ||
                !Discovery(policy.InstalledValidationComponents))
                return false;
            return mysql.Accounts.All(row => row is not null &&
                    usernames.Contains(row.Username, StringComparer.Ordinal) &&
                    !string.IsNullOrEmpty(row.Host) && !string.IsNullOrEmpty(row.AuthenticationPlugin)) &&
                mysql.Accounts.Select(row => (row.Username, row.Host)).Distinct().Count() == mysql.Accounts.Length;
        }
        if (coordinate.Profile == InfisicalRotationProfile.MssqlCredentials)
        {
            if (facts.Mysql is not null || facts.Mssql is not
                { ServerPrincipalsComplete: true, DatabasePrincipalsComplete: true } mssql ||
                mssql.Database != coordinate.Database || mssql.ServerPrincipals is null ||
                mssql.DatabasePrincipals is null)
                return false;
            return mssql.ServerPrincipals.All(row => row is not null &&
                    usernames.Contains(row.Name, StringComparer.Ordinal) && row.Sid is { Length: <= 85 } &&
                    !string.IsNullOrEmpty(row.TypeDescription)) &&
                mssql.DatabasePrincipals.All(row => row is not null &&
                    usernames.Contains(row.Name, StringComparer.Ordinal) && row.Sid is { Length: <= 85 } &&
                    !string.IsNullOrEmpty(row.TypeDescription) &&
                    !string.IsNullOrEmpty(row.AuthenticationTypeDescription)) &&
                mssql.ServerPrincipals.Select(row => row.Name).Distinct(StringComparer.Ordinal).Count() ==
                    mssql.ServerPrincipals.Length &&
                mssql.DatabasePrincipals.Select(row => row.Name).Distinct(StringComparer.Ordinal).Count() ==
                    mssql.DatabasePrincipals.Length;
        }
        return false;
    }

    private static bool Discovery(string[] values) => values is not null && values.All(v => !string.IsNullOrEmpty(v)) &&
        values.Distinct(StringComparer.Ordinal).Count() == values.Length;

    internal static bool IsAbsent(RotationIdentityCatalogFacts facts) =>
        Bound(facts, facts.Coordinate, facts.RequestedUsernames) &&
        (facts.Mysql is { Accounts.Length: 0 } ||
            facts.Mssql is { ServerPrincipals.Length: 0, DatabasePrincipals.Length: 0 });

    internal static bool PolicyEstablished(RotationIdentityCatalogFacts facts)
    {
        if (!Bound(facts, facts.Coordinate, facts.RequestedUsernames)) return false;
        if (facts.Mssql is not null) return true;
        var policy = facts.Mysql!.PasswordPolicy;
        if (!policy.IsComplete) return false;
        bool plugin = policy.ActiveValidationPlugins.SequenceEqual(["validate_password"], StringComparer.Ordinal) &&
            policy.InstalledValidationComponents.Length == 0;
        bool component = policy.ActiveValidationPlugins.Length == 0 &&
            policy.InstalledValidationComponents.SequenceEqual(["file://component_validate_password"], StringComparer.Ordinal);
        // Observed implementations outside the prepared allowlist are incompatible.
        // A recognized implementation still needs actual applicable settings;
        // completeness alone cannot turn null settings into a measured strong policy.
        if (!plugin && !component) return true;
        return policy.Policy is 0 or 1 or 2 && policy.MinimumLength is >= 0 &&
            policy.CheckUserName is not null && policy.MixedCaseCount is >= 0 &&
            policy.NumberCount is >= 0 && policy.SpecialCharCount is >= 0 && policy.DictionaryFile is not null &&
            (component ? policy.ChangedCharactersPercentage is >= 0 :
                policy.ChangedCharactersPercentage is null or >= 0);
    }

    internal static bool PolicyCompatible(RotationIdentityCatalogFacts facts)
    {
        if (!Bound(facts, facts.Coordinate, facts.RequestedUsernames)) return false;
        if (facts.Mssql is not null) return true;
        MysqlPasswordPolicyFacts policy = facts.Mysql!.PasswordPolicy;
        if (!policy.IsComplete) return false;
        if (policy.ActiveValidationPlugins.Length == 0 && policy.InstalledValidationComponents.Length == 0)
            return policy.Policy is null && policy.MinimumLength is null && policy.CheckUserName is null &&
                policy.MixedCaseCount is null && policy.NumberCount is null && policy.SpecialCharCount is null &&
                policy.DictionaryFile is null && policy.ChangedCharactersPercentage is null;
        bool plugin = policy.ActiveValidationPlugins.SequenceEqual(["validate_password"], StringComparer.Ordinal) &&
            policy.InstalledValidationComponents.Length == 0;
        bool component = policy.ActiveValidationPlugins.Length == 0 &&
            policy.InstalledValidationComponents.SequenceEqual(["file://component_validate_password"], StringComparer.Ordinal);
        // The owned witness deliberately includes weak passwords. Unknown validators,
        // stronger policies, dictionaries, and username/change checks cannot qualify it.
        // These are observations of the prepared service, never permission to edit its policy.
        return (plugin || component) && policy.Policy == 0 && policy.MinimumLength is >= 1 and <= 24 &&
            policy.CheckUserName == false && policy.MixedCaseCount is >= 0 && policy.NumberCount is >= 0 &&
            policy.SpecialCharCount is >= 0 && policy.DictionaryFile == "" &&
            (component ? policy.ChangedCharactersPercentage == 0 :
                policy.ChangedCharactersPercentage is null or 0);
    }

    internal static bool Owned(RotationIdentityCatalogFacts facts, IReadOnlyList<string> usernames)
    {
        if (!Bound(facts, facts.Coordinate, usernames)) return false;
        if (facts.Mysql is { } mysql)
            return mysql.Accounts.Length == 2 &&
                mysql.Accounts.All(row => row.Host == "%" &&
                    row.AuthenticationPlugin is "caching_sha2_password" or "mysql_native_password");
        MssqlRotationCatalogFacts mssql = facts.Mssql!;
        if (mssql.ServerPrincipals.Length != 2 || mssql.DatabasePrincipals.Length != 2 ||
            mssql.ServerPrincipals.Any(row => row.TypeDescription != "SQL_LOGIN" ||
                row.IsPolicyChecked != false || row.IsExpirationChecked != false || row.IsDisabled ||
                row.Sid.Length == 0) ||
            mssql.DatabasePrincipals.Any(row => row.TypeDescription != "SQL_USER" ||
                row.AuthenticationTypeDescription != "INSTANCE" || row.Sid.Length == 0))
            return false;
        return mssql.ServerPrincipals.All(login => mssql.DatabasePrincipals.Single(user => user.Name == login.Name)
                .Sid.AsSpan().SequenceEqual(login.Sid)) &&
            !mssql.ServerPrincipals[0].Sid.AsSpan().SequenceEqual(mssql.ServerPrincipals[1].Sid);
    }

    internal static bool SameMysqlPolicy(RotationIdentityCatalogFacts first, RotationIdentityCatalogFacts second)
    {
        if (first.Mysql?.PasswordPolicy is not { } a || second.Mysql?.PasswordPolicy is not { } b ||
            !Discovery(a.ActiveValidationPlugins) || !Discovery(b.ActiveValidationPlugins) ||
            !Discovery(a.InstalledValidationComponents) || !Discovery(b.InstalledValidationComponents))
            return false;
        return a.IsComplete == b.IsComplete &&
            a.ActiveValidationPlugins.SequenceEqual(b.ActiveValidationPlugins, StringComparer.Ordinal) &&
            a.InstalledValidationComponents.SequenceEqual(b.InstalledValidationComponents, StringComparer.Ordinal) &&
            a.Policy == b.Policy && a.MinimumLength == b.MinimumLength && a.CheckUserName == b.CheckUserName &&
            a.MixedCaseCount == b.MixedCaseCount && a.NumberCount == b.NumberCount &&
            a.SpecialCharCount == b.SpecialCharCount && a.DictionaryFile == b.DictionaryFile &&
            a.ChangedCharactersPercentage == b.ChangedCharactersPercentage;
    }
}
