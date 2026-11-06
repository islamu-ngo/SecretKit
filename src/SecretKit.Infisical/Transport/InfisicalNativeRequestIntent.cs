namespace SecretKit.Infisical;

// Expected coordinates come from the typed operation, never from the request builder.
internal sealed class InfisicalNativeRequestIntent
{
    private readonly HttpMethod _method;
    private readonly string _escapedPath;
    private readonly KeyValuePair<string, string>[] _query;

    internal InfisicalNativeRequestIntent(HttpMethod method, string escapedPath,
        IReadOnlyDictionary<string, string>? query = null)
    {
        _method = method;
        _escapedPath = escapedPath;
        _query = query?.ToArray() ?? [];
    }

    // The caller owns request/content disposal on either outcome.
    internal bool TryBind(HttpRequestMessage request, Uri origin)
    {
        if (_method is null || request.Method != _method || !ValidPath(_escapedPath) ||
            !origin.IsAbsoluteUri || origin.Scheme is not ("https" or "http") ||
            origin.UserInfo.Length != 0 || !TryCoordinates(origin, out string originPath, out string originQuery) ||
            originPath != "/" || originQuery.Length != 0 || origin.Query.Length != 0 ||
            request.RequestUri is not { } selected ||
            !TryCoordinates(selected, out string path, out string query) ||
            !ValidPath(path) || path != _escapedPath)
            return false;

        if (!Uri.TryCreate(origin, selected, out Uri? absolute) ||
            absolute.Scheme != origin.Scheme || absolute.Host != origin.Host ||
            absolute.Port != origin.Port || absolute.UserInfo.Length != 0 ||
            absolute.Fragment.Length != 0 || absolute.AbsolutePath != _escapedPath)
            return false;

        var expected = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var pair in _query)
        {
            if (string.IsNullOrEmpty(pair.Key) || pair.Key.Any(char.IsControl) ||
                pair.Value is null || pair.Value.Any(char.IsControl) ||
                !expected.TryAdd(pair.Key, pair.Value))
                return false;
        }
        var actual = new Dictionary<string, string>(StringComparer.Ordinal);
        if (query.Length != 0)
        {
            foreach (string component in query.Split('&'))
            {
                string[] pair = component.Split('=', 2);
                if (pair.Length != 2)
                    return false;
                string key = Uri.UnescapeDataString(pair[0]);
                string value = Uri.UnescapeDataString(pair[1]);
                if (!actual.TryAdd(key, value))
                    return false;
            }
        }
        if (actual.Count != expected.Count ||
            expected.Any(pair => !actual.TryGetValue(pair.Key, out string? value) || value != pair.Value))
            return false;

        request.RequestUri = absolute;
        return true;
    }

    private static bool TryCoordinates(Uri uri, out string path, out string query)
    {
        path = query = "";
        string original = uri.OriginalString;
        if (!uri.IsWellFormedOriginalString() || original.Contains('#') || original.Contains('\\') ||
            original.Any(char.IsControl) || !ValidEscapes(original))
            return false;

        int start = 0;
        if (uri.IsAbsoluteUri)
        {
            int separator = original.IndexOf("://", StringComparison.Ordinal);
            if (separator < 0)
                return false;
            int authorityStart = separator + 3;
            start = original.IndexOfAny(['/', '?'], authorityStart);
            int authorityEnd = start < 0 ? original.Length : start;
            if (original.AsSpan(authorityStart, authorityEnd - authorityStart).Contains('@'))
                return false;
            if (start < 0)
                start = original.Length;
        }
        else if (original.StartsWith("//", StringComparison.Ordinal))
            return false;

        int queryStart = original.IndexOf('?', start);
        path = queryStart < 0 ? original[start..] : original[start..queryStart];
        if (path.Length == 0)
            path = "/";
        else if (!path.StartsWith('/'))
            path = "/" + path;
        query = queryStart < 0 ? "" : original[(queryStart + 1)..];
        return true;
    }

    private static bool ValidPath(string path)
    {
        if (string.IsNullOrEmpty(path) || !path.StartsWith('/') ||
            path.StartsWith("//", StringComparison.Ordinal) || path.Contains('?') || path.Contains('#') ||
            path.Contains('\\') || !ValidEscapes(path))
            return false;
        foreach (string segment in path.Split('/'))
        {
            string decoded = Uri.UnescapeDataString(segment);
            if (decoded.Any(char.IsControl) || decoded.Contains('\\') ||
                decoded.Split('/').Any(part => part is "." or "..") ||
                Uri.EscapeDataString(decoded) != segment)
                return false;
        }
        return true;
    }

    private static bool ValidEscapes(string value)
    {
        for (int index = 0; index < value.Length; index++)
        {
            if (value[index] != '%')
                continue;
            if (index + 2 >= value.Length || !Uri.IsHexDigit(value[index + 1]) ||
                !Uri.IsHexDigit(value[index + 2]))
                return false;
            index += 2;
        }
        return true;
    }
}
