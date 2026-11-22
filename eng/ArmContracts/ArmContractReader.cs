using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace SecretKit.Build;

internal sealed record ArmMethod(string RequestPath, string ApiVersion);

internal static class ArmContractReader
{
    internal static ArmMethod Select(XDocument document, string member, string operation)
    {
        var entries = document.Root?.Element("members")?.Elements("member")
            .Where(m => (string?)m.Attribute("name") == member).ToArray();
        if (entries?.Length != 1)
            throw new InvalidDataException($"Missing or ambiguous SDK member: {member}");

        List<ArmMethod> matches = [];
        foreach (var list in entries[0].Elements("summary").Elements("list"))
        {
            string? path = null, id = null, version = null;
            void Finish()
            {
                if (path is null && id is null && version is null) return;
                if (path is null || id is null || version is null)
                    throw new InvalidDataException($"Incomplete SDK operation: {member}");
                if (id == operation) matches.Add(new(path, version));
                path = id = version = null;
            }
            foreach (var item in list.Elements("item"))
            {
                string label = (item.Element("term")?.Value ?? "").Trim();
                // Some Microsoft generators punctuate both the term and its value.
                bool punctuated = label.EndsWith('.');
                string field = punctuated ? label[..^1] : label;
                if (field is not ("Request Path" or "Operation Id" or "Default Api Version")) continue;
                var description = item.Elements("description").Single();
                string value = description.Value.Trim();
                if (description.HasElements || (punctuated && !value.EndsWith('.')))
                    throw new InvalidDataException($"Malformed SDK {field}: {member}");
                if (punctuated) value = value[..^1];
                switch (field)
                {
                    case "Request Path":
                        Finish();
                        if (!Regex.IsMatch(value, @"\A/(?:[A-Za-z0-9_.-]+|\{[A-Za-z0-9_]+\})(?:/(?:[A-Za-z0-9_.-]+|\{[A-Za-z0-9_]+\}))*\z") ||
                            value.Split('/').Any(s => s is "." or ".."))
                            throw new InvalidDataException($"Invalid relative SDK request path: {member}");
                        path = value;
                        break;
                    case "Operation Id" when id is null && value.Length > 0: id = value; break;
                    case "Default Api Version" when version is null && Regex.IsMatch(value, @"\A[0-9A-Za-z][0-9A-Za-z.-]*\z"):
                        version = value;
                        break;
                    default: throw new InvalidDataException($"Invalid or duplicate SDK {field}: {member}");
                }
            }
            Finish();
        }
        return matches.Count == 1 ? matches[0] :
            throw new InvalidDataException($"Missing or ambiguous SDK operation {operation}: {member}");
    }

    internal static void VerifyLock(string version, string hash, string lockedVersion, string lockedHash)
    {
        if (version.Length == 0 || hash.Length == 0 || version != lockedVersion || hash != lockedHash)
            throw new InvalidDataException("SDK package version or content hash differs from the lock.");
    }

    internal static void WriteChanged(string file, string text)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(text);
        if (File.Exists(file) && File.ReadAllBytes(file).AsSpan().SequenceEqual(bytes)) return;
        string temporary = file + "." + Guid.NewGuid().ToString("N");
        try
        {
            File.WriteAllBytes(temporary, bytes);
            File.Move(temporary, file, true);
        }
        finally { File.Delete(temporary); }
    }
}
