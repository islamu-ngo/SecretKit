using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace SecretKit.Infisical.Conformance.Tests;

// Real local SQLite execution under a native authorizer, with a separate
// credential catalog and private attestation key. This is CONTROLLED evidence,
// not PostgreSQL/MySQL login or native Infisical qualification. No server,
// package, provider provisioning or external database is required.
internal sealed class InfisicalMetadataPermissionSqlBackend : IDisposable
{
    private readonly ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly MetadataPermissionPin pin;
    private readonly Dictionary<Guid, (string Actor, string Project)> leases = [];
    private readonly string row;
    private readonly string fault;
    private IntPtr database;
    private long sequence;
    internal MetadataPermissionPin Pin => pin;
    internal string ProtectedRowHash => MetadataPermissionContract.Hash(row);
    internal int Remaining
    {
        get
        {
            int count = -1;
            Sqlite.RowCallback rowCount = (_, _, values, _) =>
            {
                count = int.Parse(Marshal.PtrToStringUTF8(Marshal.ReadIntPtr(values))!);
                return 0;
            };
            Execute("SELECT (SELECT count(*) FROM credentials) + (SELECT count(*) FROM protected_data);", rowCount);
            return count;
        }
    }
    internal InfisicalMetadataPermissionSqlBackend(string fault)
    {
        this.fault = fault;
        pin = new(MetadataPermissionJournal.Backend, "sql-writer", "sql-native-channel", "metadata-sql-v1",
            Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()));
        row = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        MetadataPermissionContract.Require(Sqlite.Open(":memory:", out database) == 0, "missing-prerequisite");
        Execute("CREATE TABLE credentials (lease TEXT PRIMARY KEY, hash TEXT NOT NULL);" +
            "CREATE TABLE protected_data (value TEXT NOT NULL);");
    }
    internal void Bootstrap() => Execute("INSERT INTO protected_data VALUES ('" + row + "');");
    internal void Issue(Guid lease, string materialHash, string actor, string project)
    {
        leases.Add(lease, (actor, project));
        Execute("INSERT INTO credentials VALUES ('" + lease.ToString("N") + "','" + materialHash + "');");
    }
    internal MetadataPermissionSigned<MetadataPermissionBackend> Measure(MetadataPermissionRoot root,
        string window, Guid lease, string username, string password, MetadataPermissionAction action)
    {
        MetadataPermissionContract.Require(leases.TryGetValue(lease, out var owner));
        string hash = MetadataPermissionContract.MaterialHash(username, password);
        bool authenticated = false;
        Sqlite.RowCallback match = (_, _, _, _) => { authenticated = true; return 0; };
        Execute("SELECT lease FROM credentials WHERE lease='" + lease.ToString("N") + "' AND hash='" + hash + "';", match);
        bool canWrite = fault == "unauthorized-broad-action";
        Sqlite.Authorizer authorize = (_, code, _, _, _, _) =>
            !authenticated ? 1 : code is 20 or 21 || canWrite ? 0 : 1; // SQLITE_READ / SQLITE_SELECT only
        MetadataPermissionContract.Require(Sqlite.SetAuthorizer(database, authorize, IntPtr.Zero) == 0);
        string selected = "";
        Sqlite.RowCallback capture = (_, count, values, _) =>
        {
            if (count == 1) selected = Marshal.PtrToStringUTF8(Marshal.ReadIntPtr(values)) ?? "";
            return 0;
        };
        int result;
        try
        {
            string sql = action == MetadataPermissionAction.ForbiddenWrite ?
                "UPDATE protected_data SET value='corrupted';" : "SELECT value FROM protected_data;";
            result = Sqlite.Exec(database, sql, capture, IntPtr.Zero, out var error);
            if (error != IntPtr.Zero) Sqlite.Free(error);
        }
        finally
        {
            _ = Sqlite.SetAuthorizer(database, null, IntPtr.Zero);
            GC.KeepAlive(authorize); GC.KeepAlive(capture); GC.KeepAlive(match);
        }
        var header = new MetadataPermissionHeader(MetadataPermissionContract.Hash(root), pin.Journal,
            pin.Writer, pin.Channel, pin.Schema, Convert.ToHexString(SHA256.HashData(key.ExportSubjectPublicKeyInfo())),
            Guid.NewGuid().ToString("N"), ++sequence, window);
        var fact = new MetadataPermissionBackend(header, lease, hash, owner.Actor, owner.Project, action,
            authenticated, result == 0, result == 0 && selected.Length != 0 ? MetadataPermissionContract.Hash(selected) : "");
        byte[] bytes = MetadataPermissionContract.Bytes(fact);
        try
        {
            return new(fact, Convert.ToBase64String(key.SignData(bytes, HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation)));
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    internal void Clear()
    {
        Execute("DELETE FROM credentials; DELETE FROM protected_data;");
        leases.Clear();
    }
    private void Execute(string sql, Sqlite.RowCallback? callback = null)
    {
        int result = Sqlite.Exec(database, sql, callback, IntPtr.Zero, out var error);
        if (error != IntPtr.Zero) Sqlite.Free(error);
        GC.KeepAlive(callback);
        MetadataPermissionContract.Require(result == 0, "effect-mismatch");
    }
    public void Dispose()
    {
        if (database != IntPtr.Zero) { _ = Sqlite.Close(database); database = IntPtr.Zero; }
        key.Dispose();
    }
    private static class Sqlite
    {
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate int RowCallback(IntPtr state, int columns, IntPtr values, IntPtr names);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate int Authorizer(IntPtr state, int code, IntPtr first, IntPtr second, IntPtr db, IntPtr trigger);
        [DllImport("sqlite3", EntryPoint = "sqlite3_open", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int Open([MarshalAs(UnmanagedType.LPUTF8Str)] string filename, out IntPtr database);
        [DllImport("sqlite3", EntryPoint = "sqlite3_exec", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int Exec(IntPtr database, [MarshalAs(UnmanagedType.LPUTF8Str)] string sql,
            RowCallback? callback, IntPtr state, out IntPtr error);
        [DllImport("sqlite3", EntryPoint = "sqlite3_set_authorizer", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int SetAuthorizer(IntPtr database, Authorizer? callback, IntPtr state);
        [DllImport("sqlite3", EntryPoint = "sqlite3_close", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int Close(IntPtr database);
        [DllImport("sqlite3", EntryPoint = "sqlite3_free", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void Free(IntPtr memory);
    }
}
