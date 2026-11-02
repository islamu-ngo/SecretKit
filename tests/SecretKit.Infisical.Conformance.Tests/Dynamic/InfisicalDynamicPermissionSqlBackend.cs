using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace SecretKit.Infisical.Conformance.Tests;

// Controlled Linux SQLite execution only. This is not PostgreSQL/MySQL login,
// a Windows loading claim, a provisioned database, or Infisical qualification.
// Credential authentication and protected SQL authorization are independent of
// HTTP policy decisions. A separate writer signs actual native SQL results.
internal sealed class InfisicalDynamicPermissionSqlBackend : IDisposable
{
    private readonly DynamicPermissionWriter writer = new(DynamicPermissionJournal.Backend, "native-sql");
    private readonly Dictionary<Guid, (string Principal, string Project)> leases = [];
    private readonly string protectedRow = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    private readonly string fault;
    private IntPtr database;
    internal DynamicPermissionPin Pin => writer.Pin;
    internal string ProtectedHash => DynamicPermissionContract.Hash(protectedRow);
    internal int Remaining => Inventory().Credentials + Inventory().ProtectedRows + leases.Count;
    internal InfisicalDynamicPermissionSqlBackend(string fault)
    {
        this.fault = fault;
        DynamicPermissionContract.Require(Sqlite.Open(":memory:", out database) == 0, "missing-prerequisite");
        Execute("CREATE TABLE credentials (lease TEXT PRIMARY KEY, hash TEXT NOT NULL);" +
            "CREATE TABLE protected_data (value TEXT NOT NULL);");
    }
    internal void Bootstrap() => Execute("INSERT INTO protected_data VALUES ('" + protectedRow + "');");
    internal void Issue(Guid lease, string hash, string principal, string project)
    {
        leases.Add(lease, (principal, project));
        Execute("INSERT INTO credentials VALUES ('" + lease.ToString("N") + "','" + hash + "');");
    }
    private DynamicPermissionSqlInventory Inventory()
    {
        int credentials = -1, rows = -1;
        Sqlite.RowCallback capture = (_, count, values, _) =>
        {
            DynamicPermissionContract.Require(count == 2);
            credentials = int.Parse(Marshal.PtrToStringUTF8(Marshal.ReadIntPtr(values))!);
            rows = int.Parse(Marshal.PtrToStringUTF8(Marshal.ReadIntPtr(values, IntPtr.Size))!);
            return 0;
        };
        Execute("SELECT (SELECT count(*) FROM credentials), (SELECT count(*) FROM protected_data);", capture);
        return new(credentials, rows, leases.Count, leases.Keys.Order().ToArray());
    }
    internal DynamicPermissionSigned<DynamicPermissionSqlInventory> Snapshot(DynamicPermissionRoot root, string window) =>
        writer.Sign(root, window, Inventory());
    internal DynamicPermissionSigned<DynamicPermissionSql> Measure(DynamicPermissionRoot root, string window,
        Guid lease, string username, string password, DynamicPermissionSqlAction action)
    {
        DynamicPermissionContract.Require(leases.TryGetValue(lease, out var owner));
        string hash = DynamicPermissionContract.MaterialHash(username, password);
        bool authenticated = false;
        Sqlite.RowCallback match = (_, _, _, _) => { authenticated = true; return 0; };
        Execute("SELECT lease FROM credentials WHERE lease='" + lease.ToString("N") + "' AND hash='" + hash + "';", match);
        Sqlite.Authorizer authorize = (_, code, _, _, _, _) =>
            !authenticated ? 1 : code is 20 or 21 || fault == "backend-write" ? 0 : 1;
        DynamicPermissionContract.Require(Sqlite.SetAuthorizer(database, authorize, IntPtr.Zero) == 0);
        string read = "";
        Sqlite.RowCallback capture = (_, count, values, _) =>
        { if (count == 1) read = Marshal.PtrToStringUTF8(Marshal.ReadIntPtr(values)) ?? ""; return 0; };
        int result;
        try
        {
            result = Sqlite.Exec(database, action == DynamicPermissionSqlAction.Write ?
                "UPDATE protected_data SET value='changed';" : "SELECT value FROM protected_data;",
                capture, IntPtr.Zero, out var error);
            if (error != IntPtr.Zero) Sqlite.Free(error);
        }
        finally
        {
            _ = Sqlite.SetAuthorizer(database, null, IntPtr.Zero);
            GC.KeepAlive(authorize); GC.KeepAlive(capture); GC.KeepAlive(match);
        }
        return writer.Sign(root, window, new DynamicPermissionSql(lease, hash, owner.Principal, owner.Project,
            action, authenticated, result == 0, result == 0 && read.Length != 0 ? DynamicPermissionContract.Hash(read) : ""));
    }
    internal void Clear()
    {
        if (fault != "sql-cleanup") Execute("DELETE FROM credentials; DELETE FROM protected_data;");
        leases.Clear();
    }
    private void Execute(string sql, Sqlite.RowCallback? callback = null)
    {
        int result = Sqlite.Exec(database, sql, callback, IntPtr.Zero, out var error);
        if (error != IntPtr.Zero) Sqlite.Free(error);
        GC.KeepAlive(callback);
        DynamicPermissionContract.Require(result == 0, "effect-mismatch");
    }
    public void Dispose()
    {
        if (database != IntPtr.Zero) { _ = Sqlite.Close(database); database = IntPtr.Zero; }
        writer.Dispose();
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
internal sealed class DynamicPermissionWriter : IDisposable
{
    private readonly ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private long sequence;
    internal DynamicPermissionPin Pin { get; }
    internal DynamicPermissionWriter(DynamicPermissionJournal journal, string writer) =>
        Pin = new(journal, writer, writer + "-channel", "dynamic-permission-v1",
            Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()));
    internal DynamicPermissionSigned<T> Sign<T>(DynamicPermissionRoot root, string window, T value)
    {
        var header = new DynamicPermissionHeader(DynamicPermissionContract.Hash(root), Pin.Journal, Pin.Writer,
            Pin.Channel, Pin.Schema, DynamicPermissionContract.RawHash(key.ExportSubjectPublicKeyInfo()),
            Guid.NewGuid().ToString("N"), ++sequence, window);
        var payload = new DynamicPermissionPayload<T>(header, value);
        byte[] bytes = DynamicPermissionContract.Bytes(payload);
        try
        {
            return new(payload, Convert.ToBase64String(key.SignData(bytes, HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation)));
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    public void Dispose() => key.Dispose();
}
