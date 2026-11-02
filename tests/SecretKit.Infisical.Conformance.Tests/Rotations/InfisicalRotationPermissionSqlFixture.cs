using System.Runtime.InteropServices;
using System.Security.Cryptography;
using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

// Controlled Linux SQLite verifier, NOT a PostgreSQL/MySQL/MSSQL login.
// Credential persistence, authorizer and signing authority are separate from
// the provider's material and configuration stores. No metadata echo grants SQL.
internal sealed class InfisicalRotationPermissionSqlFixture : IDisposable
{
    private readonly RotationPermissionWriter writer = new(RotationPermissionJournal.Backend, "rotation-sql");
    private readonly string protectedValue = FreshText();
    private readonly string borrowedHash = FreshText();
    private readonly string fault;
    private IntPtr database;
    private static string FreshText()
    {
        Span<byte> bytes = stackalloc byte[32];
        RandomNumberGenerator.Fill(bytes);
        try { return Convert.ToHexString(bytes); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    internal RotationPermissionPin Pin => writer.Pin;
    internal RotationPermissionSigned<RotationPermissionSeal> Seal(RotationPermissionRoot root, string window,
        RotationPermissionSeal content) => writer.Sign(root, window, content);
    internal RotationPermissionSigned<RotationPermissionStoreInventory> Inventory(RotationPermissionRoot root, string window) =>
        writer.Sign(root, window, new RotationPermissionStoreInventory(Remaining, 0, 0, BorrowedPreserved, ProtectedRows));
    internal InfisicalRotationPermissionSqlFixture(string fault)
    {
        this.fault = fault;
        RotationPermissionContract.Require(OperatingSystem.IsLinux() && Sqlite.Open(":memory:", out database) == 0,
            "missing-prerequisite");
        Execute("CREATE TABLE credentials (username TEXT PRIMARY KEY, hash TEXT NOT NULL);" +
            "CREATE TABLE protected_data (value TEXT NOT NULL);" +
            "INSERT INTO credentials VALUES ('borrowed','" + borrowedHash + "');");
    }
    internal void Bootstrap() => Execute("INSERT INTO protected_data VALUES ('" + protectedValue + "');");
    internal void Set(SecretMaterial username, SecretMaterial password)
    {
        string user = RotationPermissionContract.Hash(username.Reveal());
        string hash = RotationPermissionContract.MaterialHash(username.Reveal(), password.Reveal());
        Execute("INSERT INTO credentials VALUES ('" + user + "','" + hash +
            "') ON CONFLICT(username) DO UPDATE SET hash=excluded.hash;");
    }
    internal void Revoke(SecretMaterial username) =>
        Execute("DELETE FROM credentials WHERE username='" + RotationPermissionContract.Hash(username.Reveal()) + "';");
    private bool Authenticate(SecretMaterial username, SecretMaterial password)
    {
        bool found = false;
        Sqlite.Row capture = (_, _, _, _) => { found = true; return 0; };
        Execute("SELECT username FROM credentials WHERE username='" + RotationPermissionContract.Hash(username.Reveal()) +
            "' AND hash='" + RotationPermissionContract.MaterialHash(username.Reveal(), password.Reveal()) + "';", capture);
        GC.KeepAlive(capture);
        return found;
    }
    internal RotationPermissionSigned<RotationPermissionBackend> Measure(RotationPermissionRoot root, string window,
        string request, Guid rotation, SecretMaterial username, SecretMaterial password)
    {
        bool authenticated = Authenticate(username, password);
        using var wrong = SecretMaterial.FromText("wrong-" + Guid.NewGuid().ToString("N"));
        bool wrongRejected = !Authenticate(username, wrong);
        bool writeDenied = true, readAllowed = false;
        string selected = "";
        Sqlite.Authorizer authorizer = (_, code, _, _, _, _) =>
            !authenticated ? 1 : code is 20 or 21 || fault == "backend-permission" ? 0 : 1;
        RotationPermissionContract.Require(Sqlite.SetAuthorizer(database, authorizer, IntPtr.Zero) == 0);
        Sqlite.Row capture = (_, _, values, _) =>
        { selected = Marshal.PtrToStringUTF8(Marshal.ReadIntPtr(values)) ?? ""; return 0; };
        try
        {
            readAllowed = Exec("SELECT value FROM protected_data;", capture) == 0;
            writeDenied = Exec("UPDATE protected_data SET value='corrupted';", null) != 0;
        }
        finally
        {
            _ = Sqlite.SetAuthorizer(database, null, IntPtr.Zero);
            GC.KeepAlive(authorizer); GC.KeepAlive(capture);
        }
        string actual = "";
        Sqlite.Row read = (_, _, values, _) =>
        { actual = Marshal.PtrToStringUTF8(Marshal.ReadIntPtr(values)) ?? ""; return 0; };
        Execute("SELECT value FROM protected_data;", read);
        GC.KeepAlive(read);
        return writer.Sign(root, window, new RotationPermissionBackend(request, rotation,
            RotationPermissionContract.MaterialHash(username.Reveal(), password.Reveal()), authenticated, wrongRejected,
            readAllowed && selected == protectedValue, writeDenied, RotationPermissionContract.Hash(actual)));
    }
    internal int Remaining
    {
        get
        {
            int count = -1;
            Sqlite.Row capture = (_, _, values, _) =>
            { count = int.Parse(Marshal.PtrToStringUTF8(Marshal.ReadIntPtr(values))!); return 0; };
            Execute("SELECT count(*) FROM credentials WHERE username<>'borrowed';", capture);
            GC.KeepAlive(capture); return count;
        }
    }
    internal bool BorrowedPreserved
    {
        get
        {
            bool matched = false;
            Sqlite.Row capture = (_, _, _, _) => { matched = true; return 0; };
            Execute("SELECT username FROM credentials WHERE username='borrowed' AND hash='" + borrowedHash + "';", capture);
            GC.KeepAlive(capture); return matched;
        }
    }
    internal int ProtectedRows
    {
        get
        {
            int count = -1;
            Sqlite.Row capture = (_, _, values, _) =>
            { count = int.Parse(Marshal.PtrToStringUTF8(Marshal.ReadIntPtr(values))!); return 0; };
            Execute("SELECT count(*) FROM protected_data;", capture);
            GC.KeepAlive(capture); return count;
        }
    }
    internal void Clear() => Execute("DELETE FROM credentials WHERE username<>'borrowed'; DELETE FROM protected_data;");
    private int Exec(string sql, Sqlite.Row? capture)
    {
        int result = Sqlite.Exec(database, sql, capture, IntPtr.Zero, out var error);
        if (error != IntPtr.Zero) Sqlite.Free(error);
        GC.KeepAlive(capture); return result;
    }
    private void Execute(string sql, Sqlite.Row? capture = null) =>
        RotationPermissionContract.Require(Exec(sql, capture) == 0, "effect-mismatch");
    public void Dispose()
    {
        if (database != IntPtr.Zero) { _ = Sqlite.Close(database); database = IntPtr.Zero; }
        writer.Dispose();
    }
    private static class Sqlite
    {
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate int Row(IntPtr state, int columns, IntPtr values, IntPtr names);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate int Authorizer(IntPtr state, int code, IntPtr first, IntPtr second, IntPtr db, IntPtr trigger);
        [DllImport("sqlite3", EntryPoint = "sqlite3_open", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int Open([MarshalAs(UnmanagedType.LPUTF8Str)] string file, out IntPtr db);
        [DllImport("sqlite3", EntryPoint = "sqlite3_exec", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int Exec(IntPtr db, [MarshalAs(UnmanagedType.LPUTF8Str)] string sql, Row? callback, IntPtr state, out IntPtr error);
        [DllImport("sqlite3", EntryPoint = "sqlite3_set_authorizer", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int SetAuthorizer(IntPtr db, Authorizer? callback, IntPtr state);
        [DllImport("sqlite3", EntryPoint = "sqlite3_close", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int Close(IntPtr db);
        [DllImport("sqlite3", EntryPoint = "sqlite3_free", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void Free(IntPtr value);
    }
}
