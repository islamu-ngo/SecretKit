using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Text;
using SecretKit.Core;
using SecretKit.Infisical.Dynamic;

namespace SecretKit.Infisical.Tests;

public sealed class SpanSerializationHardeningTests
{
    [Test]
    public async Task InfisicalAssemblyHasZeroRequiresUnreferencedCodeAndIsMarkedTrimmable()
    {
        Assembly assembly = typeof(InfisicalClient).Assembly;

        bool isTrimmable = assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
            .Any(attribute => attribute.Key == "IsTrimmable" &&
                string.Equals(attribute.Value, "True", StringComparison.OrdinalIgnoreCase));
        await Assert.That(isTrimmable).IsTrue();

        const BindingFlags Any = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;
        MemberInfo[] annotatedMembers = assembly.GetTypes()
            .SelectMany(type => type.GetMembers(Any))
            .Where(member =>
                member.GetCustomAttribute<RequiresUnreferencedCodeAttribute>(inherit: false) is not null ||
                member.GetCustomAttribute<RequiresDynamicCodeAttribute>(inherit: false) is not null)
            .ToArray();
        await Assert.That(annotatedMembers).IsEmpty();
    }

    [Test]
    public async Task DatabaseCredentialsUseAccessorsVerifySpanLifecycleDisposalAndConcurrency()
    {
        using var wire = new DynamicWireFixture();
        await using var client = new InfisicalDynamicClient(new("https://dynamic.test"),
            new FailureEvidenceTests.Tokens(), new(wire.Project, wire.Environment, wire.FolderPath, wire.FolderId),
            new InfisicalNetworkOptions { Transport = InfisicalTransportOptions.HostControlled(wire) }, wire.Time);
        InfisicalDynamicDefinition definition = await wire.CreateDatabaseAsync(client);
        using InfisicalDatabaseLease lease = (await client.AcquireDatabaseAsync(definition,
            new InfisicalDynamicMutationReceipt(definition.Target, InfisicalDynamicOperation.Acquire))).Value;

        using InfisicalDatabaseCredentials credentials = lease.CopyCredentials().Value;
        string expectedUsername = credentials.RevealUsername();
        string expectedPassword = credentials.RevealPassword();
        byte[] expectedUsernameUtf8 = Encoding.UTF8.GetBytes(expectedUsername);
        byte[] expectedPasswordUtf8 = Encoding.UTF8.GetBytes(expectedPassword);

        // Null callback validation must happen before validity or copy work.
        await Assert.That(() => credentials.UseUsername((SecretSpanAction)null!)).Throws<ArgumentNullException>();
        await Assert.That(() => credentials.UseUsername(0, (SecretSpanAction<int>)null!)).Throws<ArgumentNullException>();
        await Assert.That(() => credentials.UseUsername<int>((SecretSpanFunc<int>)null!)).Throws<ArgumentNullException>();
        await Assert.That(() => credentials.UseUsername<int, int>(0, (SecretSpanFunc<int, int>)null!)).Throws<ArgumentNullException>();
        await Assert.That(() => credentials.UsePassword((SecretSpanAction)null!)).Throws<ArgumentNullException>();
        await Assert.That(() => credentials.UsePassword(0, (SecretSpanAction<int>)null!)).Throws<ArgumentNullException>();
        await Assert.That(() => credentials.UsePassword<int>((SecretSpanFunc<int>)null!)).Throws<ArgumentNullException>();
        await Assert.That(() => credentials.UsePassword<int, int>(0, (SecretSpanFunc<int, int>)null!)).Throws<ArgumentNullException>();
        await Assert.That(() => credentials.UseUsernameUtf8((SecretUtf8SpanAction)null!)).Throws<ArgumentNullException>();
        await Assert.That(() => credentials.UseUsernameUtf8(0, (SecretUtf8SpanAction<int>)null!)).Throws<ArgumentNullException>();
        await Assert.That(() => credentials.UseUsernameUtf8<int>((SecretUtf8SpanFunc<int>)null!)).Throws<ArgumentNullException>();
        await Assert.That(() => credentials.UseUsernameUtf8<int, int>(0, (SecretUtf8SpanFunc<int, int>)null!)).Throws<ArgumentNullException>();
        await Assert.That(() => credentials.UsePasswordUtf8((SecretUtf8SpanAction)null!)).Throws<ArgumentNullException>();
        await Assert.That(() => credentials.UsePasswordUtf8(0, (SecretUtf8SpanAction<int>)null!)).Throws<ArgumentNullException>();
        await Assert.That(() => credentials.UsePasswordUtf8<int>((SecretUtf8SpanFunc<int>)null!)).Throws<ArgumentNullException>();
        await Assert.That(() => credentials.UsePasswordUtf8<int, int>(0, (SecretUtf8SpanFunc<int, int>)null!)).Throws<ArgumentNullException>();

        // Verify all 16 span and UTF-8 span accessors match expected values outside locks.
        string? observedUserAction = null;
        credentials.UseUsername(chars => observedUserAction = new string(chars));
        await Assert.That(observedUserAction).IsEqualTo(expectedUsername);

        string? observedUserStateAction = null;
        credentials.UseUsername("prefix:", (chars, prefix) => observedUserStateAction = prefix + new string(chars));
        await Assert.That(observedUserStateAction).IsEqualTo("prefix:" + expectedUsername);

        string observedUserFunc = credentials.UseUsername(chars => new string(chars));
        await Assert.That(observedUserFunc).IsEqualTo(expectedUsername);

        string observedUserStateFunc = credentials.UseUsername(42, static (chars, tag) => $"{tag}:{new string(chars)}");
        await Assert.That(observedUserStateFunc).IsEqualTo($"42:{expectedUsername}");

        string? observedPassAction = null;
        credentials.UsePassword(chars => observedPassAction = new string(chars));
        await Assert.That(observedPassAction).IsEqualTo(expectedPassword);

        string? observedPassStateAction = null;
        credentials.UsePassword("p:", (chars, prefix) => observedPassStateAction = prefix + new string(chars));
        await Assert.That(observedPassStateAction).IsEqualTo("p:" + expectedPassword);

        string observedPassFunc = credentials.UsePassword(chars => new string(chars));
        await Assert.That(observedPassFunc).IsEqualTo(expectedPassword);

        string observedPassStateFunc = credentials.UsePassword(7, static (chars, tag) => $"{tag}:{new string(chars)}");
        await Assert.That(observedPassStateFunc).IsEqualTo($"7:{expectedPassword}");

        byte[]? observedUserUtf8Action = null;
        credentials.UseUsernameUtf8(utf8 => observedUserUtf8Action = utf8.ToArray());
        await Assert.That(observedUserUtf8Action!.AsSpan().SequenceEqual(expectedUsernameUtf8)).IsTrue();

        byte[]? observedUserUtf8StateAction = null;
        credentials.UseUsernameUtf8(1, (utf8, _) => observedUserUtf8StateAction = utf8.ToArray());
        await Assert.That(observedUserUtf8StateAction!.AsSpan().SequenceEqual(expectedUsernameUtf8)).IsTrue();

        byte[] observedUserUtf8Func = credentials.UseUsernameUtf8(utf8 => utf8.ToArray());
        await Assert.That(observedUserUtf8Func.AsSpan().SequenceEqual(expectedUsernameUtf8)).IsTrue();

        bool userUtf8StateMatch = credentials.UseUsernameUtf8(expectedUsernameUtf8, static (utf8, expected) => utf8.SequenceEqual(expected));
        await Assert.That(userUtf8StateMatch).IsTrue();

        byte[]? observedPassUtf8Action = null;
        credentials.UsePasswordUtf8(utf8 => observedPassUtf8Action = utf8.ToArray());
        await Assert.That(observedPassUtf8Action!.AsSpan().SequenceEqual(expectedPasswordUtf8)).IsTrue();

        byte[]? observedPassUtf8StateAction = null;
        credentials.UsePasswordUtf8(1, (utf8, _) => observedPassUtf8StateAction = utf8.ToArray());
        await Assert.That(observedPassUtf8StateAction!.AsSpan().SequenceEqual(expectedPasswordUtf8)).IsTrue();

        byte[] observedPassUtf8Func = credentials.UsePasswordUtf8(utf8 => utf8.ToArray());
        await Assert.That(observedPassUtf8Func.AsSpan().SequenceEqual(expectedPasswordUtf8)).IsTrue();

        bool passUtf8StateMatch = credentials.UsePasswordUtf8(expectedPasswordUtf8, static (utf8, expected) => utf8.SequenceEqual(expected));
        await Assert.That(passUtf8StateMatch).IsTrue();

        // Reentrant Dispose inside the callback must not deadlock or corrupt the active span copy; subsequent calls fail closed.
        string reentrantResult = credentials.UsePassword(chars =>
        {
            credentials.Dispose();
            return new string(chars);
        });
        await Assert.That(reentrantResult).IsEqualTo(expectedPassword);
        await Assert.That(() => credentials.UseUsername(_ => { })).Throws<ObjectDisposedException>();
        await Assert.That(() => credentials.UsePasswordUtf8(_ => { })).Throws<ObjectDisposedException>();

        // Concurrent span access racing against lease expiry must never deadlock or leak stale material after expiry.
        using InfisicalDatabaseCredentials racingCopy = lease.CopyCredentials().Value;
        using var gate = new ManualResetEventSlim(false);
        Task[] workers = Enumerable.Range(0, 8).Select(index => Task.Run(() =>
        {
            gate.Wait();
            for (int iteration = 0; iteration < 25; iteration++)
            {
                try
                {
                    if ((index & 1) == 0)
                    {
                        bool match = racingCopy.UsePassword(expectedPassword, static (chars, expected) => chars.SequenceEqual(expected));
                        if (!match) throw new InvalidOperationException("Mismatched password span.");
                    }
                    else
                    {
                        bool match = racingCopy.UsePasswordUtf8(expectedPasswordUtf8, static (utf8, expected) => utf8.SequenceEqual(expected));
                        if (!match) throw new InvalidOperationException("Mismatched password UTF-8 span.");
                    }
                }
                catch (InvalidOperationException ex) when (ex.Message.Contains("not locally usable", StringComparison.Ordinal))
                {
                    break;
                }
            }
        })).ToArray();
        Task expirer = Task.Run(() =>
        {
            gate.Wait();
            Thread.Sleep(2);
            wire.Time.Advance(TimeSpan.FromHours(1));
        });
        gate.Set();
        await Task.WhenAll([.. workers, expirer]).WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(() => racingCopy.UseUsername(_ => { })).Throws<InvalidOperationException>();
        await Assert.That(() => racingCopy.UsePasswordUtf8(_ => { })).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task RotationSetAutomaticUsesSpanWriterAndLoginProofAvoidsLohBuffer()
    {
        Assembly assembly = typeof(InfisicalClient).Assembly;
        await Assert.That(assembly.GetType("SecretKit.Infisical.InfisicalRotationEnablementBody")).IsNull();
        Type rotationApi = assembly.GetType("SecretKit.Infisical.IInfisicalRotationApi", throwOnError: true)!;
        foreach (MethodInfo method in rotationApi.GetMethods())
        {
            foreach (ParameterInfo parameter in method.GetParameters())
            {
                bool hasBodyAttribute = parameter.GetCustomAttributes(inherit: false)
                    .Any(attr => attr.GetType().FullName == "Refit.BodyAttribute");
                if (hasBodyAttribute)
                {
                    await Assert.That(parameter.ParameterType == typeof(HttpContent)).IsTrue();
                }
            }
        }

        using var secret = SecretMaterial.FromText("proof-canary");
        // Warm once so JIT and type initialization are not counted as per-proof allocation.
        using (InfisicalLoginProof.Oidc("identity-1", secret)) { }
        long before = GC.GetAllocatedBytesForCurrentThread();
        using var proof = InfisicalLoginProof.Oidc("identity-1", secret);
        long allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        await Assert.That(allocated).IsLessThan(32 * 1024L);
    }
}
