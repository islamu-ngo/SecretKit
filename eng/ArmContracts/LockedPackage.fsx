// Run inside the pinned SDK's F# host. NuGet lock hashes cover signed content,
// not the raw .nupkg or an unauthenticated hash sidecar in the package cache.
open System
open System.IO
open System.Threading
open NuGet.Packaging

let verify (stream: Stream) (id: string) (version: string) (hash: string) =
    use package = new PackageArchiveReader(stream, true)
    let identity = package.GetIdentity()
    if identity.Id <> id || identity.Version.ToNormalizedString() <> version then
        raise (InvalidDataException $"Wrong SDK archive identity: {id}")
    let signature = package.GetPrimarySignatureAsync(CancellationToken.None).GetAwaiter().GetResult()
    if isNull signature || package.GetContentHash(CancellationToken.None,
        fun () -> raise (InvalidDataException "No signed NuGet content hash.")) <> hash then
        raise (InvalidDataException $"Signed content differs from locked hash: {id}")
    package.ValidateIntegrityAsync(signature.SignatureContent, CancellationToken.None).GetAwaiter().GetResult()

match fsi.CommandLineArgs[1..] with
| [| assets; locks; framework; references; bindings; output |] ->
    SecretKit.Build.Generate.Run(assets, locks, framework, references, bindings, output, Action<_,_,_,_>(verify))
| _ -> invalidArg "args" "Expected assets, lock, framework, reference list, symbolic bindings and output."
