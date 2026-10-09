# Signed ZIP regression fixture

The Base64 file is the unmodified public archive for
Microsoft.NETCore.Platforms 1.1.0, fetched on 2026-10-09 from
https://api.nuget.org/v3-flatcontainer/microsoft.netcore.platforms/1.1.0/microsoft.netcore.platforms.1.1.0.nupkg.
It is test data, not a project/package dependency, and is not packed or loaded.
The archive contains runtime mapping metadata, a nuspec, an empty library marker,
OPC metadata, its original license/notices, and NuGet's repository signature.
No vendor implementation was used to design the ZIP reconstruction.

- Archive length: 17,960 bytes.
- Signed archive SHA-256:
  `15e338d24b5c39b4099389cc612841eb51ff13c07bb4829f97d39b27420e7023`.
- Independently extracted CMS properties-document SHA-256 of the original
  unsigned archive, Base64: `ScOW1SKYEECOkS1XH7HyHPovkoU9Svyzx3aB0UHQlqc=`.
- Independent extraction: feed the stored `.signature.p7s` bytes to
  `openssl cms -verify -noverify -inform DER`. Observed exit 0 and
  `CMS Verification successful`; the embedded properties document specifies
  version 1 and OID `2.16.840.1.101.3.4.2.1`.
- `-noverify` deliberately does **not** establish certificate-chain trust,
  timestamp policy, current revocation, publisher rights, or namespace ownership.
  This oracle checks signature mathematics and supplies an expected archive hash
  independently of the implementation under test.

The fixture retains `dotnet_library_license.txt` and `ThirdPartyNotices.txt`
inside the unchanged archive; retain them on redistribution. Package provenance
is the Microsoft .NET distribution on NuGet.org, not SecretKit ownership.
The archive is used solely for ZIP/signature interoperability tests under its
included .NET Library license and notices. No source code or executable library
is extracted into this repository or shipped in SecretKit packages.
