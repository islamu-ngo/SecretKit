using SecretKit.Core;
using SecretKit.Infisical;
using SecretKit.Testing.Infisical;

// Offline fixture: replace this reader with an explicitly authenticated runtime client.
using var reader = new InMemoryInfisicalSecretReader();
using var input = SecretMaterial.FromText("offline-demo-value");
reader.Set(new InfisicalSecretAddress("demo-project", "development", "/", "DemoKey"), input);

var scope = reader.CreateScope("demo-project", "development");
using SecretRead secret = await scope.GetSecretAsync("DemoKey");
bool accepted = secret.Material.Use(static value => value.SequenceEqual("offline-demo-value"));
if (!accepted) throw new InvalidOperationException("Offline demonstration failed.");
Console.WriteLine("Secret consumed without exporting or printing its value.");
