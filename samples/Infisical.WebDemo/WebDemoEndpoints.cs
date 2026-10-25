using System.Text.Json;
using SecretKit.Samples.RuntimeConfiguration;

namespace SecretKit.Samples.Infisical.WebDemo;

internal sealed class WebDemoEndpoints(
    RuntimeIntegrationCoordinator required, RuntimeIntegrationCoordinator? optional)
{
    private static readonly TimeSpan WorkTimeout = TimeSpan.FromSeconds(30);

    internal async Task HandleAsync(HttpContext context)
    {
        context.Response.ContentType = "application/json";
        try
        {
            if (context.Request.Method == "GET" && context.Request.Path == "/health/live")
                await ReplyAsync(context, 200, new { outcome = "live" });
            else if (context.Request.Method == "GET" && context.Request.Path == "/health/ready")
                await ReadinessAsync(context);
            else if (context.Request.Method == "POST" && context.Request.Path == "/work")
                await WorkAsync(context);
            else
                await ReplyAsync(context, 404, new { outcome = "not-found" });
        }
        catch (OperationCanceledException)
        {
            if (!context.Response.HasStarted && !context.RequestAborted.IsCancellationRequested)
                await ReplyAsync(context, 504, new { outcome = "cancelled" });
        }
        catch (Exception)
        {
            // HTTP-boundary failures deliberately omit downstream/provider exception details.
            if (!context.Response.HasStarted)
                await ReplyAsync(context, 502, new { outcome = "unavailable" });
        }
    }

    private Task ReadinessAsync(HttpContext context)
    {
        bool ready = required.Observe().Active;
        return ReplyAsync(context, ready ? 200 : 503, new { outcome = ready ? "ready" : "unavailable" });
    }

    private async Task WorkAsync(HttpContext context)
    {
        RuntimeIntegrationCoordinator? selected = context.Request.Query["optional"] == "true" ? optional : required;
        await using RuntimeGenerationLease? lease = selected?.Acquire();
        if (lease is null)
        {
            await ReplyAsync(context, 503, new { outcome = "unavailable" });
            return;
        }
        using var operation = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted);
        operation.CancelAfter(WorkTimeout);
        string outcome = await lease.ExecuteAsync(operation.Token);
        await ReplyAsync(context, outcome == "accepted" ? 200 : 502, new { outcome, revision = lease.Revision });
    }

    private static Task ReplyAsync(HttpContext context, int status, object response)
    {
        context.Response.StatusCode = status;
        return context.Response.WriteAsync(JsonSerializer.Serialize(response), context.RequestAborted);
    }
}
