using LogicAppProxy;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using System.Text;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddOptions<LogicAppsOptions>().Bind(builder.Configuration.GetSection("LogicApps"));
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));
var app = builder.Build();
app.MapReverseProxy(proxyPipeline =>
{
    proxyPipeline.Use((context, next) =>
    {
        var logicAppsOptions = app.Services.GetRequiredService<IOptions<LogicAppsOptions>>().Value;
        if (logicAppsOptions is null || logicAppsOptions.AuthConfig is null) {
            return next();
        }

        foreach (var workflowConfig in logicAppsOptions.AuthConfig)
        {
            if (!string.IsNullOrEmpty(workflowConfig.WorkflowName) && context.Request.GetEncodedUrl().Contains(workflowConfig.WorkflowName))
            {
                if (string.IsNullOrEmpty(workflowConfig.AuthType) || workflowConfig.AuthType == "None")
                {
                    // authentication not required for this workflow
                    return next();
                }

                // authentication is mandatory, get the authorization header
                if (!context.Request.Headers.TryGetValue("Authorization", out var authHeaders))
                {
                    context.Response.StatusCode = 401;
                    return Task.CompletedTask;
                }
                var authHeader = authHeaders.FirstOrDefault();
                if (string.IsNullOrEmpty(authHeader))
                {
                    context.Response.StatusCode = 401;
                    return Task.CompletedTask;
                }
                if (workflowConfig.AuthType == "Basic")
                {
                    if (!authHeader.StartsWith("Basic "))
                    {
                        context.Response.StatusCode = 401;
                        return Task.CompletedTask;
                    }
                    authHeader = authHeader["Basic ".Length..];
                    // decode the base64 string
                    var decodedAuthHeader = Encoding.UTF8.GetString(Convert.FromBase64String(authHeader));
                    var parts = decodedAuthHeader.Split(':', 2);
                    if (parts.Length != 2)
                    {
                        context.Response.StatusCode = 401;
                        return Task.CompletedTask;
                    }
                    var username = parts[0];
                    var password = parts[1];
                    if (username != "user" || password != "password")
                    {
                        context.Response.StatusCode = 401;
                        return Task.CompletedTask;
                    }
                }
                if (workflowConfig.AuthType == "Bearer")
                {
                    // Leverage EasyAuth feature for Bearer token validation
                    // Check if x-ms-client-principal-id header is present
                    if (!context.Request.Headers.TryGetValue("x-ms-client-principal-id", out var principalId))
                    {
                        context.Response.StatusCode = 401;
                        return Task.CompletedTask;
                    }
                }
            }
        }

        return next();
    });
});

app.MapGet("/", () => "OK!");
app.MapGet("/config", (IOptions<LogicAppsOptions> options) => options.Value);

app.Run();


