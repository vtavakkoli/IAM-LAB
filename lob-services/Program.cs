var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
var app = builder.Build();

// Retrieve environment variables
var serviceName = Environment.GetEnvironmentVariable("SERVICE_NAME") ?? "Unknown LOB";
var port = Environment.GetEnvironmentVariable("PORT") ?? "8080";

// Configure the HTTP request pipeline.
app.MapGet("/", () => {
    Console.WriteLine($"Received request for {serviceName}");
    return Results.Ok(new {
        message = $"Hello from {serviceName}! You have successfully accessed this protected service.",
        service = serviceName,
        timestamp = DateTime.UtcNow.ToString("o")
    });
});

app.Run();