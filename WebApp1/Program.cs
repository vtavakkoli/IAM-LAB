using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

var builder = WebApplication.CreateBuilder(args);

// ---------- ENV ----------
string? KEYCLOAK_URL        = Environment.GetEnvironmentVariable("KEYCLOAK_URL");
string? KEYCLOAK_PUBLIC_URL = Environment.GetEnvironmentVariable("KEYCLOAK_PUBLIC_URL") ?? KEYCLOAK_URL;
string   REALM               = Environment.GetEnvironmentVariable("KEYCLOAK_REALM") ?? "IAM_Lab_Realm";
string   CLIENT_ID           = Environment.GetEnvironmentVariable("CLIENT_ID") ?? "webapp-client";
string?  CLIENT_SECRET       = Environment.GetEnvironmentVariable("CLIENT_SECRET");
string   REDIRECT_URI        = Environment.GetEnvironmentVariable("REDIRECT_URI") ?? "http://localhost:8080/auth/callback";
string   KONG_API_URL        = Environment.GetEnvironmentVariable("KONG_API_URL") ?? "http://kong:8000";
bool     disableHttpsMeta    = (Environment.GetEnvironmentVariable("OIDC_DISABLE_HTTPS") ?? "false")
                                .Equals("true", StringComparison.OrdinalIgnoreCase);

// ---------- Persist DataProtection keys ----------
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo("/keys"))
    .SetApplicationName("iam-lab-bff");

// ---------- Session ----------
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(o =>
{
    o.Cookie.Name = "iam-lab-bff";
    o.Cookie.HttpOnly = true;
    o.Cookie.SameSite = SameSiteMode.Lax;
    o.Cookie.SecurePolicy = CookieSecurePolicy.None; // dev; use Always with HTTPS
});

// ---------- Authentication / OIDC ----------
builder.Services.AddAuthentication(o =>
{
    o.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    o.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie(o =>
{
    o.SlidingExpiration = true;
    o.Cookie.HttpOnly = true;
    o.Cookie.SameSite = SameSiteMode.Lax;
    o.Cookie.SecurePolicy = CookieSecurePolicy.None; // dev
})
.AddOpenIdConnect(o =>
{
    var authorityBase = KEYCLOAK_PUBLIC_URL ?? KEYCLOAK_URL;
    o.Authority = $"{authorityBase}/realms/{REALM}";
    o.ClientId = CLIENT_ID;
    o.ClientSecret = CLIENT_SECRET;
    o.ResponseType = OpenIdConnectResponseType.Code;
    o.ResponseMode  = OpenIdConnectResponseMode.Query;    // GET callback
    o.UsePkce       = true;
    o.CallbackPath  = "/auth/callback";
    o.SaveTokens    = true;
    o.GetClaimsFromUserInfoEndpoint = true;
    o.Scope.Clear();
    o.Scope.Add("openid");
    o.Scope.Add("profile");
    o.RequireHttpsMetadata = !disableHttpsMeta;
	var internalAuthorityBase = KEYCLOAK_URL; // http://keycloak:8080

    // *** Critical: make correlation/nonce cookies explicitly Lax + not secure (HTTP) ***
    o.CorrelationCookie.SameSite   = SameSiteMode.Lax;
    o.CorrelationCookie.SecurePolicy = CookieSecurePolicy.None; // dev
    o.NonceCookie.SameSite         = SameSiteMode.Lax;
    o.NonceCookie.SecurePolicy     = CookieSecurePolicy.None;   // dev

    o.Events = new OpenIdConnectEvents
    {
        OnRedirectToIdentityProvider = ctx =>
        {
            // force exact redirect_uri (matches what you registered in Keycloak)
            if (!string.IsNullOrWhiteSpace(REDIRECT_URI))
                ctx.ProtocolMessage.RedirectUri = REDIRECT_URI;
            return Task.CompletedTask;
        },
        OnTokenValidated = ctx =>
        {
            // 1) Claims (same as you had)
            var claimsDict = ctx.Principal!.Claims
                .GroupBy(c => c.Type)
                .ToDictionary(g => g.Key, g => g.Select(c => c.Value).ToArray());
            var claimsJson = JsonSerializer.Serialize(claimsDict);
            ctx.HttpContext.Session.SetString("claims.json", claimsJson);

            // 2) Tokens — read directly from the token endpoint response here
            var accessToken = ctx.TokenEndpointResponse?.AccessToken;
            var idToken = ctx.TokenEndpointResponse?.IdToken ?? ctx.ProtocolMessage?.IdToken;

            // Optional: log without dumping secrets
            Console.WriteLine("\n==== OIDC OnTokenValidated ====");
            Console.WriteLine($"[OIDC] User: {ctx.Principal?.Identity?.Name}");
            Console.WriteLine($"[OIDC] access_token present: {(!string.IsNullOrEmpty(accessToken))}");
            Console.WriteLine($"[OIDC] id_token present: {(!string.IsNullOrEmpty(idToken))}");
            Console.WriteLine("================================\n");

            if (!string.IsNullOrEmpty(accessToken))
                ctx.HttpContext.Session.SetString("token.access_token", accessToken);

            if (!string.IsNullOrEmpty(idToken))
            {
                ctx.HttpContext.Session.SetString("token.id_token", idToken);

                // Also store raw ID token payload JSON (for /user UI)
                var parts = idToken.Split('.');
                if (parts.Length >= 2)
                {
                    var payloadJson = System.Text.Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(parts[1]));
                    ctx.HttpContext.Session.SetString("id_token.payload.json", payloadJson);
                }
            }

            return Task.CompletedTask;
        },
        OnAuthenticationFailed = ctx =>
        {
            Console.Error.WriteLine("[OIDC] AuthenticationFailed: " + ctx.Exception);
            ctx.HandleResponse();
            ctx.Response.StatusCode = 500;
            return ctx.Response.WriteAsync("OIDC auth failed.");
        }
    };
});

builder.Services.AddAuthorization();
builder.Services.AddHttpClient("kong", c =>
{
    c.BaseAddress = new Uri(KONG_API_URL.EndsWith("/") ? KONG_API_URL : KONG_API_URL + "/");
    c.Timeout = TimeSpan.FromSeconds(30);
});

var app = builder.Build();

// *** Enforce at least Lax for all cookies (belt-and-braces) ***
app.UseCookiePolicy(new CookiePolicyOptions
{
    MinimumSameSitePolicy = SameSiteMode.Lax
});

app.UseForwardedHeaders();
app.UseDefaultFiles();
app.UseStaticFiles();
app.UseRouting();

// *** Order matters: Session BEFORE Auth ***
app.UseSession();
app.UseAuthentication();
app.UseAuthorization();

// Debug log
app.Use(async (ctx, next) =>
{
    Console.WriteLine("---------------------------------------------------");
    Console.WriteLine($"[DEBUG] {ctx.Request.Method} {ctx.Request.Path}");
    Console.WriteLine($"[DEBUG] Session Id: {ctx.Session.Id}");
    Console.WriteLine(ctx.Session.TryGetValue("claims.json", out _)
        ? "[DEBUG] Claims FOUND in session."
        : "[DEBUG] Claims NOT FOUND in session.");
    Console.WriteLine("---------------------------------------------------");
    await next();
});

// /login
app.MapGet("/login", async ctx =>
{
    await ctx.ChallengeAsync(new AuthenticationProperties { RedirectUri = "/" });
}).AllowAnonymous();

// /user
app.MapGet("/user", (HttpContext ctx) =>
{
    if (ctx.Session.TryGetValue("claims.json", out var bytes))
        return Results.Content(System.Text.Encoding.UTF8.GetString(bytes), "application/json");
    return Results.Unauthorized();
});

// /logout
app.MapGet("/logout", async (HttpContext ctx) =>
{
    var idToken = ctx.Session.GetString("token.id_token");
    ctx.Session.Clear();

    var baseRedirect = REDIRECT_URI.Replace("/auth/callback", "", StringComparison.OrdinalIgnoreCase);
    var logoutUrl = QueryHelpers.AddQueryString(
        $"{KEYCLOAK_PUBLIC_URL}/realms/{REALM}/protocol/openid-connect/logout",
        new Dictionary<string, string?> {
            ["post_logout_redirect_uri"] = baseRedirect,
            ["id_token_hint"] = idToken
        });

    await ctx.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.Redirect(logoutUrl);
}).RequireAuthorization();

// lob proxy via Kong with user's access token
async Task<IResult> Calllob(HttpContext ctx, string lobPath, IHttpClientFactory f)
{
    var accessToken = ctx.Session.GetString("token.access_token");
    if (string.IsNullOrEmpty(accessToken))
    {
        Console.WriteLine($"[AUTH] lob call '{lobPath}' rejected. Access token missing from session.");
        return Results.Unauthorized();
    }

    var client = f.CreateClient("kong");
    var req = new HttpRequestMessage(HttpMethod.Get, lobPath);
    req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

    try
    {
        var resp = await client.SendAsync(req, ctx.RequestAborted);
        var statusCode = (int)resp.StatusCode;
        var body = await resp.Content.ReadAsStringAsync(ctx.RequestAborted);

        // ---------- ADD THIS DEBUGGING BLOCK ----------
        Console.WriteLine($"---> BFF calling Kong for '{lobPath}'");
        Console.WriteLine($"<--- Response from Kong: STATUS {statusCode}");
        Console.WriteLine($"<--- Response body from Kong: {body}"); // This is the most important log!
        // ----------------------------------------------

        // Return the exact response from Kong to the browser
        return Results.Content(
            body,
            resp.Content.Headers.ContentType?.ToString() ?? "application/json",
            statusCode: statusCode);
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[ERROR] Failed to call Kong: {ex.Message}");
        return Results.Problem("Failed to connect to the upstream API gateway.", statusCode: 502);
    }
}

app.MapGet("/api/call-lob1", (HttpContext ctx, IHttpClientFactory f) => Calllob(ctx, "lob1", f));
app.MapGet("/api/call-lob2", (HttpContext ctx, IHttpClientFactory f) => Calllob(ctx, "lob2", f));
app.MapGet("/api/call-lob3", (HttpContext ctx, IHttpClientFactory f) => Calllob(ctx, "lob3", f));

app.MapGet("/", (HttpContext ctx) =>
{
    var port = Environment.GetEnvironmentVariable("PORT") ?? "8080";
    return Results.Json(new
    {
        message = $"BFF for {CLIENT_ID} running",
        url = $"http://localhost:{port}",
        loggedIn = ctx.Session.GetString("token.access_token") != null
    });
});

app.Run();
