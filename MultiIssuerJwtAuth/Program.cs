using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using MultiIssuerJwtAuth;
using Scalar.AspNetCore;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;

var builder = WebApplication.CreateBuilder(args);

// 读取配置
var jwtSection = builder.Configuration.GetSection("Jwt:Issuers");
var issuers = jwtSection.Get<JwtIssuerSettings[]>()!;

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,

            ValidIssuers = issuers.Select(i => i.Name),
            ValidAudiences = issuers.Select(i => i.Audience),

            // 动态解析签名密钥（根据 issuer 选用对应公钥）
            IssuerSigningKeyResolver = (token, securityToken, kid, parameters) =>
            {
                var jwt = new JwtSecurityToken(token);
                var issuer = jwt.Issuer;

                var matched = issuers.FirstOrDefault(i => i.Name == issuer);
                if (matched == null)
                    return [];

                var rsa = RSA.Create();
                rsa.ImportFromPem(matched.PublicKeyPem.ToCharArray());
                return [new RsaSecurityKey(rsa)];
            }
        };
    });

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference("/docs",options =>
    {
        options
        .WithTitle("Multi Issuer Jwt Auth")
        .WithTheme(ScalarTheme.Mars)
        .WithDefaultHttpClient(ScalarTarget.CSharp, ScalarClient.HttpClient);
    });
}

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
