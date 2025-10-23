using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using MultiIssuerJwtAuth;
using Scalar.AspNetCore;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

// ============================================================================
// 应用程序配置和启动
// ============================================================================

var builder = WebApplication.CreateBuilder(args);

// 读取 JWT 发行者配置
var jwtSection = builder.Configuration.GetSection("Jwt:Issuers");
var issuers = jwtSection.Get<JwtIssuerSettings[]>()!;

// ============================================================================
// 服务注册
// ============================================================================

// API 文档服务
builder.Services.AddOpenApi();

// JWT 认证服务
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options => ConfigureJwtBearer(options, issuers));

// 授权服务
builder.Services.AddAuthorization();

// ============================================================================
// 应用程序构建和中间件配置
// ============================================================================

var app = builder.Build();

// 开发环境：配置 API 文档
if (app.Environment.IsDevelopment())
{
    ConfigureApiDocumentation(app);
}

// 认证和授权中间件
app.UseAuthentication();
app.UseAuthorization();

// ============================================================================
// API 端点定义
// ============================================================================

ConfigureApiEndpoints(app);

// ============================================================================
// 启动应用程序
// ============================================================================

app.Run();

// ============================================================================
// 配置方法
// ============================================================================

/// <summary>
/// 配置 JWT Bearer 认证选项
/// </summary>
static void ConfigureJwtBearer(JwtBearerOptions options, JwtIssuerSettings[] issuers)
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
}

/// <summary>
/// 配置 API 文档
/// </summary>
static void ConfigureApiDocumentation(WebApplication app)
{
    app.MapOpenApi();
    app.MapScalarApiReference("/docs", options =>
    {
        options
            .WithTitle("Multi Issuer JWT Authentication API")
            .WithTheme(ScalarTheme.Mars)
            .WithDefaultHttpClient(ScalarTarget.CSharp, ScalarClient.HttpClient);
    });
}

/// <summary>
/// 配置所有 API 端点
/// </summary>
static void ConfigureApiEndpoints(WebApplication app)
{
    // ========== 认证相关端点 ==========
    
    // 生成 JWT Token
    app.MapGet("/auth/issue-token/{issuerIndex}", GenerateJwtToken)
        .WithName("IssueToken")
        .WithSummary("生成 JWT Token")
        .WithDescription("根据发行者索引生成对应的 JWT Token")
        .WithTags("Authentication")
        .Produces<object>(200, "application/json")
        .Produces(400);

    // 访问受保护的资源
    app.MapGet("/auth/secure-data", GetSecureData)
        .RequireAuthorization()
        .WithName("GetSecureData")
        .WithSummary("获取受保护的数据")
        .WithDescription("需要有效 JWT Token 才能访问的安全端点")
        .WithTags("Authentication")
        .Produces<object>(200, "application/json")
        .Produces(401);
}

// ============================================================================
// API 端点处理程序
// ============================================================================

/// <summary>
/// 生成 JWT Token
/// </summary>
static IResult GenerateJwtToken(
    [FromRoute] int issuerIndex,
    [FromServices] IConfiguration config)
{
    var issuerSettings = config.GetSection("Jwt:Issuers").Get<JwtIssuerSettings[]>();
    
    // 验证发行者索引
    if (issuerSettings == null || issuerIndex < 0 || issuerIndex >= issuerSettings.Length)
        return Results.BadRequest("Invalid issuer index.");

    var issuer = issuerSettings[issuerIndex];
    
    try
    {
        // 创建 RSA 密钥并导入私钥
        using var rsa = RSA.Create();
        rsa.ImportFromPem(issuer.PrivateKeyPem.ToCharArray());

        // 创建签名凭据
        var creds = new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256);

        // 创建 JWT Token
        var token = new JwtSecurityToken(
            issuer: issuer.Name,
            audience: issuer.Audience,
            claims: new[]
            {
                new Claim(ClaimTypes.Name, $"UserFromIssuer{issuerIndex + 1}")
            },
            expires: DateTime.UtcNow.AddMinutes(30),
            signingCredentials: creds
        );

        // 生成 Token 字符串
        var tokenString = new JwtSecurityTokenHandler().WriteToken(token);
        
        return Results.Ok(new { 
            issuer = issuer.Name, 
            token = tokenString,
            expiresAt = token.ValidTo
        });
    }
    catch (Exception ex)
    {
        return Results.Problem(
            detail: $"Failed to generate token: {ex.Message}",
            statusCode: 500
        );
    }
}

/// <summary>
/// 获取受保护的数据
/// </summary>
static IResult GetSecureData(ClaimsPrincipal user)
{
    var username = user.Identity?.Name ?? "Anonymous";
    var claims = user.Claims.Select(c => new { c.Type, c.Value }).ToList();
    
    return Results.Ok(new
    {
        message = $"Hello {username}, you are authorized via RSA token!",
        time = DateTime.UtcNow,
        userClaims = claims
    });
}
