using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace MultiIssuerJwtAuth.Controllers;

[ApiController]
[Route("[controller]")]
public class AuthTestController : ControllerBase
{
    private readonly IConfiguration _config;

    public AuthTestController(IConfiguration config)
    {
        _config = config;
    }

    [HttpGet("issue-token/{issuerIndex}")]
    public IActionResult IssueToken(int issuerIndex = 0)
    {
        var issuers = _config.GetSection("Jwt:Issuers").Get<JwtIssuerSettings[]>();
        if (issuerIndex < 0 || issuerIndex >= issuers.Length)
            return BadRequest("Invalid issuer index.");

        var issuer = issuers[issuerIndex];
        using var rsa = RSA.Create();
        rsa.ImportFromPem(issuer.PrivateKeyPem.ToCharArray());

        var creds = new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256);

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

        var tokenString = new JwtSecurityTokenHandler().WriteToken(token);
        return Ok(new { issuer = issuer.Name, token = tokenString });
    }

    [Authorize]
    [HttpGet("secure-data")]
    public IActionResult GetSecureData()
    {
        var username = User.Identity?.Name ?? "Anonymous";
        return Ok(new
        {
            message = $"Hello {username}, you are authorized via RSA token!",
            time = DateTime.UtcNow
        });
    }
}
