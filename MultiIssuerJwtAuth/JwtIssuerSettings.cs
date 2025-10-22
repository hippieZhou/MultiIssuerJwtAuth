namespace MultiIssuerJwtAuth;

public class JwtIssuerSettings
{
    public string Name { get; set; } = string.Empty;
    public string Audience { get; set; } = string.Empty;
    public string PrivateKeyPem { get; set; } = string.Empty;
    public string PublicKeyPem { get; set; } = string.Empty;
}
