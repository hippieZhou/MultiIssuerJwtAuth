# Multi-Issuer JWT Authentication API

一个支持多发行者的 JWT 认证系统，使用 ASP.NET Core 9.0 和 Minimal API 构建。

## 🚀 功能特性

- ✅ **多发行者支持** - 支持多个不同的 JWT 发行者同时签发和验证 token
- ✅ **RSA 非对称加密** - 使用 RSA-SHA256 算法进行 JWT 签名和验证
- ✅ **动态密钥解析** - 根据 token 中的 issuer 自动选择对应的公钥进行验证
- ✅ **Minimal API** - 使用现代 ASP.NET Core Minimal API 架构
- ✅ **OpenAPI 文档** - 集成 Scalar UI 提供美观的交互式 API 文档
- ✅ **企业级结构** - 清晰的代码组织和完整的错误处理

## 🏗️ 技术栈

- **.NET 9.0** - 最新的 .NET 平台
- **ASP.NET Core** - Web API 框架
- **JWT Bearer Authentication** - 认证中间件
- **RSA 加密** - 非对称密钥加密
- **OpenAPI** - API 文档
- **Scalar UI** - 现代化 API 文档界面

## 📋 系统要求

- .NET 9.0 SDK (ARM64 for Apple Silicon)
- macOS/Linux/Windows

## 🛠️ 快速开始

### 1. 克隆项目

```bash
git clone git@github.com:hippieZhou/MultiIssuerJwtAuth.git
cd MultiIssuerJwtAuth
```

### 2. 安装依赖

```bash
dotnet restore
```

### 3. 配置 JWT 发行者

编辑 `appsettings.Development.json` 文件，配置你的 JWT 发行者：

```json
{
  "Jwt": {
    "Issuers": [
      {
        "Name": "https://your-issuer1.com",
        "Audience": "your-api-1",
        "PrivateKeyPem": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
        "PublicKeyPem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
      },
      {
        "Name": "https://your-issuer2.com", 
        "Audience": "your-api-2",
        "PrivateKeyPem": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
        "PublicKeyPem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
      }
    ]
  }
}
```

### 4. 运行应用

```bash
dotnet run
```

应用将在 `http://localhost:5000` 启动。

## 📚 API 文档

启动应用后，访问 `http://localhost:5000/docs` 查看交互式 API 文档。

## 🔧 API 端点

### 认证相关

#### 生成 JWT Token
```http
GET /auth/issue-token/{issuerIndex}
```

**参数：**
- `issuerIndex` (路径参数): 发行者索引 (0, 1, 2, ...)

**响应：**
```json
{
  "issuer": "https://issuer1.example.com",
  "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expiresAt": "2025-10-23T00:54:22Z"
}
```

#### 访问受保护资源
```http
GET /auth/secure-data
Authorization: Bearer <your-jwt-token>
```

**响应：**
```json
{
  "message": "Hello UserFromIssuer1, you are authorized via RSA token!",
  "time": "2025-10-23T00:24:26.296385Z",
  "userClaims": [
    {
      "type": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
      "value": "UserFromIssuer1"
    },
    {
      "type": "exp",
      "value": "1761180866"
    },
    {
      "type": "iss", 
      "value": "https://issuer1.example.com"
    },
    {
      "type": "aud",
      "value": "issuer1-api"
    }
  ]
}
```

## 🔑 生成 RSA 密钥对

### 使用 OpenSSL

```bash
# 生成私钥
openssl genrsa 2048 2>/dev/null | openssl pkcs8 -topk8 -nocrypt -outform PEM

# 从私钥提取公钥
echo "YOUR_PRIVATE_KEY" | openssl rsa -pubout 2>/dev/null
```

### 使用 C# 代码

```csharp
using var rsa = RSA.Create(2048);
var privateKey = rsa.ExportRSAPrivateKey();
var publicKey = rsa.ExportRSAPublicKey();

var privateKeyPem = $"-----BEGIN PRIVATE KEY-----\n{Convert.ToBase64String(privateKey, Base64FormattingOptions.InsertLineBreaks)}\n-----END PRIVATE KEY-----";
var publicKeyPem = $"-----BEGIN PUBLIC KEY-----\n{Convert.ToBase64String(publicKey, Base64FormattingOptions.InsertLineBreaks)}\n-----END PUBLIC KEY-----";
```

## 🧪 测试示例

### 1. 生成 Token

```bash
# 生成 Issuer 1 的 Token
curl http://localhost:5000/auth/issue-token/0

# 生成 Issuer 2 的 Token  
curl http://localhost:5000/auth/issue-token/1
```

### 2. 使用 Token 访问受保护资源

```bash
# 获取 Token
TOKEN=$(curl -s http://localhost:5000/auth/issue-token/0 | jq -r '.token')

# 使用 Token 访问受保护端点
curl -H "Authorization: Bearer $TOKEN" http://localhost:5000/auth/secure-data
```

### 3. 测试无 Token 访问（应该返回 401）

```bash
curl http://localhost:5000/auth/secure-data
```

## 🏛️ 架构设计

### 核心组件

1. **JwtIssuerSettings** - JWT 发行者配置模型
2. **动态密钥解析器** - 根据 issuer 自动选择公钥
3. **Minimal API 端点** - 现代化的 API 定义方式
4. **认证中间件** - JWT Bearer 认证管道

### 安全特性

- ✅ **RSA 非对称加密** - 更安全的密钥管理
- ✅ **多发行者隔离** - 每个发行者独立的密钥对
- ✅ **Token 过期控制** - 30 分钟有效期
- ✅ **动态密钥验证** - 运行时密钥解析

## 🎯 使用场景

- **微服务架构** - 多个服务信任不同身份提供商的 token
- **多租户系统** - 不同租户使用独立的身份验证服务
- **第三方集成** - 接受多个外部系统签发的 token
- **B2B 应用** - 不同合作伙伴有独立的身份认证系统

## 🔧 开发指南

### 项目结构

```
MultiIssuerJwtAuth/
├── Program.cs                    # 主程序文件（Minimal API）
├── JwtIssuerSettings.cs         # JWT 发行者配置模型
├── appsettings.json             # 生产环境配置
├── appsettings.Development.json # 开发环境配置
└── MultiIssuerJwtAuth.csproj    # 项目文件
```

### 添加新的发行者

1. 在 `appsettings.Development.json` 中添加新的发行者配置
2. 生成对应的 RSA 密钥对
3. 重启应用即可使用新的发行者索引

### 自定义 Claims

修改 `GenerateJwtToken` 方法中的 claims 部分：

```csharp
claims: new[]
{
    new Claim(ClaimTypes.Name, $"UserFromIssuer{issuerIndex + 1}"),
    new Claim(ClaimTypes.Role, "Admin"),
    new Claim("custom-claim", "custom-value")
}
```

## 📝 许可证

MIT License

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

---

**注意：** 这是一个演示项目，生产环境使用前请确保：
- 使用安全的密钥管理方案
- 配置适当的 CORS 策略
- 启用 HTTPS
- 实施适当的日志记录和监控