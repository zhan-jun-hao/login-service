# login-service

> **Gateway + Nacos + Spring Security + OAuth2 + Redis 微服务登录鉴权脚手架，开箱即用**

## 📋 目录

- [项目简介](#项目简介)
- [系统架构](#系统架构)
- [功能特性](#功能特性)
- [模块说明](#模块说明)
- [技术栈](#技术栈)
- [快速开始](#快速开始)
- [接口文档](#接口文档)
- [踢人机制详解](#踢人机制详解)
- [Nacos 配置中心](#nacos-配置中心)
- [Redis Key 设计](#redis-key-设计)
- [安全设计](#安全设计)
- [部署说明](#部署说明)

---

## 项目简介

**login-service** 是一个基于 Spring Cloud 微服务架构的登录鉴权脚手架项目。它提供了一套完整的安全体系：

- ✅ **认证**：用户名密码登录 → JWT 双 Token 签发（access_token + refresh_token）
- ✅ **鉴权**：Gateway 统一拦截，OAuth2 资源服务器校验 JWT
- ✅ **白名单**：可配置的公开路径，无需鉴权直接放行
- ✅ **黑名单精准踢人**：管理员可踢出指定用户，所有 Token 立即失效
- ✅ **版本号批量踢人**：设置最低客户端版本，低于此版本的用户全部被拦截

---

## 系统架构

```
                         ┌─────────────────────────────────────────────┐
                         │              Nacos 注册中心 + 配置中心         │
                         │              (服务发现 + 动态配置)              │
                         └──────┬──────────────────────────┬───────────┘
                                │                          │
     ┌──────────────────────────┼──────────────────────────┼──────────────────┐
     │                          │                          │                  │
     ▼                          ▼                          ▼                  ▼
┌─────────┐    ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐    ┌─────────┐
│ Client  │───▶│ Gateway │  │  Auth   │  │  User   │  │  Admin  │    │  Redis  │
│(APP/Web)│    │  :8080  │  │  :8081  │  │  :8082  │  │  :8083  │    │  :6379  │
└─────────┘    └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘    └────┬────┘
                    │            │            │            │              │
                    │            ▼            │            │              │
                    │       ┌─────────┐       │            │              │
                    │       │  MySQL  │       │            │              │
                    │       │  :3306  │       │            │              │
                    │       └─────────┘       │            │              │
                    │                         │            │              │
                    └─────────────────────────┴────────────┴──────────────┘
                                    鉴权请求流程
```

### 请求流程

```
客户端请求
    │
    ▼
┌──────────────────────┐
│ 1. TraceIdFilter     │  生成 traceId（全链路追踪）
├──────────────────────┤
│ 2. AuthGlobalFilter  │
│   ├─ 白名单检查       │  → 白名单路径直接放行
│   ├─ JWT 签名校验     │  → OAuth2 资源服务器本地校验
│   ├─ Token 黑名单检查  │  → 登出后的 token 拒绝
│   ├─ 用户黑名单检查    │  → 精准踢人（Redis Set）
│   └─ 版本控制检查     │  → 批量踢人（版本比较）
├──────────────────────┤
│ 3. 注入用户上下文     │  X-User-Id, X-User-Role, X-Trace-Id
├──────────────────────┤
│ 4. 路由到下游服务     │  lb://login-auth / login-user / login-admin
└──────────────────────┘
```

---

## 功能特性

### 🔐 认证与授权
| 功能 | 说明 |
|------|------|
| 用户注册 | BCrypt 密码加密存储 |
| 用户登录 | Spring Security 自动认证 → JWT 双 Token 签发 |
| Token 刷新 | Refresh Token Rotation（刷新轮转，防盗用） |
| 用户登出 | Token 加入黑名单（TTL = 剩余有效期） |
| OAuth2 支持 | Gateway 作为 OAuth2 资源服务器 |

### 🛡️ 三层防护
| 层级 | 机制 | 触发方式 |
|------|------|----------|
| Token 黑名单 | 用户登出 → Token(jti) 加入黑名单 | 用户主动登出 |
| 精准踢人 | 管理员踢出 → userId 加入黑名单 Set | 管理员手动操作 |
| 批量踢人 | 设置最低版本 → 低版本客户端全部拦截 | 管理员设置版本号 |

### 📋 管理功能
| 功能 | API |
|------|-----|
| 踢出指定用户 | `POST /admin/kick/user` |
| 批量踢出用户 | `POST /admin/kick/users/batch` |
| 恢复被踢用户 | `DELETE /admin/kick/user/{userId}` |
| 查看黑名单 | `GET /admin/blacklist/users` |
| 设置最低版本 | `POST /admin/version/min` |
| 封禁特定版本 | `POST /admin/version/blacklist` |
| 管理白名单 | `POST/DELETE /admin/whitelist/path` |

---

## 模块说明

| 模块 | 端口 | 描述 |
|------|------|------|
| **login-gateway** | 8080 | API 网关：路由转发 + OAuth2 JWT 鉴权 + 白名单/黑名单/版本控制 |
| **login-auth** | 8081 | 认证服务：登录/注册/Token 签发/刷新/登出 + 管理员踢人管理 |
| **login-user** | 8082 | 用户服务：示例业务服务（展示如何获取 Gateway 透传的用户信息） |
| **login-admin** | 8083 | 管理员服务：管理控制台后端（仪表盘、黑名单、版本控制） |
| **login-common** | - | 公共模块：JWT 工具类、统一响应体、Redis Key 常量、版本工具类 |

---

## 技术栈

| 技术 | 版本 | 用途 |
|------|------|------|
| Java | 17 | 运行环境 |
| Spring Boot | 3.2.0 | 应用框架 |
| Spring Cloud | 2023.0.0 | 微服务框架 |
| Spring Cloud Alibaba | 2023.0.1.0 | Nacos 集成 |
| Spring Security | 6.x | 认证框架 |
| Spring Security OAuth2 | 6.x | OAuth2 资源服务器 |
| Spring Cloud Gateway | 4.x | API 网关（WebFlux 响应式） |
| Nacos | 2.x | 服务发现 + 配置中心 |
| Redis | 7.x | Token/黑名单/版本控制缓存 |
| MySQL | 8.x | 用户数据持久化 |
| MyBatis-Plus | 3.5.5 | ORM 框架 |
| jjwt | 0.12.3 | JWT 签发与校验 |
| Lombok | - | 简化代码 |

---

## 快速开始

### 1. 环境要求

- JDK 17+
- Maven 3.8+
- MySQL 8.0+
- Redis 7.0+
- Nacos 2.x

### 2. 启动基础设施

```bash
# 启动 MySQL
# 创建数据库：执行 sql/init.sql

# 启动 Redis
redis-server

# 启动 Nacos（单机模式）
# Windows:
startup.cmd -m standalone
# Linux/Mac:
sh startup.sh -m standalone
```

### 3. 配置 Nacos

1. 访问 Nacos 控制台：http://localhost:8848/nacos（用户名/密码：nacos/nacos）
2. 在 `public` 命名空间下创建以下配置文件：

| Data ID | Group | 内容 |
|---------|-------|------|
| shared-redis.yaml | DEFAULT_GROUP | `nacos-config/shared-redis.yaml` |
| shared-jwt.yaml | DEFAULT_GROUP | `nacos-config/shared-jwt.yaml` |
| gateway-routes.yaml | DEFAULT_GROUP | `nacos-config/gateway-routes.yaml` |

### 4. 修改数据库配置

各模块 `application.yml` 中的数据库连接信息：
```yaml
spring:
  datasource:
    url: jdbc:mysql://localhost:3306/login_service?...
    username: root
    password: your_password   # 修改为实际密码
```

### 5. 启动服务

```bash
# 按顺序启动
# 1. 认证服务
cd login-auth && mvn spring-boot:run

# 2. 用户服务
cd login-user && mvn spring-boot:run

# 3. 管理员服务
cd login-admin && mvn spring-boot:run

# 4. 网关（最后启动）
cd login-gateway && mvn spring-boot:run
```

---

## 接口文档

### 认证接口（公开，无需 Token）

#### 注册
```http
POST /auth/register
Content-Type: application/json

{
    "username": "zhangsan",
    "password": "123456",
    "nickname": "张三"
}
```

#### 登录
```http
POST /auth/login
Content-Type: application/json
X-Client-Version: 1.5.0        # 客户端版本号（用于版本控制）

{
    "username": "zhangsan",
    "password": "123456"
}

# 响应
{
    "code": 200,
    "message": "success",
    "data": {
        "accessToken": "eyJhbGciOi...",
        "refreshToken": "eyJhbGciOi...",
        "expiresIn": 1800,
        "tokenType": "Bearer"
    }
}
```

#### 刷新 Token
```http
POST /auth/refresh
Content-Type: application/json

{
    "refreshToken": "eyJhbGciOi..."
}
```

#### 登出
```http
POST /auth/logout
Authorization: Bearer eyJhbGciOi...
```

### 受保护接口（需要 JWT Token）

#### 获取用户信息
```http
GET /user/info
Authorization: Bearer eyJhbGciOi...
```

### 管理员接口（需要 admin 角色）

#### 踢出用户
```http
POST /admin/kick/user
Authorization: Bearer {admin_token}
Content-Type: application/json

{
    "userId": 123,
    "reason": "违规操作"
}
```

#### 设置最低版本
```http
POST /admin/version/min
Authorization: Bearer {admin_token}
Content-Type: application/json

{
    "minVersion": "1.5.0",
    "kickMessage": "您的客户端版本过低，请更新到最新版本"
}
```

---

## 踢人机制详解

### 1. Token 黑名单（登出保护）
```
用户主动登出 → access_token(jti) 加入 Redis 黑名单
Key: login:blacklist:token:{jti}    TTL: token剩余有效时间
```

### 2. 精准踢人（用户黑名单）
```
管理员 POST /admin/kick/user → userId 加入 Redis Set
Key: login:blacklist:user:set {userId1, userId2, ...}
     login:blacklist:user:kick_time:{userId} → 踢出时间戳
     login:blacklist:user:kick_reason:{userId} → 踢出原因

效果：该用户的所有 token 立即失效，refresh_token 被删除，
      下次请求时 Gateway 检查 Set → 返回 401
```

### 3. 批量踢人（版本控制）
```
管理员 POST /admin/version/min → 设置最低版本号
Key: login:version:min → "1.5.0"
     login:version:kick_message → "请更新到最新版本"
     login:version:blacklist:set → {"1.3.0", "1.2.0"}

效果：所有客户端版本 < 1.5.0 的请求 → 返回 426 Upgrade Required
      版本在 blacklist:set 中的请求 → 精确封禁
```

---

## Nacos 配置中心

### 配置优先级
```
Nacos 共享配置 (shared-*.yaml)
    ↓ 覆盖
Nacos 扩展配置 (gateway-routes.yaml)
    ↓ 覆盖
本地 application.yml
```

### 动态刷新
Nacos 中的配置修改后，通过 `@RefreshScope` 或 `@ConfigurationProperties` 注解，
配置会自动刷新到应用中，**无需重启服务**。

可动态刷新的配置：
- 白名单路径
- 最低版本号
- 版本黑名单
- 踢出提示消息
- Gateway 路由规则

---

## Redis Key 设计

```
login-service (命名空间)
│
├── login:refresh_token:{userId}              # refresh_token 存储
│
├── login:blacklist:token:{jti}               # Token 黑名单（登出）
│   └── TTL: token剩余有效时间
│
├── login:blacklist:user:set                  # 用户黑名单 Set（精准踢人）
├── login:blacklist:user:kick_time:{userId}   # 被踢时间戳
├── login:blacklist:user:kick_reason:{userId} # 被踢原因
│
├── login:version:min                         # 最低允许版本号
├── login:version:kick_message                # 版本过期提示
├── login:version:blacklist:set               # 版本黑名单 Set
│
├── login:whitelist:paths                     # 动态白名单路径 Set
│
└── login:online:users                        # 在线用户 Set
```

---

## 安全设计

### JWT Token 安全
- **双 Token 机制**：access_token（30分钟）+ refresh_token（7天）
- **Refresh Token Rotation**：每次刷新时同时轮转两个 Token，防止 refresh_token 被盗用
- **签名算法**：HMAC-SHA256（对称密钥）
- **Token 黑名单**：登出后 token 加入黑名单，防止 token 在有效期内被复用

### 踢人安全
- **多层防护**：Token黑名单 + 用户黑名单 + 版本控制
- **防绕过**：踢人时同时删除 refresh_token，用户无法通过刷新获取新 token
- **审计记录**：记录踢出时间、原因、操作人

### API 安全
- **Gateway 统一入口**：所有请求经过 Gateway，不暴露内部服务
- **OAuth2 资源服务器**：标准的 JWT Bearer Token 鉴权
- **角色控制**：admin 角色才能访问管理接口

---

## 部署说明

### 生产环境 checklist
- [ ] 修改 JWT 签名密钥为强随机密钥（从环境变量或配置中心读取）
- [ ] 修改 MySQL 密码为强密码
- [ ] 设置 Redis 密码
- [ ] 修改 Nacos 默认密码
- [ ] 创建独立的 Nacos 命名空间（不使用 public）
- [ ] 关闭 MyBatis SQL 日志输出
- [ ] 配置 HTTPS 证书
- [ ] 配置 CORS 允许的具体域名（不使用 *）
- [ ] 限制管理接口的访问 IP（白名单）

---

## 项目命令

```bash
# 编译整个项目
mvn clean compile

# 打包
mvn clean package -DskipTests

# 启动指定模块
mvn -pl login-gateway spring-boot:run
mvn -pl login-auth spring-boot:run
mvn -pl login-user spring-boot:run
mvn -pl login-admin spring-boot:run
```
