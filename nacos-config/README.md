# Nacos 配置导入说明

## 配置列表

将以下配置文件导入到 Nacos 配置中心（`public` 命名空间）：

| Data ID | Group | 类型 | 说明 |
|---------|-------|------|------|
| `shared-redis.yaml` | `DEFAULT_GROUP` | YAML | 共享 Redis 连接配置 |
| `shared-jwt.yaml` | `DEFAULT_GROUP` | YAML | 共享 JWT 密钥和白名单配置 |
| `gateway-routes.yaml` | `DEFAULT_GROUP` | YAML | Gateway 动态路由规则 |

## 导入方式

### 方式一：Nacos 控制台手动导入

1. 访问 http://localhost:8848/nacos
2. 登录（默认 nacos/nacos）
3. 进入「配置管理」→「配置列表」
4. 选择 `public` 命名空间
5. 点击「+」新建配置，分别填入上述 Data ID / Group，复制对应文件内容

### 方式二：API 导入

```bash
# shared-redis.yaml
curl -X POST "http://localhost:8848/nacos/v1/cs/configs" \
  -d "dataId=shared-redis.yaml&group=DEFAULT_GROUP&content=$(cat shared-redis.yaml | base64)&type=yaml"

# shared-jwt.yaml
curl -X POST "http://localhost:8848/nacos/v1/cs/configs" \
  -d "dataId=shared-jwt.yaml&group=DEFAULT_GROUP&content=$(cat shared-jwt.yaml | base64)&type=yaml"

# gateway-routes.yaml
curl -X POST "http://localhost:8848/nacos/v1/cs/configs" \
  -d "dataId=gateway-routes.yaml&group=DEFAULT_GROUP&content=$(cat gateway-routes.yaml | base64)&type=yaml"
```

## 配置内容说明

### shared-redis.yaml
所有微服务共享的 Redis 连接信息。修改后所有服务自动刷新（通过 `@RefreshScope`）。

### shared-jwt.yaml
JWT 签名密钥和白名单路径。**生产环境必须修改 secret 为强随机密钥**。

### gateway-routes.yaml
Gateway 的路由规则。修改后 Gateway 自动刷新路由表，无需重启。
