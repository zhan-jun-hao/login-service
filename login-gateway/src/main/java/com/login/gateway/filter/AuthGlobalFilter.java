package com.login.gateway.filter;

import com.login.common.constant.RedisKey;
import com.login.common.context.UserContextHolder;
import com.login.common.utils.JwtUtil;
import com.login.common.utils.VersionUtil;
import com.login.gateway.config.WhitelistProperties;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

/**
 * JWT 鉴权全局过滤器 — Gateway 的核心安全过滤器
 * <p>
 * 拦截所有经过 Gateway 的请求，按以下顺序进行安全校验：
 * </p>
 *
 * <h3>校验流程（链式拦截）：</h3>
 * <ol>
 *   <li><b>白名单检查</b>：配置的公开路径直接放行（如登录、注册接口）</li>
 *   <li><b>JWT 校验</b>：提取 Authorization header 中的 Bearer token，校验签名和类型</li>
 *   <li><b>Token 黑名单检查</b>：检查 token 是否已被加入黑名单（用户登出后 token 失效）</li>
 *   <li><b>用户黑名单检查（精准踢人）</b>：检查用户是否被管理员加入黑名单</li>
 *   <li><b>版本控制检查（批量踢人）</b>：检查客户端版本是否低于最低允许版本</li>
 *   <li><b>用户上下文注入</b>：校验全部通过后，将 userId、role、traceId 注入请求头</li>
 * </ol>
 *
 * <h3>精准踢人 vs 批量踢人：</h3>
 * <ul>
 *   <li><b>精准踢人</b>：管理员指定 userId 踢出单个用户，该用户所有 token 立即失效</li>
 *   <li><b>批量踢人</b>：管理员设置最低版本号，所有低于该版本的客户端全部被拦截</li>
 * </ul>
 *
 * @author login-service
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AuthGlobalFilter implements GlobalFilter, Ordered {

    // ==========================================
    // 依赖注入
    // ==========================================

    /** 响应式 Redis 客户端 — 用于查询黑名单、版本配置 */
    private final ReactiveStringRedisTemplate redisTemplate;

    /** 路径匹配器 — 支持 Ant 风格的通配符（如 /public/**） */
    private final AntPathMatcher antPathMatcher = new AntPathMatcher();

    /** 白名单配置 — 从 application.yml 的 jwt.whitelist.paths 加载 */
    private final WhitelistProperties whitelistProperties;

    // ==========================================
    // 常量
    // ==========================================

    /** Authorization 请求头中 Bearer token 的前缀 */
    private static final String BEARER_PREFIX = "Bearer ";

    /** 默认的版本过期提示消息 */
    private static final String DEFAULT_VERSION_KICK_MESSAGE = "您的客户端版本过低，请更新到最新版本后再使用";

    // ==========================================
    // 核心过滤逻辑
    // ==========================================

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // ────────────────────────────────────────
        // 第 1 步：获取当前请求路径
        // ────────────────────────────────────────
        String path = exchange.getRequest().getURI().getPath();

        // ────────────────────────────────────────
        // 第 2 步：白名单检查 — 公开路径直接放行
        // 登录、注册、健康检查等不需要鉴权的接口
        // ────────────────────────────────────────
        if (isWhitelist(path)) {
            log.debug("白名单路径放行: path={}", path);
            return chain.filter(exchange);
        }

        // ────────────────────────────────────────
        // 第 3 步：提取 Authorization header
        // ────────────────────────────────────────
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            log.warn("缺少 Authorization header: path={}", path);
            return unauthorized(exchange, "未提供有效的认证信息，请先登录");
        }

        // 提取 Bearer token（去掉 "Bearer " 前缀）
        String token = authHeader.substring(BEARER_PREFIX.length()).trim();

        // ────────────────────────────────────────
        // 第 4 步：JWT 校验 — 验证签名和类型
        // ────────────────────────────────────────
        Claims claims = JwtUtil.validateAndGetClaims(token);
        if (claims == null) {
            log.warn("JWT 签名校验失败: path={}", path);
            return unauthorized(exchange, "token 无效或签名错误");
        }

        // 必须是 access_token 类型（refresh_token 不能用于接口访问）
        if (!JwtUtil.TOKEN_TYPE_ACCESS.equals(JwtUtil.getTokenType(claims))) {
            log.warn("token 类型不正确: path={}, type={}", path, JwtUtil.getTokenType(claims));
            return unauthorized(exchange, "请使用 access_token 访问，refresh_token 仅用于刷新");
        }

        // 提取 JWT 中的用户信息
        Long userId = JwtUtil.getUserId(claims);
        if (userId == null) {
            log.warn("token 缺少用户信息: path={}", path);
            return unauthorized(exchange, "token 格式不正确，缺少用户标识");
        }

        String role = JwtUtil.getRole(claims);                    // 用户角色
        String clientVersion = JwtUtil.getClientVersion(claims);  // 客户端版本号
        String jti = claims.getId();                               // JWT 唯一 ID
        String traceId = exchange.getRequest().getHeaders().getFirst("X-Trace-Id");

        // ────────────────────────────────────────
        // 第 5 步：Token 黑名单检查（登出保护）
        // 用户主动登出后，token 被加入黑名单
        // ────────────────────────────────────────
        if (jti != null) {
            String tokenBlacklistKey = RedisKey.tokenBlacklistKey(jti);

            return redisTemplate.hasKey(tokenBlacklistKey)
                    .flatMap(isTokenBlacklisted -> {
                        if (Boolean.TRUE.equals(isTokenBlacklisted)) {
                            log.warn("token 已在黑名单中（已登出）: userId={}, jti={}", userId, jti);
                            return unauthorized(exchange, "token 已失效，请重新登录");
                        }
                        // ────────────────────────────────────────
                        // 第 6 步：用户黑名单检查（精准踢人）
                        // 管理员踢出指定用户，检查该 userId 是否在黑名单中
                        // ────────────────────────────────────────
                        return checkUserBlacklistAndVersion(
                                exchange, chain, userId, role, clientVersion, traceId);
                    });
        }

        // 没有 jti 的情况（理论不会发生），直接跳到用户黑名单和版本检查
        return checkUserBlacklistAndVersion(
                exchange, chain, userId, role, clientVersion, traceId);
    }

    // ==========================================
    // 第 6 步：用户黑名单检查（精准踢人）
    // ==========================================

    /**
     * 检查用户是否在管理员设置的黑名单中（精准踢人）
     * <p>
     * 如果用户在黑名单中，拒绝请求并返回被踢原因。
     * 如果不在黑名单中，继续执行版本检查。
     * </p>
     *
     * @param exchange      ServerWebExchange
     * @param chain         GatewayFilterChain
     * @param userId        用户 ID
     * @param role          用户角色
     * @param clientVersion 客户端版本号
     * @param traceId       链路追踪 ID
     * @return Mono<Void>
     */
    private Mono<Void> checkUserBlacklistAndVersion(ServerWebExchange exchange,
                                                     GatewayFilterChain chain,
                                                     Long userId, String role,
                                                     String clientVersion, String traceId) {
        // 检查用户是否在精准踢人黑名单中
        // Redis 命令：SISMEMBER login:blacklist:user:set <userId>
        return redisTemplate.opsForSet()
                .isMember(RedisKey.USER_BLACKLIST_SET_KEY, String.valueOf(userId))
                .flatMap(isBlacklisted -> {
                    if (Boolean.TRUE.equals(isBlacklisted)) {
                        // ─── 用户被精准踢出 ───
                        // 异步查询被踢原因（不阻塞主流程）
                        return redisTemplate.opsForValue()
                                .get(RedisKey.userKickReasonKey(userId))
                                .defaultIfEmpty("您的账号已被管理员踢出")
                                .flatMap(kickReason -> {
                                    log.warn("用户在黑名单中（精准踢人）: userId={}, reason={}", userId, kickReason);
                                    return unauthorized(exchange, kickReason);
                                });
                    }

                    // ────────────────────────────────────────
                    // 第 7 步：版本控制检查（批量踢人）
                    // 检查客户端版本是否 >= 最低允许版本
                    // ────────────────────────────────────────
                    return checkClientVersion(
                            exchange, chain, userId, role, clientVersion, traceId);
                });
    }

    // ==========================================
    // 第 7 步：版本控制检查（批量踢人）
    // ==========================================

    /**
     * 检查客户端版本是否满足最低版本要求（批量踢人）
     * <p>
     * 管理员设置最低版本号后，所有低于该版本的请求都会被拦截。
     * 用于强制用户升级 App（如安全漏洞修复、API 不兼容变更）。
     * </p>
     *
     * <h3>检查逻辑：</h3>
     * <ol>
     *   <li>从 Redis 读取最低允许版本号</li>
     *   <li>如果未设置最低版本，直接放行</li>
     *   <li>如果客户端未传版本号，视为版本过低，拒绝</li>
     *   <li>比较客户端版本与最低版本，低于则拒绝</li>
     *   <li>检查客户端版本是否在版本黑名单中（精确版本封禁）</li>
     * </ol>
     */
    private Mono<Void> checkClientVersion(ServerWebExchange exchange,
                                           GatewayFilterChain chain,
                                           Long userId, String role,
                                           String clientVersion, String traceId) {
        // 从 Redis 读取最低允许版本号
        return redisTemplate.opsForValue()
                .get(RedisKey.MIN_VERSION_KEY)
                .flatMap(minVersion -> {
                    // 如果设置了最低版本号（不为空），则进行校验
                    if (minVersion != null && !minVersion.isBlank()) {
                        // 检查客户端版本是否低于最低版本
                        if (VersionUtil.isLessThan(clientVersion, minVersion)) {
                            // 客户端版本过低 → 拒绝请求
                            return redisTemplate.opsForValue()
                                    .get(RedisKey.VERSION_KICK_MESSAGE_KEY)
                                    .defaultIfEmpty(DEFAULT_VERSION_KICK_MESSAGE)
                                    .flatMap(kickMessage -> {
                                        log.warn("客户端版本过低被拦截: userId={}, clientVersion={}, minVersion={}",
                                                userId, clientVersion, minVersion);
                                        // 返回 426 Upgrade Required（要求客户端升级）
                                        return versionBlocked(exchange, minVersion, kickMessage);
                                    });
                        }
                    }

                    // ─── 版本校验通过 → 检查版本黑名单（精确版本封禁） ───
                    return checkVersionBlacklist(
                            exchange, chain, userId, role, clientVersion, traceId);
                })
                // 如果 Redis 中没有设置最低版本号，直接跳过版本校验
                .switchIfEmpty(
                        checkVersionBlacklist(exchange, chain, userId, role, clientVersion, traceId)
                );
    }

    /**
     * 检查客户端版本是否在版本黑名单中（精确版本封禁）
     * <p>
     * 用于封禁某个已知有严重问题的特定版本。
     * 与最低版本控制的区别：
     * - 最低版本控制：封禁所有低于某版本的客户端（范围封禁）
     * - 版本黑名单：封禁特定的版本号（精确封禁）
     * </p>
     */
    private Mono<Void> checkVersionBlacklist(ServerWebExchange exchange,
                                              GatewayFilterChain chain,
                                              Long userId, String role,
                                              String clientVersion, String traceId) {
        // 如果客户端没有传版本号，跳过版本黑名单检查
        if (clientVersion == null || clientVersion.isBlank()) {
            return forwardWithUserContext(exchange, chain, userId, role, traceId);
        }

        // 检查版本是否在黑名单中
        return redisTemplate.opsForSet()
                .isMember(RedisKey.VERSION_BLACKLIST_SET_KEY, clientVersion)
                .flatMap(isVersionBlacklisted -> {
                    if (Boolean.TRUE.equals(isVersionBlacklisted)) {
                        log.warn("客户端版本在黑名单中: userId={}, version={}", userId, clientVersion);
                        return versionBlocked(exchange, null,
                                "您当前的客户端版本（" + clientVersion + "）已被禁用，请更新到最新版本");
                    }
                    // 所有校验通过，放行请求
                    return forwardWithUserContext(exchange, chain, userId, role, traceId);
                });
    }

    // ==========================================
    // 放行请求 + 用户上下文注入
    // ==========================================

    /**
     * 所有校验通过后，放行请求并在请求头中注入用户信息
     * <p>
     * 向下游服务透传：
     * - X-User-Id：用户 ID
     * - X-User-Role：用户角色
     * - X-Trace-Id：链路追踪 ID（由 TraceIdFilter 生成）
     * </p>
     * <p>
     * 同时设置 UserContextHolder（ThreadLocal），
     * 并在请求结束后自动清理，防止内存泄漏。
     * </p>
     *
     * @param exchange ServerWebExchange
     * @param chain    GatewayFilterChain
     * @param userId   用户 ID
     * @param role     用户角色
     * @param traceId  链路追踪 ID
     * @return Mono<Void>
     */
    private Mono<Void> forwardWithUserContext(ServerWebExchange exchange,
                                               GatewayFilterChain chain,
                                               Long userId, String role, String traceId) {
        // 设置 ThreadLocal 上下文（供业务代码通过 UserContextHolder 获取）
        UserContextHolder.set(userId, traceId);

        // 向下游服务透传用户信息（通过请求头）
        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                .header("X-User-Id", String.valueOf(userId))
                .header("X-User-Role", role != null ? role : "user")
                // 如果上游没有 traceId，这里补充一个
                .header("X-Trace-Id", traceId != null ? traceId : "")
                .build();

        ServerWebExchange mutatedExchange = exchange.mutate()
                .request(mutatedRequest)
                .build();

        log.debug("JWT 校验全部通过: userId={}, role={}, path={}",
                userId, role, exchange.getRequest().getURI().getPath());

        // 放行请求，并在请求结束后清理 ThreadLocal
        return chain.filter(mutatedExchange)
                .doFinally(signalType -> {
                    UserContextHolder.clear();
                    log.trace("请求结束，清理 UserContextHolder: signalType={}", signalType);
                });
    }

    // ==========================================
    // 错误响应
    // ==========================================

    /**
     * 返回 401 未授权响应（鉴权失败）
     *
     * @param exchange ServerWebExchange
     * @param message  错误提示消息
     * @return Mono<Void>
     */
    private Mono<Void> unauthorized(ServerWebExchange exchange, String message) {
        return writeJsonResponse(exchange, HttpStatus.UNAUTHORIZED, 401, message);
    }

    /**
     * 返回 426 Upgrade Required 响应（版本过低，需要升级客户端）
     * <p>
     * HTTP 426 状态码的含义：服务器拒绝使用当前协议处理请求，
     * 客户端必须升级到新版本后才能继续使用。
     * 这里用来提示用户更新 App。
     * </p>
     *
     * @param exchange    ServerWebExchange
     * @param minVersion  最低要求的版本号
     * @param kickMessage 提示消息
     * @return Mono<Void>
     */
    private Mono<Void> versionBlocked(ServerWebExchange exchange, String minVersion, String kickMessage) {
        // 构建响应体
        String body;
        if (minVersion != null) {
            body = String.format(
                    "{\"code\":426,\"message\":\"%s\",\"data\":{\"minVersion\":\"%s\",\"requireUpgrade\":true}}",
                    escapeJson(kickMessage), escapeJson(minVersion));
        } else {
            body = String.format(
                    "{\"code\":426,\"message\":\"%s\",\"data\":{\"requireUpgrade\":true}}",
                    escapeJson(kickMessage));
        }
        return writeJsonBody(exchange, HttpStatus.UPGRADE_REQUIRED, 426, body);
    }

    /**
     * 写入 JSON 响应到客户端（将消息包装为标准 JSON 格式）
     *
     * @param exchange   ServerWebExchange
     * @param httpStatus HTTP 状态码
     * @param code       业务状态码
     * @param message    错误消息
     * @return Mono<Void>
     */
    private Mono<Void> writeJsonResponse(ServerWebExchange exchange, HttpStatus httpStatus,
                                          int code, String message) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        // 禁止缓存错误响应
        response.getHeaders().set(HttpHeaders.CACHE_CONTROL, "no-store");

        String body = String.format("{\"code\":%d,\"message\":\"%s\",\"data\":null}",
                code, escapeJson(message));
        DataBuffer buffer = response.bufferFactory()
                .wrap(body.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
    }

    /**
     * 写入预格式化的 JSON 响应体（已包含完整 JSON 结构的 body）
     *
     * @param exchange   ServerWebExchange
     * @param httpStatus HTTP 状态码
     * @param code       业务状态码
     * @param jsonBody   预格式化的 JSON 字符串
     * @return Mono<Void>
     */
    private Mono<Void> writeJsonBody(ServerWebExchange exchange, HttpStatus httpStatus,
                                      int code, String jsonBody) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        response.getHeaders().set(HttpHeaders.CACHE_CONTROL, "no-store");

        DataBuffer buffer = response.bufferFactory()
                .wrap(jsonBody.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
    }

    // ==========================================
    // 工具方法
    // ==========================================

    /**
     * JSON 字符串转义 — 防止特殊字符破坏 JSON 格式
     *
     * @param str 原始字符串
     * @return 转义后的字符串
     */
    private String escapeJson(String str) {
        if (str == null) {
            return "";
        }
        return str.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    /**
     * 判断请求路径是否在白名单中（无需鉴权）
     *
     * @param path 请求路径
     * @return true 表示在白名单中
     */
    private boolean isWhitelist(String path) {
        // 从配置文件读取的白名单路径
        if (whitelistProperties.getPaths() != null) {
            boolean matched = whitelistProperties.getPaths()
                    .stream()
                    .anyMatch(whitePath -> antPathMatcher.match(whitePath, path));
            if (matched) {
                return true;
            }
        }
        return false;
    }

    // ==========================================
    // 排序
    // ==========================================

    @Override
    public int getOrder() {
        // 执行顺序：
        // TraceIdFilter: -200（最先执行，生成 traceId）
        // AuthGlobalFilter: -100（在 TraceIdFilter 之后执行）
        // NettyWriteResponseFilter: -1（Netty 内置，最后执行）
        return -100;
    }
}
