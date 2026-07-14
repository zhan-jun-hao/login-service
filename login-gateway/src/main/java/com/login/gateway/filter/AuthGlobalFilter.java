package com.login.gateway.filter;

import com.login.common.constant.RedisKey;
import com.login.common.context.UserContextHolder;
import com.login.common.utils.JwtUtil;
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
 * JWT 鉴权全局过滤器
 * <p>
 * 拦截所有请求，校验 JWT token 的有效性：
 * 1. 白名单路径直接放行（traceId 已由 TraceIdFilter 设置）
 * 2. 从 Authorization header 提取 Bearer token
 * 3. 校验 JWT 签名 + 过期时间
 * 4. 检查 token 是否在黑名单（已登出）
 * 5. 校验通过后，将 userId、role 写入 header 传递给下游服务
 * 6. 设置 UserContextHolder（ThreadLocal），请求结束后自动清理
 * </p>
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AuthGlobalFilter implements GlobalFilter, Ordered {

    // 响应式redisTemplate
    private final ReactiveStringRedisTemplate redisTemplate;
    // 用来匹配URL路径的工具类 支持Ant风格的路径表达式 * ** ? 等通配符
    private final AntPathMatcher antPathMatcher = new AntPathMatcher();
    // 白名单配置文件
    private final WhitelistProperties whitelistProperties;
    // token前缀
    private static final String BEARER_PREFIX = "Bearer ";


    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // 1. 获得当前URL
        String path = exchange.getRequest().getURI().getPath();

        // 2. 白名单放行
        if (isWhitelist(path)) {
            log.debug("白名单路径放行: {}", path);
            return chain.filter(exchange);
        }

        // 3. 提取 Authorization header
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            log.warn("缺少 Authorization header: {}", path);
            return unauthorized(exchange, "未提供有效的认证信息");
        }

        // 4. 解析token
        String token = authHeader.substring(BEARER_PREFIX.length()).trim();

        // 5. 校验 JWT
        Claims claims = JwtUtil.validateAndGetClaims(token);
        if (claims == null) {
            log.warn("JWT 校验失败: {}", path);
            return unauthorized(exchange, "token 无效");
        }

        // 必须是 access_token 类型 因为refresh_token不能放行 因为refresh_token是旧的token
        if (!JwtUtil.TOKEN_TYPE_ACCESS.equals(JwtUtil.getTokenType(claims))) {
            log.warn("token 类型不正确: path={}, type={}", path, JwtUtil.getTokenType(claims));
            return unauthorized(exchange, "请使用 access_token 访问");
        }

        Long userId = JwtUtil.getUserId(claims);
        if (userId == null) {
            log.warn("token 缺少用户信息: {}", path);
            return unauthorized(exchange, "token 格式不正确");
        }

        // 从 claims 中提取角色
        String role = JwtUtil.getRole(claims);

        // 从请求头获取 traceId
        String traceId = exchange.getRequest().getHeaders().getFirst("X-Trace-Id");

        // 6. 检查黑名单 是否已登出
        String jti = claims.getId();  // 1. 从 Token 里取出 jti 唯一ID
        if (jti != null) {            // 2. 如果有 jti 防止空指针
            String blacklistKey = RedisKey.tokenBlacklistKey(jti);  // 3. 拼 Redis key

            return redisTemplate.hasKey(blacklistKey)  // 4. 查 Redis 返回的是 Mono<Boolean>
                    .flatMap(isBlacklisted -> {        // 5. 处理查询结果
                        if (Boolean.TRUE.equals(isBlacklisted)) {  // 6. 如果在黑名单
                            log.warn("token 已被加入黑名单: userId={}", userId);
                            return unauthorized(exchange, "token 已失效，请重新登录");
                        }
                        // 7. 不在黑名单 → 设置上下文并放行
                        return forwardWithUserContext(exchange, chain, userId, role, traceId);
                    });
        }

        // 7. 放行
        return forwardWithUserContext(exchange, chain, userId, role, traceId);
    }

    /**
     * 放行请求并在 header 中注入 userId、role（traceId 已由 TraceIdFilter 设置）
     * <p>
     * 同时设置 UserContextHolder，请求结束后自动清理。
     * </p>
     */
    private Mono<Void> forwardWithUserContext(ServerWebExchange exchange, GatewayFilterChain chain,
                                               Long userId, String role, String traceId) {
        // 设置 ThreadLocal 上下文
        UserContextHolder.set(userId, traceId);

        // 向下游服务透传 userId、role
        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                .header("X-User-Id", String.valueOf(userId))
                .header("X-User-Role", role != null ? role : "user")
                .build();
        ServerWebExchange mutatedExchange = exchange.mutate().request(mutatedRequest).build();

        return chain.filter(mutatedExchange)
                .doFinally(signalType -> {
                    // 请求结束后清理 ThreadLocal，防止内存泄漏
                    UserContextHolder.clear();
                });
    }

    /**
     * 返回 401 未授权
     */
    private Mono<Void> unauthorized(ServerWebExchange exchange, String message) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        String body = String.format("{\"code\":401,\"message\":\"%s\",\"data\":null}", message);
        DataBuffer buffer = response.bufferFactory()
                .wrap(body.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
    }

    /**
     * 判断请求路径是否在白名单中
     */
    private boolean isWhitelist(String path) {
        return whitelistProperties.getPaths()
                .stream().anyMatch(whitePath -> antPathMatcher.match(whitePath, path));
    }

    @Override
    public int getOrder() {
        // 在 TraceIdFilter (-200) 之后、NettyWriteResponseFilter (-1) 之前执行
        return -100;
    }
}
