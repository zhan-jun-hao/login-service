package com.login.gateway.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

/**
 * OAuth2 资源服务器配置 — Gateway 作为 OAuth2 资源服务器
 * <p>
 * Gateway 不创建 session，完全无状态。每次请求通过 JWT 进行身份认证。
 * 此配置让 Spring Security 自动解析和校验 JWT token，
 * 但具体的鉴权逻辑（白名单、黑名单、版本控制）由 AuthGlobalFilter 实现。
 * </p>
 *
 * <h3>安全架构：</h3>
 * <ol>
 *   <li>OAuth2 Resource Server：自动校验 JWT 签名和过期时间</li>
 *   <li>AuthGlobalFilter：白名单 → 用户黑名单 → 版本控制 → Token 黑名单</li>
 *   <li>SecurityWebFilterChain：放行所有请求（具体鉴权交给 Filter）</li>
 * </ol>
 *
 * @author login-service
 */
@Slf4j
@Configuration
@EnableWebFluxSecurity
public class ResourceServerConfig {

    /**
     * JWT 签名密钥 — 与 auth-service 使用相同的对称密钥
     * <p>
     * Gateway 本地校验 JWT 签名，无需远程调用 auth-service。
     * 生产环境应从 Nacos 配置中心读取。
     * </p>
     */
    private static final String JWT_SECRET = "login-service-jwt-secret-key-2024-must-be-at-least-256-bits-long!!";

    /**
     * 响应式 JWT 解码器
     * <p>
     * 使用 NimbusReactiveJwtDecoder + HMAC-SHA256 对称密钥，
     * Gateway 本地校验 JWT 签名和过期时间。
     * </p>
     *
     * @return ReactiveJwtDecoder 实例
     */
    @Bean
    public ReactiveJwtDecoder reactiveJwtDecoder() {
        // 创建 HMAC-SHA256 密钥
        SecretKey secretKey = new SecretKeySpec(
                JWT_SECRET.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        return NimbusReactiveJwtDecoder.withSecretKey(secretKey).build();
    }

    /**
     * 安全过滤链 — Gateway 的 Security 配置
     * <p>
     * 策略说明：
     * 1. 禁用 CSRF（前后端分离 + JWT 无状态）
     * 2. 无状态 session（不创建 HttpSession，不依赖 Cookie）
     * 3. 启用 OAuth2 Resource Server JWT 支持
     * 4. 放行所有请求 — 具体鉴权由 AuthGlobalFilter（GlobalFilter）实现
     * </p>
     * <p>
     * 为什么放行所有请求？
     * Gateway 的鉴权逻辑包含白名单、用户黑名单、版本控制等复杂判断，
     * Spring Security 的声明式配置不够灵活，
     * 因此统一交给 AuthGlobalFilter（GlobalFilter）处理。
     * </p>
     *
     * @param http ServerHttpSecurity
     * @return SecurityWebFilterChain
     */
    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http
                // ── 禁用 CSRF — 前后端分离 + JWT 无状态 ──
                .csrf(ServerHttpSecurity.CsrfSpec::disable)

                // ── 禁用默认的登录页和表单登录 ──
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)

                // ── 无状态 Session — 不创建 HttpSession ──
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())

                // ── 启用 OAuth2 Resource Server JWT 支持 ──
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt
                                // 使用自定义的 JWT 解码器（本地 HMAC 校验）
                                .jwtDecoder(reactiveJwtDecoder())
                        )
                )

                // ── 放行所有请求（具体鉴权由 AuthGlobalFilter 实现） ──
                .authorizeExchange(exchanges -> exchanges
                        .anyExchange().permitAll()
                );

        return http.build();
    }
}
