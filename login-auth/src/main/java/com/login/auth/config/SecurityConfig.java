package com.login.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Spring Security 配置 — auth-service 的安全策略
 * <p>
 * auth-service 的定位：
 * 1. 认证端点（/auth/**）对 Gateway 公开 — 不需要 JWT
 * 2. 管理端点（/admin/**）受 JWT 保护 — 仅管理员可访问
 * </p>
 *
 * <h3>架构说明：</h3>
 * <ul>
 *   <li>JWT 鉴权由 Gateway 统一处理，auth-service 信任 Gateway 透传的 header</li>
 *   <li>auth-service 自身的 Security 配置较宽松，主要用于密码加密和认证管理器</li>
 *   <li>/admin/** 端点的访问控制可以在这里做二次兜底</li>
 * </ul>
 *
 * @author login-service
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity  // 启用方法级安全注解（@PreAuthorize, @Secured 等）
public class SecurityConfig {

    /**
     * BCrypt 密码编码器
     * <p>
     * BCrypt 是一种自适应哈希算法，可以调节计算强度（strength/log rounds）。
     * 默认 strength=10，每次生成的 salt 不同，相同密码的密文也不同。
     * </p>
     *
     * @return PasswordEncoder 实例
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * DaoAuthenticationProvider — Spring Security 自动密码校验的核心
     * <p>
     * 认证流程：
     * 1. UserDetailsService.loadUserByUsername() → 从数据库加载用户
     * 2. PasswordEncoder.matches(rawPassword, encodedPassword) → 比对密码
     * 3. 检查 UserDetails 的状态（isEnabled, isAccountNonLocked...）
     * 4. 返回已认证的 Authentication 对象
     * </p>
     *
     * @param userDetailsService 用户详情服务（从数据库加载用户）
     * @param passwordEncoder    密码编码器（BCrypt）
     * @return DaoAuthenticationProvider 实例
     */
    @Bean
    public DaoAuthenticationProvider authenticationProvider(UserDetailsService userDetailsService,
                                                            PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        // 隐藏"用户不存在"的详细信息，防止用户名枚举攻击
        provider.setHideUserNotFoundExceptions(false);
        return provider;
    }

    /**
     * AuthenticationManager — 认证管理器
     * <p>
     * 暴露为 Bean，供 AuthService 注入使用。
     * 调用 authenticate() 方法即可自动完成用户名密码校验。
     * </p>
     *
     * @param config AuthenticationConfiguration
     * @return AuthenticationManager 实例
     * @throws Exception 配置异常
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    /**
     * 安全过滤链 — HTTP 安全策略
     * <p>
     * 策略说明：
     * - /auth/**   → 公开访问（登录、注册、刷新 token）
     * - /admin/**  → 需要 ADMIN 角色（双重保护：Gateway + 本地）
     * - /actuator/** → 公开访问（健康检查）
     * - 其他路径   → 需要认证
     * </p>
     * <p>
     * 注意：Gateway 已经做了 JWT 校验并透传用户信息（X-User-Id, X-User-Role），
     * auth-service 这里的 Security 配置是"纵深防御"的第二层。
     * </p>
     *
     * @param http HttpSecurity
     * @return SecurityFilterChain
     * @throws Exception 配置异常
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // ── 1. 禁用 CSRF — 前后端分离 + JWT 无状态，不需要 CSRF 保护 ──
                .csrf(AbstractHttpConfigurer::disable)

                // ── 2. 无状态 Session — 不创建 HttpSession，不依赖 Cookie ──
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // ── 3. URL 访问控制 ──
                .authorizeHttpRequests(auth -> auth
                        // 认证接口：公开访问
                        .requestMatchers("/auth/**").permitAll()
                        // 健康检查：公开访问
                        .requestMatchers("/actuator/**").permitAll()
                        // 管理接口：仅 ADMIN 角色可访问
                        // Spring Security 自动加 ROLE_ 前缀，所以 hasRole("admin") 匹配 ROLE_admin
                        .requestMatchers("/admin/**").hasRole("admin")
                        // 其他路径：需要认证
                        .anyRequest().authenticated()
                )

                // ── 4. 禁用默认的登录页和表单登录 ──
                // 使用自定义的 /auth/login 接口
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)

                // ── 5. 异常处理 ──
                .exceptionHandling(exceptions -> exceptions
                        // 未认证（401）
                        .authenticationEntryPoint((request, response, authException) -> {
                            response.setContentType("application/json;charset=UTF-8");
                            response.setStatus(401);
                            response.getWriter().write(
                                    "{\"code\":401,\"message\":\"未登录或 token 已失效\",\"data\":null}");
                        })
                        // 无权限（403）
                        .accessDeniedHandler((request, response, accessDeniedException) -> {
                            response.setContentType("application/json;charset=UTF-8");
                            response.setStatus(403);
                            response.getWriter().write(
                                    "{\"code\":403,\"message\":\"权限不足，仅管理员可访问\",\"data\":null}");
                        })
                );

        return http.build();
    }
}
