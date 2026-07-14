package com.login.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Spring Security 配置
 * <p>
 * auth-service 的 Security 负责：
 * 1. 密码加密（BCrypt）
 * 2. 通过 DaoAuthenticationProvider 自动校验用户密码
 * 3. JWT 鉴权由 Gateway 统一处理
 * </p>
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /**
     * BCrypt 密码编码器
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * DaoAuthenticationProvider — Spring Security 自动密码校验的核心
     * <p>
     * 负责：加载用户信息 → 比对密码 → 返回已认证的 Authentication
     * </p>
     */
    @Bean
    public DaoAuthenticationProvider authenticationProvider(UserDetailsService userDetailsService,
                                                            PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        // 设置 UserDetailsService（从数据库加载用户）
        provider.setUserDetailsService(userDetailsService);
        // 设置密码编码器（BCrypt）
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }

    /**
     * AuthenticationManager — 认证管理器
     * <p>
     * 注入到 AuthService 中，调用 authenticate() 自动完成用户名密码校验。
     * </p>
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    /**
     * 安全过滤链
     * <p>
     * auth-service 的所有接口对 gateway 放行，
     * 认证逻辑由 AuthService 调用 AuthenticationManager 完成。
     * </p>
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // 禁用 CSRF（前后端分离 + JWT 无状态）
                .csrf(AbstractHttpConfigurer::disable)
                // 无状态 session
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // 放行与拦截url
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/**").permitAll()
                        // 它自动帮你加了 ROLE_ 前缀
                        .requestMatchers("/admin/**").hasRole("admin")
                        .anyRequest().authenticated())
                // 不用默认的登录接口
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable);

        return http.build();
    }
}
