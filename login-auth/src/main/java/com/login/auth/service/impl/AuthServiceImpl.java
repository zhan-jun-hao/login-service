package com.login.auth.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.login.auth.config.SecurityUser;
import com.login.auth.entity.User;
import com.login.auth.mapper.UserMapper;
import com.login.auth.service.AuthService;
import com.login.common.constant.RedisKey;
import com.login.common.model.LoginUser;
import com.login.common.model.Result;
import com.login.common.model.TokenResult;
import com.login.common.utils.JwtUtil;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

/**
 * 认证服务实现
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;
    private final StringRedisTemplate stringRedisTemplate;
    // Spring Security 认证管理器 — 自动调用 UserDetailsService + PasswordEncoder 完成校验
    private final AuthenticationManager authenticationManager;

    @Override
    public Result<Void> register(String username, String password, String nickname) {
        // 检查用户名是否已存在
        Long count = userMapper.selectCount(
                new LambdaQueryWrapper<User>().eq(User::getUsername, username));
        if (count > 0) {
            return Result.fail("用户名已存在");
        }

        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));
        user.setNickname(nickname != null ? nickname : username);
        // 默认角色：普通用户
        user.setRole("user");
        user.setStatus(1);

        userMapper.insert(user);
        log.info("用户注册成功: username={}", username);
        return Result.ok();
    }

    @Override
    public Result<TokenResult> login(String username, String password) {
        // 使用 Spring Security 的 AuthenticationManager 自动校验用户名和密码
        // 内部会调用 UserDetailsService.loadUserByUsername() → DaoAuthenticationProvider 比对密码
        // 1. 创建认证令牌
        UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(username, password);
        Authentication authentication;
        try {
            // 2. 交给 Security 自动认证
            //    ↓ 自动做了：
            //    a. 调用 UserDetailsService.loadUserByUsername()
            //    b. 返回 SecurityUser（含密码、状态、权限）
            //    c. 用 PasswordEncoder 比对密码
            //    d. 检查 isEnabled()、isAccountNonLocked()...
            authentication = authenticationManager.authenticate(authToken);

        } catch (BadCredentialsException e) {
            // 密码错误
            return Result.fail("用户名或密码错误");
        } catch (DisabledException e) {
            // 账号被禁用
            return Result.fail("账号已被禁用");
        } catch (Exception e) {
            log.error("登录认证异常: {}", e.getMessage(), e);
            return Result.fail("登录失败");
        }

        // 认证成功，从 principal 中提取用户信息
        SecurityUser securityUser = (SecurityUser) authentication.getPrincipal();

        // 构建登录用户信息
        LoginUser loginUser = LoginUser.builder()
                .userId(securityUser.getUserId())
                .username(securityUser.getUsername())
                .nickname(securityUser.getNickname())
                .role(securityUser.getRole())
                .build();

        // 生成 token
        String accessToken = JwtUtil.generateAccessToken(loginUser);
        String refreshToken = JwtUtil.generateRefreshToken(loginUser);

        // refresh_token 存入 Redis
        String redisKey = RedisKey.refreshTokenKey(securityUser.getUserId());
        stringRedisTemplate.opsForValue()
                .set(redisKey, refreshToken, JwtUtil.REFRESH_TOKEN_EXPIRE, TimeUnit.MILLISECONDS);

        log.info("用户登录成功: userId={}, username={}, role={}", securityUser.getUserId(), username, securityUser.getRole());

        TokenResult result = TokenResult.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .expiresIn(JwtUtil.ACCESS_TOKEN_EXPIRE / 1000)
                .tokenType("Bearer")
                .build();

        return Result.ok(result);
    }

    @Override
    public Result<TokenResult> refreshToken(String refreshToken) {
        // 校验 refresh_token
        if (refreshToken == null || refreshToken.isBlank()) {
            return Result.unauthorized("refresh_token 不能为空");
        }

        Claims claims = JwtUtil.validateAndGetClaims(refreshToken);
        if (claims == null) {
            return Result.unauthorized("refresh_token 无效");
        }

        // 必须是 refresh 类型的 token
        if (!JwtUtil.TOKEN_TYPE_REFRESH.equals(JwtUtil.getTokenType(claims))) {
            return Result.unauthorized("token 类型不正确，需要 refresh_token");
        }

        Long userId = JwtUtil.getUserId(claims);
        if (userId == null) {
            return Result.unauthorized("token 中缺少用户信息");
        }

        // 检查 Redis 中是否存在该 refresh_token
        String redisKey = RedisKey.refreshTokenKey(userId);
        String storedToken = stringRedisTemplate.opsForValue().get(redisKey);
        if (storedToken == null || !storedToken.equals(refreshToken)) {
            return Result.unauthorized("refresh_token 已失效或已过期");
        }

        // 查询用户是否仍然有效
        User user = userMapper.selectById(userId);
        if (user == null || user.getStatus() == 0) {
            // 清理 Redis 中的 refresh_token
            stringRedisTemplate.delete(redisKey);
            return Result.fail("用户不存在或已被禁用");
        }

        // 签发新的 access_token + 新的 refresh_token（refresh 轮转）
        LoginUser loginUser = LoginUser.builder()
                .userId(user.getId())
                .username(user.getUsername())
                .nickname(user.getNickname())
                .role(user.getRole())
                .build();

        String newAccessToken = JwtUtil.generateAccessToken(loginUser);
        String newRefreshToken = JwtUtil.generateRefreshToken(loginUser);

        // 更新 Redis 中的 refresh_token
        stringRedisTemplate.opsForValue()
                .set(redisKey, newRefreshToken, JwtUtil.REFRESH_TOKEN_EXPIRE, TimeUnit.MILLISECONDS);

        log.info("token 刷新成功: userId={}", userId);

        TokenResult result = TokenResult.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .expiresIn(JwtUtil.ACCESS_TOKEN_EXPIRE / 1000)
                .tokenType("Bearer")
                .build();

        return Result.ok(result);
    }

    @Override
    public Result<Void> logout(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            return Result.ok();
        }

        Claims claims = JwtUtil.parseToken(rawToken);
        if (claims == null) {
            return Result.ok();
        }

        // 删除 Redis 中的 refresh_token
        Long userId = JwtUtil.getUserId(claims);
        if (userId != null) {
            stringRedisTemplate.delete(RedisKey.refreshTokenKey(userId));
        }

        // access_token 加入黑名单
        String jti = claims.getId();
        long remainingMs = JwtUtil.getRemainingMs(rawToken);
        if (jti != null && remainingMs > 0) {
            String blacklistKey = RedisKey.tokenBlacklistKey(jti);
            stringRedisTemplate.opsForValue()
                    .set(blacklistKey, "1", remainingMs, TimeUnit.MILLISECONDS);
        }

        log.info("用户登出成功: userId={}", userId);
        return Result.ok();
    }
}
