package com.login.auth.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.login.auth.config.SecurityUser;
import com.login.auth.entity.User;
import com.login.auth.mapper.UserMapper;
import com.login.auth.service.AuthService;
import com.login.common.constant.RedisKey;
import com.login.common.model.KickRecord;
import com.login.common.model.LoginUser;
import com.login.common.model.Result;
import com.login.common.model.TokenResult;
import com.login.common.model.VersionConfig;
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

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * 认证服务实现 — 用户认证 + 管理员踢人管理
 * <p>
 * 整合了 Spring Security 认证框架和 Redis 缓存，
 * 提供完整的用户认证、Token 管理、黑名单/版本控制功能。
 * </p>
 *
 * <h3>踢人机制（三层防护）：</h3>
 * <ol>
 *   <li><b>Token 黑名单</b>：用户主动登出 → token(jti) 加入黑名单 → TTL=剩余有效期</li>
 *   <li><b>用户黑名单（精准踢人）</b>：管理员踢出 → userId 加入 Set → 所有 token 立即失效</li>
 *   <li><b>版本控制（批量踢人）</b>：管理员设最低版本 → 低于该版本的客户端全部拦截</li>
 * </ol>
 *
 * @author login-service
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    // ==========================================
    // 依赖注入
    // ==========================================

    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;
    private final StringRedisTemplate stringRedisTemplate;
    /** Spring Security 认证管理器 — 调用 authenticate() 自动完成密码校验 */
    private final AuthenticationManager authenticationManager;

    // ==========================================
    // 一、用户认证
    // ==========================================

    @Override
    public Result<Void> register(String username, String password, String nickname) {
        // ── 1. 检查用户名唯一性 ──
        Long count = userMapper.selectCount(
                new LambdaQueryWrapper<User>().eq(User::getUsername, username));
        if (count > 0) {
            return Result.fail("用户名已存在");
        }

        // ── 2. 创建用户 ──
        User user = new User();
        user.setUsername(username);
        // BCrypt 加密密码（相同密码每次生成的密文不同，安全性高）
        user.setPassword(passwordEncoder.encode(password));
        user.setNickname(nickname != null ? nickname : username);
        user.setRole("user");   // 默认角色：普通用户
        user.setStatus(1);      // 状态：正常

        userMapper.insert(user);
        log.info("用户注册成功: username={}, userId={}", username, user.getId());
        return Result.ok();
    }

    @Override
    public Result<TokenResult> login(String username, String password, String clientVersion) {
        // ── 1. Spring Security 自动认证 ──
        // authenticate() 内部自动执行：
        //   a. UserDetailsService.loadUserByUsername() → 从数据库加载用户
        //   b. DaoAuthenticationProvider → 比对 BCrypt 密码
        //   c. 检查账户状态：isEnabled(), isAccountNonLocked(), etc.
        UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(username, password);
        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(authToken);
        } catch (BadCredentialsException e) {
            // 密码不匹配
            return Result.fail("用户名或密码错误");
        } catch (DisabledException e) {
            // 账号被禁用（status != 1）
            return Result.fail("账号已被禁用，请联系管理员");
        } catch (Exception e) {
            log.error("登录认证异常: {}", e.getMessage(), e);
            return Result.fail("登录失败，请稍后重试");
        }

        // ── 2. 提取认证通过的用户信息 ──
        SecurityUser securityUser = (SecurityUser) authentication.getPrincipal();

        // ── 3. 检查用户是否在黑名单中（被管理员踢出） ──
        Boolean isBlacklisted = stringRedisTemplate.opsForSet()
                .isMember(RedisKey.USER_BLACKLIST_SET_KEY, String.valueOf(securityUser.getUserId()));
        if (Boolean.TRUE.equals(isBlacklisted)) {
            log.warn("黑名单用户尝试登录被拒绝: userId={}, username={}",
                    securityUser.getUserId(), username);
            return Result.fail("您的账号已被限制登录，请联系管理员");
        }

        // ── 4. 构建 LoginUser（写入 JWT） ──
        LoginUser loginUser = LoginUser.builder()
                .userId(securityUser.getUserId())
                .username(securityUser.getUsername())
                .nickname(securityUser.getNickname())
                .role(securityUser.getRole())
                .clientVersion(clientVersion)  // 客户端版本号（用于后续版本控制）
                .build();

        // ── 5. 生成双 Token ──
        String accessToken = JwtUtil.generateAccessToken(loginUser);
        String refreshToken = JwtUtil.generateRefreshToken(loginUser);

        // ── 6. refresh_token 存入 Redis ──
        // Key: login:refresh_token:<userId> | Value: refresh_token | TTL: 7天
        String redisKey = RedisKey.refreshTokenKey(securityUser.getUserId());
        stringRedisTemplate.opsForValue()
                .set(redisKey, refreshToken, JwtUtil.REFRESH_TOKEN_EXPIRE, TimeUnit.MILLISECONDS);

        // ── 7. 记录在线用户 ──
        stringRedisTemplate.opsForSet()
                .add(RedisKey.ONLINE_USERS_SET_KEY, String.valueOf(securityUser.getUserId()));

        log.info("用户登录成功: userId={}, username={}, role={}, version={}",
                securityUser.getUserId(), username, securityUser.getRole(), clientVersion);

        // ── 8. 返回 Token 信息 ──
        TokenResult result = TokenResult.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .expiresIn(JwtUtil.ACCESS_TOKEN_EXPIRE / 1000)  // 过期时间（秒）
                .tokenType("Bearer")
                .build();

        return Result.ok(result);
    }

    @Override
    public Result<TokenResult> refreshToken(String refreshToken) {
        // ── 1. 非空校验 ──
        if (refreshToken == null || refreshToken.isBlank()) {
            return Result.unauthorized("refresh_token 不能为空");
        }

        // ── 2. 校验 refresh_token 有效性 ──
        Claims claims = JwtUtil.validateAndGetClaims(refreshToken);
        if (claims == null) {
            return Result.unauthorized("refresh_token 无效或签名错误");
        }

        // ── 3. 校验 token 类型（必须是 refresh 类型） ──
        if (!JwtUtil.TOKEN_TYPE_REFRESH.equals(JwtUtil.getTokenType(claims))) {
            return Result.unauthorized("token 类型不正确，需要使用 refresh_token");
        }

        Long userId = JwtUtil.getUserId(claims);
        if (userId == null) {
            return Result.unauthorized("token 中缺少用户信息");
        }

        // ── 4. 检查 Redis 中是否有该 refresh_token（是否已登出或被踢） ──
        String redisKey = RedisKey.refreshTokenKey(userId);
        String storedToken = stringRedisTemplate.opsForValue().get(redisKey);
        if (storedToken == null || !storedToken.equals(refreshToken)) {
            log.warn("refresh_token 不匹配或已失效: userId={}", userId);
            return Result.unauthorized("refresh_token 已失效，请重新登录");
        }

        // ── 5. 检查用户是否被踢出（黑名单） ──
        Boolean isBlacklisted = stringRedisTemplate.opsForSet()
                .isMember(RedisKey.USER_BLACKLIST_SET_KEY, String.valueOf(userId));
        if (Boolean.TRUE.equals(isBlacklisted)) {
            // 清理 refresh_token
            stringRedisTemplate.delete(redisKey);
            stringRedisTemplate.opsForSet().remove(RedisKey.ONLINE_USERS_SET_KEY, String.valueOf(userId));

            // 获取被踢原因
            String kickReason = stringRedisTemplate.opsForValue()
                    .get(RedisKey.userKickReasonKey(userId));
            return Result.unauthorized(kickReason != null ? kickReason : "您的账号已被管理员踢出");
        }

        // ── 6. 检查用户数据库状态 ──
        User user = userMapper.selectById(userId);
        if (user == null || user.getStatus() == 0) {
            stringRedisTemplate.delete(redisKey);
            stringRedisTemplate.opsForSet().remove(RedisKey.ONLINE_USERS_SET_KEY, String.valueOf(userId));
            return Result.fail("用户不存在或已被禁用");
        }

        // ── 7. 签发新 Token（Refresh Token Rotation — 刷新轮转） ──
        // 同时轮转 access_token 和 refresh_token，提升安全性
        // 旧的 refresh_token 被新的替换，防止 refresh_token 被盗用
        String oldClientVersion = JwtUtil.getClientVersion(claims);
        LoginUser loginUser = LoginUser.builder()
                .userId(user.getId())
                .username(user.getUsername())
                .nickname(user.getNickname())
                .role(user.getRole())
                .clientVersion(oldClientVersion)
                .build();

        String newAccessToken = JwtUtil.generateAccessToken(loginUser);
        String newRefreshToken = JwtUtil.generateRefreshToken(loginUser);

        // ── 8. 更新 Redis 中的 refresh_token ──
        stringRedisTemplate.opsForValue()
                .set(redisKey, newRefreshToken, JwtUtil.REFRESH_TOKEN_EXPIRE, TimeUnit.MILLISECONDS);

        log.info("Token 刷新成功: userId={}", userId);

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
        // ── 无 token 直接返回成功（幂等） ──
        if (rawToken == null || rawToken.isBlank()) {
            return Result.ok();
        }

        Claims claims = JwtUtil.parseToken(rawToken);
        if (claims == null) {
            return Result.ok();
        }

        Long userId = JwtUtil.getUserId(claims);

        // ── 1. 删除 Redis 中的 refresh_token ──
        if (userId != null) {
            stringRedisTemplate.delete(RedisKey.refreshTokenKey(userId));
        }

        // ── 2. access_token 加入黑名单（防止登出后 token 被复用） ──
        // 黑名单 TTL = token 剩余有效时间（token 过期后自动清理，避免黑名单无限增长）
        String jti = claims.getId();
        long remainingMs = JwtUtil.getRemainingMs(rawToken);
        if (jti != null && remainingMs > 0) {
            String blacklistKey = RedisKey.tokenBlacklistKey(jti);
            stringRedisTemplate.opsForValue()
                    .set(blacklistKey, "1", remainingMs, TimeUnit.MILLISECONDS);
        }

        // ── 3. 从在线用户集合中移除 ──
        if (userId != null) {
            stringRedisTemplate.opsForSet()
                    .remove(RedisKey.ONLINE_USERS_SET_KEY, String.valueOf(userId));
        }

        log.info("用户登出成功: userId={}, jti={}", userId, jti);
        return Result.ok();
    }

    // ==========================================
    // 二、精准踢人 — 用户黑名单管理
    // ==========================================

    @Override
    public Result<Void> kickUser(Long userId, String reason, Long operatorId) {
        // ── 1. 参数校验 ──
        if (userId == null) {
            return Result.fail("userId 不能为空");
        }

        // ── 2. 不能踢自己 ──
        if (userId.equals(operatorId)) {
            return Result.fail("不能踢出自己");
        }

        // ── 3. 检查用户是否存在 ──
        User user = userMapper.selectById(userId);
        if (user == null) {
            return Result.fail("用户不存在");
        }

        // ── 4. 加入用户黑名单 Set ──
        // Redis: SADD login:blacklist:user:set <userId>
        stringRedisTemplate.opsForSet()
                .add(RedisKey.USER_BLACKLIST_SET_KEY, String.valueOf(userId));

        // ── 5. 记录踢出时间和原因 ──
        String kickTimeValue = String.valueOf(System.currentTimeMillis());
        stringRedisTemplate.opsForValue()
                .set(RedisKey.userKickTimeKey(userId), kickTimeValue);
        stringRedisTemplate.opsForValue()
                .set(RedisKey.userKickReasonKey(userId),
                        reason != null ? reason : "管理员踢出");

        // ── 6. 删除该用户的 refresh_token（使其无法刷新） ──
        stringRedisTemplate.delete(RedisKey.refreshTokenKey(userId));

        // ── 7. 从在线用户集合中移除 ──
        stringRedisTemplate.opsForSet()
                .remove(RedisKey.ONLINE_USERS_SET_KEY, String.valueOf(userId));

        log.info("精准踢人成功: operatorId={}, targetUserId={}, reason={}", operatorId, userId, reason);
        return Result.ok();
    }

    @Override
    public Result<Map<String, Object>> kickUsersBatch(List<Long> userIds, String reason, Long operatorId) {
        int successCount = 0;
        int failCount = 0;

        for (Long userId : userIds) {
            Result<Void> result = kickUser(userId, reason, operatorId);
            if (result.isSuccess()) {
                successCount++;
            } else {
                failCount++;
            }
        }

        Map<String, Object> data = new HashMap<>();
        data.put("total", userIds.size());
        data.put("success", successCount);
        data.put("fail", failCount);

        log.info("批量踢人完成: operatorId={}, total={}, success={}, fail={}",
                operatorId, userIds.size(), successCount, failCount);
        return Result.ok(data);
    }

    @Override
    public Result<Void> unkickUser(Long userId, Long operatorId) {
        if (userId == null) {
            return Result.fail("userId 不能为空");
        }

        // ── 1. 从用户黑名单 Set 中移除 ──
        // Redis: SREM login:blacklist:user:set <userId>
        stringRedisTemplate.opsForSet()
                .remove(RedisKey.USER_BLACKLIST_SET_KEY, String.valueOf(userId));

        // ── 2. 清理踢出记录 ──
        stringRedisTemplate.delete(RedisKey.userKickTimeKey(userId));
        stringRedisTemplate.delete(RedisKey.userKickReasonKey(userId));

        log.info("取消踢出成功: operatorId={}, targetUserId={}", operatorId, userId);
        return Result.ok();
    }

    @Override
    public Result<Set<String>> getBlacklistedUsers() {
        Set<String> blacklistedUsers = stringRedisTemplate.opsForSet()
                .members(RedisKey.USER_BLACKLIST_SET_KEY);
        return Result.ok(blacklistedUsers);
    }

    @Override
    public Result<KickRecord> getKickRecord(Long userId) {
        if (userId == null) {
            return Result.fail("userId 不能为空");
        }

        // ── 检查是否在黑名单中 ──
        Boolean isMember = stringRedisTemplate.opsForSet()
                .isMember(RedisKey.USER_BLACKLIST_SET_KEY, String.valueOf(userId));

        // ── 获取踢出时间和原因 ──
        String kickTimeStr = stringRedisTemplate.opsForValue()
                .get(RedisKey.userKickTimeKey(userId));
        String reason = stringRedisTemplate.opsForValue()
                .get(RedisKey.userKickReasonKey(userId));

        if (Boolean.FALSE.equals(isMember) && kickTimeStr == null) {
            return Result.ok(null);  // 用户不在黑名单中，无踢出记录
        }

        // ── 查询用户名 ──
        User user = userMapper.selectById(userId);
        String username = user != null ? user.getUsername() : "未知用户";

        Long kickTime = null;
        try {
            kickTime = kickTimeStr != null ? Long.parseLong(kickTimeStr) : null;
        } catch (NumberFormatException ignored) {
            // 时间格式异常，忽略
        }

        KickRecord record = KickRecord.builder()
                .userId(userId)
                .username(username)
                .kickTime(kickTime)
                .reasonType("MANUAL")
                .reasonDesc(reason != null ? reason : "管理员手动踢出")
                .operator("admin")
                .build();

        return Result.ok(record);
    }

    // ==========================================
    // 三、批量踢人 — 版本控制管理
    // ==========================================

    @Override
    public Result<Void> setMinVersion(String minVersion, String kickMessage,
                                       String forceUpdateVersion, Long operatorId) {
        if (minVersion == null || minVersion.isBlank()) {
            return Result.fail("minVersion 不能为空");
        }

        // ── 1. 设置最低版本号 ──
        // Redis: SET login:version:min "1.5.0"
        stringRedisTemplate.opsForValue()
                .set(RedisKey.MIN_VERSION_KEY, minVersion);

        // ── 2. 设置踢出提示消息 ──
        if (kickMessage != null && !kickMessage.isBlank()) {
            stringRedisTemplate.opsForValue()
                    .set(RedisKey.VERSION_KICK_MESSAGE_KEY, kickMessage);
        }

        // ── 3. 记录操作日志 ──
        log.info("设置最低版本号: operatorId={}, minVersion={}, forceUpdateVersion={}, kickMessage={}",
                operatorId, minVersion, forceUpdateVersion, kickMessage);

        // ── 4. 如果设置了强制更新版本，可以选择踢出所有低于此版本的用户 ──
        if (forceUpdateVersion != null && !forceUpdateVersion.isBlank()) {
            // 强制更新模式下，可以在此处添加逻辑：
            // 批量踢出所有使用低于 forceUpdateVersion 版本的用户
            log.warn("强制更新模式已启用: forceUpdateVersion={}, 低于此版本的用户需要在下次请求时重新登录",
                    forceUpdateVersion);
            // 注：实际的版本拦截逻辑在 Gateway 的 AuthGlobalFilter 中执行
            // 这里只负责存储配置
        }

        return Result.ok();
    }

    @Override
    public Result<VersionConfig> getVersionConfig() {
        String minVersion = stringRedisTemplate.opsForValue()
                .get(RedisKey.MIN_VERSION_KEY);
        String kickMessage = stringRedisTemplate.opsForValue()
                .get(RedisKey.VERSION_KICK_MESSAGE_KEY);
        String forceUpdateVersion = stringRedisTemplate.opsForValue()
                .get(RedisKey.MIN_VERSION_KEY);  // 简化处理，实际可单独存储

        VersionConfig config = VersionConfig.builder()
                .minVersion(minVersion)
                .enabled(minVersion != null && !minVersion.isBlank())
                .kickMessage(kickMessage)
                .forceUpdateVersion(forceUpdateVersion)
                .build();

        return Result.ok(config);
    }

    @Override
    public Result<Void> addVersionToBlacklist(String version) {
        if (version == null || version.isBlank()) {
            return Result.fail("version 不能为空");
        }

        // Redis: SADD login:version:blacklist:set "1.3.0"
        stringRedisTemplate.opsForSet()
                .add(RedisKey.VERSION_BLACKLIST_SET_KEY, version);

        log.info("版本加入黑名单: version={}", version);
        return Result.ok();
    }

    @Override
    public Result<Void> removeVersionFromBlacklist(String version) {
        if (version == null || version.isBlank()) {
            return Result.fail("version 不能为空");
        }

        // Redis: SREM login:version:blacklist:set "1.3.0"
        stringRedisTemplate.opsForSet()
                .remove(RedisKey.VERSION_BLACKLIST_SET_KEY, version);

        log.info("版本从黑名单移除: version={}", version);
        return Result.ok();
    }

    @Override
    public Result<Set<String>> getVersionBlacklist() {
        Set<String> versions = stringRedisTemplate.opsForSet()
                .members(RedisKey.VERSION_BLACKLIST_SET_KEY);
        return Result.ok(versions);
    }

    // ==========================================
    // 四、在线用户管理
    // ==========================================

    @Override
    public Result<Long> getOnlineUserCount() {
        Long count = stringRedisTemplate.opsForSet()
                .size(RedisKey.ONLINE_USERS_SET_KEY);
        return Result.ok(count != null ? count : 0L);
    }

    @Override
    public Result<Set<String>> getOnlineUsers() {
        Set<String> onlineUsers = stringRedisTemplate.opsForSet()
                .members(RedisKey.ONLINE_USERS_SET_KEY);
        return Result.ok(onlineUsers);
    }

    // ==========================================
    // 五、白名单管理
    // ==========================================

    @Override
    public Result<Void> addWhitelistPath(String path) {
        if (path == null || path.isBlank()) {
            return Result.fail("path 不能为空");
        }

        // Redis: SADD login:whitelist:paths "/public/**"
        stringRedisTemplate.opsForSet()
                .add(RedisKey.WHITELIST_PATHS_SET_KEY, path);

        log.info("添加白名单路径: path={}", path);
        return Result.ok();
    }

    @Override
    public Result<Void> removeWhitelistPath(String path) {
        if (path == null || path.isBlank()) {
            return Result.fail("path 不能为空");
        }

        // Redis: SREM login:whitelist:paths "/public/**"
        stringRedisTemplate.opsForSet()
                .remove(RedisKey.WHITELIST_PATHS_SET_KEY, path);

        log.info("移除白名单路径: path={}", path);
        return Result.ok();
    }

    @Override
    public Result<Set<String>> getWhitelistPaths() {
        Set<String> paths = stringRedisTemplate.opsForSet()
                .members(RedisKey.WHITELIST_PATHS_SET_KEY);
        return Result.ok(paths);
    }
}
