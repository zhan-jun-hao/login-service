package com.login.admin.controller;

import com.login.common.constant.RedisKey;
import com.login.common.model.Result;
import com.login.common.model.VersionConfig;
import com.login.common.context.UserContextHolder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.web.bind.annotation.*;

import java.util.*;

/**
 * 管理员仪表盘控制器 — 管理控制台核心接口
 * <p>
 * 提供管理控制台的各项功能：
 * - 系统概览（在线用户数、黑名单用户数、版本配置等）
 * - 黑名单管理（查看、踢出、恢复）
 * - 版本控制（设置最低版本、封禁版本）
 * - 白名单管理（添加/移除路径）
 * </p>
 * <p>
 * 所有接口需要 admin 角色，由 Gateway 统一鉴权。
 * </p>
 *
 * @author login-service
 */
@Slf4j
@RestController
@RequestMapping("/admin")
@RequiredArgsConstructor
public class AdminDashboardController {

    private final StringRedisTemplate stringRedisTemplate;

    // ==========================================
    // 一、管理仪表盘 — 系统概览
    // ==========================================

    /**
     * 获取管理仪表盘概览数据
     * <p>
     * 返回系统的整体运行状态，包括：
     * - 在线用户数
     * - 黑名单用户数
     * - 当前最低版本配置
     * - 被禁用版本列表
     * - 白名单路径数
     * </p>
     *
     * @return 仪表盘数据
     */
    @GetMapping("/dashboard")
    public Result<Map<String, Object>> dashboard(@RequestHeader("X-User-Id") Long userId,
                                                  @RequestHeader("X-User-Role") String role) {
        log.info("管理员访问仪表盘: userId={}, role={}", userId, role);

        Map<String, Object> data = new LinkedHashMap<>();

        // ── 1. 在线用户统计 ──
        Long onlineCount = stringRedisTemplate.opsForSet()
                .size(RedisKey.ONLINE_USERS_SET_KEY);
        data.put("onlineUserCount", onlineCount != null ? onlineCount : 0L);

        // ── 2. 黑名单用户统计 ──
        Long blacklistCount = stringRedisTemplate.opsForSet()
                .size(RedisKey.USER_BLACKLIST_SET_KEY);
        data.put("blacklistUserCount", blacklistCount != null ? blacklistCount : 0L);

        // ── 3. 版本控制配置 ──
        String minVersion = stringRedisTemplate.opsForValue()
                .get(RedisKey.MIN_VERSION_KEY);
        String kickMessage = stringRedisTemplate.opsForValue()
                .get(RedisKey.VERSION_KICK_MESSAGE_KEY);
        Long versionBlacklistCount = stringRedisTemplate.opsForSet()
                .size(RedisKey.VERSION_BLACKLIST_SET_KEY);

        Map<String, Object> versionInfo = new LinkedHashMap<>();
        versionInfo.put("minVersion", minVersion != null ? minVersion : "未设置");
        versionInfo.put("enabled", minVersion != null && !minVersion.isBlank());
        versionInfo.put("kickMessage", kickMessage != null ? kickMessage : "版本过低，请更新");
        versionInfo.put("blacklistedVersionCount", versionBlacklistCount != null ? versionBlacklistCount : 0L);
        data.put("versionControl", versionInfo);

        // ── 4. 白名单统计 ──
        Long whitelistCount = stringRedisTemplate.opsForSet()
                .size(RedisKey.WHITELIST_PATHS_SET_KEY);
        data.put("whitelistPathCount", whitelistCount != null ? whitelistCount : 0L);

        // ── 5. 当前管理员信息 ──
        data.put("operatorId", userId);
        data.put("operatorRole", role);
        data.put("serverTime", System.currentTimeMillis());

        return Result.ok(data);
    }

    /**
     * 获取在线用户详情列表
     * <p>
     * 返回当前所有在线用户的 ID 列表。
     * </p>
     *
     * @return 在线用户 ID 集合
     */
    @GetMapping("/online/users")
    public Result<Set<String>> getOnlineUsers(@RequestHeader("X-User-Id") Long userId) {
        log.debug("管理员查询在线用户: operatorId={}", userId);
        Set<String> onlineUsers = stringRedisTemplate.opsForSet()
                .members(RedisKey.ONLINE_USERS_SET_KEY);
        return Result.ok(onlineUsers != null ? onlineUsers : Collections.emptySet());
    }

    /**
     * 获取黑名单用户详情列表
     * <p>
     * 返回所有被踢出的用户及其踢出信息。
     * </p>
     *
     * @return 黑名单用户列表（含踢出时间和原因）
     */
    @GetMapping("/blacklist/users/detail")
    public Result<List<Map<String, Object>>> getBlacklistedUsersDetail(
            @RequestHeader("X-User-Id") Long userId) {
        log.debug("管理员查询黑名单详情: operatorId={}", userId);

        Set<String> blacklistedUserIds = stringRedisTemplate.opsForSet()
                .members(RedisKey.USER_BLACKLIST_SET_KEY);

        if (blacklistedUserIds == null || blacklistedUserIds.isEmpty()) {
            return Result.ok(Collections.emptyList());
        }

        List<Map<String, Object>> result = new ArrayList<>();
        for (String uidStr : blacklistedUserIds) {
            Map<String, Object> userInfo = new LinkedHashMap<>();
            userInfo.put("userId", uidStr);

            // 查询踢出时间
            String kickTime = stringRedisTemplate.opsForValue()
                    .get(RedisKey.userKickTimeKey(Long.valueOf(uidStr)));
            userInfo.put("kickTime", kickTime);

            // 查询踢出原因
            String kickReason = stringRedisTemplate.opsForValue()
                    .get(RedisKey.userKickReasonKey(Long.valueOf(uidStr)));
            userInfo.put("kickReason", kickReason != null ? kickReason : "未知原因");

            result.add(userInfo);
        }

        return Result.ok(result);
    }

    // ==========================================
    // 二、精准踢人 — 黑名单管理
    // ==========================================

    /**
     * 踢出指定用户（精准踢人）
     *
     * @param body 请求体 { "userId": 123, "reason": "违规操作" }
     * @return 操作结果
     */
    @PostMapping("/kick/user")
    public Result<Void> kickUser(@RequestBody Map<String, Object> body,
                                  @RequestHeader("X-User-Id") Long operatorId) {
        Long targetUserId = toLong(body.get("userId"));
        String reason = body.getOrDefault("reason", "管理员手动踢出").toString();

        if (targetUserId == null) {
            return Result.fail("userId 不能为空");
        }
        if (targetUserId.equals(operatorId)) {
            return Result.fail("不能踢出自己");
        }

        log.warn("管理员踢出用户: operatorId={}, targetUserId={}, reason={}", operatorId, targetUserId, reason);

        // ── 加入用户黑名单 ──
        stringRedisTemplate.opsForSet()
                .add(RedisKey.USER_BLACKLIST_SET_KEY, String.valueOf(targetUserId));

        // ── 记录踢出时间和原因 ──
        stringRedisTemplate.opsForValue()
                .set(RedisKey.userKickTimeKey(targetUserId), String.valueOf(System.currentTimeMillis()));
        stringRedisTemplate.opsForValue()
                .set(RedisKey.userKickReasonKey(targetUserId), reason);

        // ── 删除 refresh_token 使其无法刷新 ──
        stringRedisTemplate.delete(RedisKey.refreshTokenKey(targetUserId));

        // ── 从在线用户中移除 ──
        stringRedisTemplate.opsForSet()
                .remove(RedisKey.ONLINE_USERS_SET_KEY, String.valueOf(targetUserId));

        return Result.ok();
    }

    /**
     * 批量踢出用户
     *
     * @param body 请求体 { "userIds": [1, 2, 3], "reason": "批量处理" }
     * @return 操作结果
     */
    @PostMapping("/kick/users/batch")
    public Result<Map<String, Object>> kickUsersBatch(@RequestBody Map<String, Object> body,
                                                       @RequestHeader("X-User-Id") Long operatorId) {
        @SuppressWarnings("unchecked")
        List<Integer> userIdList = (List<Integer>) body.get("userIds");
        String reason = body.getOrDefault("reason", "管理员批量踢出").toString();

        if (userIdList == null || userIdList.isEmpty()) {
            return Result.fail("userIds 不能为空");
        }

        int successCount = 0;
        int failCount = 0;

        for (Integer uid : userIdList) {
            Long targetUserId = uid.longValue();
            if (targetUserId.equals(operatorId)) {
                failCount++;
                continue;
            }
            try {
                stringRedisTemplate.opsForSet()
                        .add(RedisKey.USER_BLACKLIST_SET_KEY, String.valueOf(targetUserId));
                stringRedisTemplate.opsForValue()
                        .set(RedisKey.userKickTimeKey(targetUserId), String.valueOf(System.currentTimeMillis()));
                stringRedisTemplate.opsForValue()
                        .set(RedisKey.userKickReasonKey(targetUserId), reason);
                stringRedisTemplate.delete(RedisKey.refreshTokenKey(targetUserId));
                stringRedisTemplate.opsForSet()
                        .remove(RedisKey.ONLINE_USERS_SET_KEY, String.valueOf(targetUserId));
                successCount++;
            } catch (Exception e) {
                log.error("批量踢人失败: userId={}, error={}", targetUserId, e.getMessage());
                failCount++;
            }
        }

        log.warn("管理员批量踢出完成: operatorId={}, total={}, success={}, fail={}",
                operatorId, userIdList.size(), successCount, failCount);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("total", userIdList.size());
        result.put("success", successCount);
        result.put("fail", failCount);
        return Result.ok(result);
    }

    /**
     * 恢复被踢出的用户
     *
     * @param userId 用户 ID
     * @return 操作结果
     */
    @DeleteMapping("/kick/user/{userId}")
    public Result<Void> unkickUser(@PathVariable Long userId,
                                    @RequestHeader("X-User-Id") Long operatorId) {
        log.info("管理员恢复用户: operatorId={}, targetUserId={}", operatorId, userId);

        // ── 从黑名单移除 ──
        stringRedisTemplate.opsForSet()
                .remove(RedisKey.USER_BLACKLIST_SET_KEY, String.valueOf(userId));

        // ── 清理踢出记录 ──
        stringRedisTemplate.delete(RedisKey.userKickTimeKey(userId));
        stringRedisTemplate.delete(RedisKey.userKickReasonKey(userId));

        return Result.ok();
    }

    // ==========================================
    // 三、批量踢人 — 版本控制管理
    // ==========================================

    /**
     * 设置最低客户端版本号
     * <p>
     * 低于此版本的客户端将被 Gateway 拦截（返回 426 Upgrade Required）。
     * </p>
     *
     * @param body 请求体 { "minVersion": "1.5.0", "kickMessage": "请更新到最新版本" }
     * @return 操作结果
     */
    @PostMapping("/version/min")
    public Result<Void> setMinVersion(@RequestBody Map<String, Object> body,
                                       @RequestHeader("X-User-Id") Long operatorId) {
        String minVersion = body.get("minVersion") != null ? body.get("minVersion").toString() : null;
        String kickMessage = body.getOrDefault("kickMessage", "您的客户端版本过低，请更新到最新版本后再使用").toString();

        if (minVersion == null || minVersion.isBlank()) {
            return Result.fail("minVersion 不能为空");
        }

        log.warn("管理员设置最低版本: operatorId={}, minVersion={}, kickMessage={}",
                operatorId, minVersion, kickMessage);

        stringRedisTemplate.opsForValue().set(RedisKey.MIN_VERSION_KEY, minVersion);
        stringRedisTemplate.opsForValue().set(RedisKey.VERSION_KICK_MESSAGE_KEY, kickMessage);

        return Result.ok();
    }

    /**
     * 获取当前版本控制配置
     *
     * @return 版本控制配置
     */
    @GetMapping("/version/config")
    public Result<VersionConfig> getVersionConfig() {
        String minVersion = stringRedisTemplate.opsForValue().get(RedisKey.MIN_VERSION_KEY);
        String kickMessage = stringRedisTemplate.opsForValue().get(RedisKey.VERSION_KICK_MESSAGE_KEY);
        Set<String> blacklistedVersions = stringRedisTemplate.opsForSet()
                .members(RedisKey.VERSION_BLACKLIST_SET_KEY);

        VersionConfig config = VersionConfig.builder()
                .minVersion(minVersion)
                .enabled(minVersion != null && !minVersion.isBlank())
                .kickMessage(kickMessage != null ? kickMessage : "版本过低，请更新")
                .build();

        return Result.ok(config);
    }

    /**
     * 封禁指定版本（加入版本黑名单）
     *
     * @param body 请求体 { "version": "1.3.0" }
     * @return 操作结果
     */
    @PostMapping("/version/blacklist")
    public Result<Void> addVersionToBlacklist(@RequestBody Map<String, Object> body,
                                               @RequestHeader("X-User-Id") Long operatorId) {
        String version = body.get("version") != null ? body.get("version").toString() : null;

        if (version == null || version.isBlank()) {
            return Result.fail("version 不能为空");
        }

        log.warn("管理员封禁版本: operatorId={}, version={}", operatorId, version);
        stringRedisTemplate.opsForSet().add(RedisKey.VERSION_BLACKLIST_SET_KEY, version);

        return Result.ok();
    }

    /**
     * 解封版本
     *
     * @param version 版本号
     * @return 操作结果
     */
    @DeleteMapping("/version/blacklist/{version}")
    public Result<Void> removeVersionFromBlacklist(@PathVariable String version,
                                                    @RequestHeader("X-User-Id") Long operatorId) {
        log.info("管理员解封版本: operatorId={}, version={}", operatorId, version);
        stringRedisTemplate.opsForSet().remove(RedisKey.VERSION_BLACKLIST_SET_KEY, version);
        return Result.ok();
    }

    /**
     * 获取被禁用的版本列表
     *
     * @return 版本号列表
     */
    @GetMapping("/version/blacklist")
    public Result<Set<String>> getVersionBlacklist() {
        Set<String> versions = stringRedisTemplate.opsForSet()
                .members(RedisKey.VERSION_BLACKLIST_SET_KEY);
        return Result.ok(versions != null ? versions : Collections.emptySet());
    }

    // ==========================================
    // 四、白名单管理
    // ==========================================

    /**
     * 添加白名单路径
     *
     * @param body 请求体 { "path": "/public/new-feature/**" }
     * @return 操作结果
     */
    @PostMapping("/whitelist/path")
    public Result<Void> addWhitelistPath(@RequestBody Map<String, Object> body,
                                          @RequestHeader("X-User-Id") Long operatorId) {
        String path = body.get("path") != null ? body.get("path").toString() : null;

        if (path == null || path.isBlank()) {
            return Result.fail("path 不能为空");
        }

        log.info("管理员添加白名单路径: operatorId={}, path={}", operatorId, path);
        stringRedisTemplate.opsForSet().add(RedisKey.WHITELIST_PATHS_SET_KEY, path);

        return Result.ok();
    }

    /**
     * 移除白名单路径
     *
     * @param body 请求体 { "path": "/public/old-path/**" }
     * @return 操作结果
     */
    @DeleteMapping("/whitelist/path")
    public Result<Void> removeWhitelistPath(@RequestBody Map<String, Object> body,
                                             @RequestHeader("X-User-Id") Long operatorId) {
        String path = body.get("path") != null ? body.get("path").toString() : null;

        if (path == null || path.isBlank()) {
            return Result.fail("path 不能为空");
        }

        log.info("管理员移除白名单路径: operatorId={}, path={}", operatorId, path);
        stringRedisTemplate.opsForSet().remove(RedisKey.WHITELIST_PATHS_SET_KEY, path);

        return Result.ok();
    }

    /**
     * 获取所有白名单路径
     *
     * @return 路径列表
     */
    @GetMapping("/whitelist/paths")
    public Result<Set<String>> getWhitelistPaths() {
        Set<String> paths = stringRedisTemplate.opsForSet()
                .members(RedisKey.WHITELIST_PATHS_SET_KEY);
        return Result.ok(paths != null ? paths : Collections.emptySet());
    }

    // ==========================================
    // 五、系统健康检查
    // ==========================================

    /**
     * 健康检查
     *
     * @return 服务状态
     */
    @GetMapping("/health")
    public Result<Map<String, Object>> health() {
        Map<String, Object> healthInfo = new LinkedHashMap<>();
        healthInfo.put("service", "login-admin");
        healthInfo.put("status", "UP");
        healthInfo.put("timestamp", System.currentTimeMillis());
        healthInfo.put("operatorId", UserContextHolder.getUserId());
        healthInfo.put("traceId", UserContextHolder.getTraceId());
        return Result.ok(healthInfo);
    }

    // ==========================================
    // 工具方法
    // ==========================================

    /**
     * 安全地将 Object 转为 Long
     */
    private Long toLong(Object obj) {
        if (obj == null) return null;
        if (obj instanceof Long l) return l;
        if (obj instanceof Number n) return n.longValue();
        try {
            return Long.valueOf(obj.toString());
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
