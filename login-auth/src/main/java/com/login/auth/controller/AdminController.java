package com.login.auth.controller;

import com.login.auth.service.AuthService;
import com.login.common.model.KickRecord;
import com.login.common.model.Result;
import com.login.common.model.VersionConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 管理员控制器 — 踢人管理与版本控制
 * <p>
 * 仅管理员可访问（role=admin），提供以下功能：
 * </p>
 *
 * <h3>精准踢人（黑名单）：</h3>
 * <ul>
 *   <li>踢出指定用户（加入黑名单，所有 token 立即失效）</li>
 *   <li>取消踢出（从黑名单移除）</li>
 *   <li>查看黑名单列表</li>
 * </ul>
 *
 * <h3>批量踢人（版本控制）：</h3>
 * <ul>
 *   <li>设置最低客户端版本号</li>
 *   <li>封禁/解封特定版本</li>
 *   <li>查看版本控制配置</li>
 * </ul>
 *
 * <h3>在线用户管理：</h3>
 * <ul>
 *   <li>查看在线用户数量</li>
 * </ul>
 *
 * @author login-service
 */
@Slf4j
@RestController
@RequestMapping("/admin")
@RequiredArgsConstructor
public class AdminController {

    private final AuthService authService;

    // ==========================================
    // 一、精准踢人 — 用户黑名单管理
    // ==========================================

    /**
     * 踢出指定用户（精准踢人）
     * <p>
     * 将该用户加入黑名单，其所有 token 立即失效。
     * 用户在下次请求时会被 Gateway 拦截（返回 401）。
     * </p>
     *
     * @param body 请求体：{ "userId": 123, "reason": "违规操作" }
     * @return 操作结果
     */
    @PostMapping("/kick/user")
    public Result<Void> kickUser(@RequestBody Map<String, Object> body,
                                  @RequestHeader("X-User-Id") Long operatorId) {
        // 从请求体提取参数
        Long userId = toLong(body.get("userId"));
        String reason = body.getOrDefault("reason", "管理员手动踢出").toString();

        if (userId == null) {
            return Result.fail("userId 不能为空");
        }

        log.info("管理员踢出用户: operatorId={}, targetUserId={}, reason={}", operatorId, userId, reason);
        return authService.kickUser(userId, reason, operatorId);
    }

    /**
     * 批量踢出用户
     * <p>
     * 一次性踢出多个用户，适用于批量处理违规账号。
     * </p>
     *
     * @param body 请求体：{ "userIds": [1, 2, 3], "reason": "批量违规处理" }
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

        List<Long> userIds = userIdList.stream()
                .map(Long::valueOf)
                .toList();

        log.info("管理员批量踢出用户: operatorId={}, count={}, reason={}", operatorId, userIds.size(), reason);
        return authService.kickUsersBatch(userIds, reason, operatorId);
    }

    /**
     * 取消踢出用户（从黑名单移除）
     * <p>
     * 用户被取消踢出后，需要重新登录获取新 token。
     * 之前的旧 token 仍然在黑名单中直到过期。
     * </p>
     *
     * @param userId 要恢复的用户 ID
     * @return 操作结果
     */
    @DeleteMapping("/kick/user/{userId}")
    public Result<Void> unkickUser(@PathVariable Long userId,
                                    @RequestHeader("X-User-Id") Long operatorId) {
        log.info("管理员取消踢出用户: operatorId={}, targetUserId={}", operatorId, userId);
        return authService.unkickUser(userId, operatorId);
    }

    /**
     * 查询被踢出的用户列表（黑名单）
     *
     * @return 黑名单用户 ID 列表
     */
    @GetMapping("/blacklist/users")
    public Result<Set<String>> getBlacklistedUsers(@RequestHeader("X-User-Id") Long operatorId) {
        log.debug("管理员查询黑名单: operatorId={}", operatorId);
        return authService.getBlacklistedUsers();
    }

    /**
     * 查询指定用户的踢出记录
     *
     * @param userId 用户 ID
     * @return 踢出记录（含时间、原因、操作人）
     */
    @GetMapping("/kick/record/{userId}")
    public Result<KickRecord> getKickRecord(@PathVariable Long userId) {
        return authService.getKickRecord(userId);
    }

    // ==========================================
    // 二、批量踢人 — 版本控制管理
    // ==========================================

    /**
     * 设置最低客户端版本号（批量踢人）
     * <p>
     * 所有客户端版本号低于此值的请求都会被 Gateway 拦截。
     * 用于强制用户升级 App（安全修复、API 不兼容等场景）。
     * </p>
     * <p>
     * 示例：设置为 "1.5.0"，则所有 1.4.x 及以下版本的客户端都会被拦截。
     * </p>
     *
     * @param body 请求体：{ "minVersion": "1.5.0", "kickMessage": "请更新到最新版本", "forceUpdateVersion": "1.2.0" }
     * @return 操作结果
     */
    @PostMapping("/version/min")
    public Result<Void> setMinVersion(@RequestBody Map<String, Object> body,
                                       @RequestHeader("X-User-Id") Long operatorId) {
        String minVersion = body.get("minVersion") != null ? body.get("minVersion").toString() : null;
        String kickMessage = body.getOrDefault("kickMessage", "您的客户端版本过低，请更新到最新版本").toString();
        String forceUpdateVersion = body.get("forceUpdateVersion") != null
                ? body.get("forceUpdateVersion").toString() : null;

        if (minVersion == null || minVersion.isBlank()) {
            return Result.fail("minVersion 不能为空");
        }

        log.info("管理员设置最低版本: operatorId={}, minVersion={}, forceUpdateVersion={}",
                operatorId, minVersion, forceUpdateVersion);
        return authService.setMinVersion(minVersion, kickMessage, forceUpdateVersion, operatorId);
    }

    /**
     * 获取当前版本控制配置
     *
     * @return 版本控制配置信息
     */
    @GetMapping("/version/config")
    public Result<VersionConfig> getVersionConfig() {
        return authService.getVersionConfig();
    }

    /**
     * 将指定版本加入版本黑名单（精确版本封禁）
     * <p>
     * 封禁某个特定版本号，该版本的客户端全部被拦截。
     * 适用于发现某个版本有严重 bug 需要紧急封禁。
     * </p>
     *
     * @param body 请求体：{ "version": "1.3.0", "reason": "发现严重安全漏洞" }
     * @return 操作结果
     */
    @PostMapping("/version/blacklist")
    public Result<Void> addVersionToBlacklist(@RequestBody Map<String, Object> body,
                                               @RequestHeader("X-User-Id") Long operatorId) {
        String version = body.get("version") != null ? body.get("version").toString() : null;

        if (version == null || version.isBlank()) {
            return Result.fail("version 不能为空");
        }

        log.info("管理员封禁版本: operatorId={}, version={}", operatorId, version);
        return authService.addVersionToBlacklist(version);
    }

    /**
     * 从版本黑名单中移除（解封版本）
     *
     * @param version 要解封的版本号
     * @return 操作结果
     */
    @DeleteMapping("/version/blacklist/{version}")
    public Result<Void> removeVersionFromBlacklist(@PathVariable String version,
                                                    @RequestHeader("X-User-Id") Long operatorId) {
        log.info("管理员解封版本: operatorId={}, version={}", operatorId, version);
        return authService.removeVersionFromBlacklist(version);
    }

    /**
     * 查询版本黑名单列表
     *
     * @return 被禁用的版本号列表
     */
    @GetMapping("/version/blacklist")
    public Result<Set<String>> getVersionBlacklist() {
        return authService.getVersionBlacklist();
    }

    // ==========================================
    // 三、在线用户管理
    // ==========================================

    /**
     * 获取在线用户数量
     *
     * @return 在线用户数
     */
    @GetMapping("/online/count")
    public Result<Long> getOnlineUserCount() {
        return authService.getOnlineUserCount();
    }

    /**
     * 获取在线用户列表
     *
     * @return 在线用户 ID 集合
     */
    @GetMapping("/online/users")
    public Result<Set<String>> getOnlineUsers() {
        return authService.getOnlineUsers();
    }

    // ==========================================
    // 四、白名单管理
    // ==========================================

    /**
     * 向白名单添加路径
     *
     * @param body 请求体：{ "path": "/public/new-api/**" }
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
        return authService.addWhitelistPath(path);
    }

    /**
     * 从白名单移除路径
     *
     * @param body 请求体：{ "path": "/public/old-api/**" }
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
        return authService.removeWhitelistPath(path);
    }

    /**
     * 查询白名单路径列表
     *
     * @return 白名单路径集合
     */
    @GetMapping("/whitelist/paths")
    public Result<Set<String>> getWhitelistPaths() {
        return authService.getWhitelistPaths();
    }

    // ==========================================
    // 工具方法
    // ==========================================

    /**
     * 安全地将 Object 转为 Long
     *
     * @param obj 可能是 Integer、Long、String 等
     * @return Long 值，转换失败返回 null
     */
    private Long toLong(Object obj) {
        if (obj == null) {
            return null;
        }
        if (obj instanceof Long l) {
            return l;
        }
        if (obj instanceof Number n) {
            return n.longValue();
        }
        try {
            return Long.valueOf(obj.toString());
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
