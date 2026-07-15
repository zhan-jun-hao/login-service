package com.login.auth.service;

import com.login.common.model.KickRecord;
import com.login.common.model.Result;
import com.login.common.model.TokenResult;
import com.login.common.model.VersionConfig;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 认证服务接口 — 用户认证 + 管理员管理
 *
 * @author login-service
 */
public interface AuthService {

    // ==========================================
    // 一、用户认证
    // ==========================================

    /**
     * 用户注册
     *
     * @param username 用户名
     * @param password 密码
     * @param nickname 昵称
     * @return 注册结果
     */
    Result<Void> register(String username, String password, String nickname);

    /**
     * 用户登录
     *
     * @param username      用户名
     * @param password      密码
     * @param clientVersion 客户端版本号（用于版本控制）
     * @return Token 信息（access_token + refresh_token）
     */
    Result<TokenResult> login(String username, String password, String clientVersion);

    /**
     * 刷新 access_token
     *
     * @param refreshToken 刷新令牌
     * @return 新的 Token 信息
     */
    Result<TokenResult> refreshToken(String refreshToken);

    /**
     * 用户登出
     *
     * @param accessToken 当前使用的 access_token
     * @return 登出结果
     */
    Result<Void> logout(String accessToken);

    // ==========================================
    // 二、精准踢人 — 用户黑名单管理
    // ==========================================

    /**
     * 踢出指定用户（加入黑名单）
     *
     * @param userId     被踢用户 ID
     * @param reason     踢出原因
     * @param operatorId 操作人 ID
     * @return 操作结果
     */
    Result<Void> kickUser(Long userId, String reason, Long operatorId);

    /**
     * 批量踢出用户
     *
     * @param userIds    被踢用户 ID 列表
     * @param reason     踢出原因
     * @param operatorId 操作人 ID
     * @return 操作结果（含成功/失败数量）
     */
    Result<Map<String, Object>> kickUsersBatch(List<Long> userIds, String reason, Long operatorId);

    /**
     * 取消踢出（从黑名单移除）
     *
     * @param userId     用户 ID
     * @param operatorId 操作人 ID
     * @return 操作结果
     */
    Result<Void> unkickUser(Long userId, Long operatorId);

    /**
     * 获取黑名单用户列表
     *
     * @return 用户 ID 集合
     */
    Result<Set<String>> getBlacklistedUsers();

    /**
     * 获取指定用户的踢出记录
     *
     * @param userId 用户 ID
     * @return 踢出记录
     */
    Result<KickRecord> getKickRecord(Long userId);

    // ==========================================
    // 三、批量踢人 — 版本控制管理
    // ==========================================

    /**
     * 设置最低客户端版本号
     *
     * @param minVersion          最低版本号
     * @param kickMessage         版本过期提示消息
     * @param forceUpdateVersion  强制升级的最低版本
     * @param operatorId          操作人 ID
     * @return 操作结果
     */
    Result<Void> setMinVersion(String minVersion, String kickMessage,
                                String forceUpdateVersion, Long operatorId);

    /**
     * 获取当前版本控制配置
     *
     * @return 版本控制配置
     */
    Result<VersionConfig> getVersionConfig();

    /**
     * 将指定版本加入版本黑名单
     *
     * @param version 要封禁的版本号
     * @return 操作结果
     */
    Result<Void> addVersionToBlacklist(String version);

    /**
     * 从版本黑名单中移除
     *
     * @param version 要解封的版本号
     * @return 操作结果
     */
    Result<Void> removeVersionFromBlacklist(String version);

    /**
     * 获取版本黑名单
     *
     * @return 版本号集合
     */
    Result<Set<String>> getVersionBlacklist();

    // ==========================================
    // 四、在线用户管理
    // ==========================================

    /**
     * 获取在线用户数量
     *
     * @return 在线用户数
     */
    Result<Long> getOnlineUserCount();

    /**
     * 获取在线用户列表
     *
     * @return 用户 ID 集合
     */
    Result<Set<String>> getOnlineUsers();

    // ==========================================
    // 五、白名单管理
    // ==========================================

    /**
     * 添加白名单路径
     *
     * @param path 路径（支持 Ant 通配符）
     * @return 操作结果
     */
    Result<Void> addWhitelistPath(String path);

    /**
     * 移除白名单路径
     *
     * @param path 路径
     * @return 操作结果
     */
    Result<Void> removeWhitelistPath(String path);

    /**
     * 获取白名单路径列表
     *
     * @return 路径集合
     */
    Result<Set<String>> getWhitelistPaths();
}
