package com.login.common.constant;

/**
 * Redis Key 常量 — 统一管理所有 Redis 缓存 Key
 * <p>
 * Key 命名规范：login:模块:功能:标识
 * </p>
 *
 * <h3>黑名单体系（三层防护）：</h3>
 * <ol>
 *   <li><b>Token 黑名单</b>：用户登出时，将当前 token 的 jti 加入黑名单，TTL = token 剩余有效期</li>
 *   <li><b>用户黑名单（精准踢人）</b>：管理员踢出指定用户，该用户所有 token 立即失效，下次请求被拦截</li>
 *   <li><b>版本黑名单（批量踢人）</b>：管理员设置最低版本号，低于该版本的客户端一律被拦截</li>
 * </ol>
 *
 * @author login-service
 */
public final class RedisKey {

    private RedisKey() {
        // 工具类禁止实例化
    }

    // ==========================================
    // 1. Token 相关
    // ==========================================

    /** refresh_token 前缀，完整 key: login:refresh_token:<userId> */
    public static final String REFRESH_TOKEN_PREFIX = "login:refresh_token:";

    /** access_token 黑名单前缀（登出时加入），完整 key: login:blacklist:token:<jti> */
    public static final String TOKEN_BLACKLIST_PREFIX = "login:blacklist:token:";

    /**
     * 构建 refresh_token 的 Redis Key
     *
     * @param userId 用户 ID
     * @return login:refresh_token:123
     */
    public static String refreshTokenKey(Long userId) {
        return REFRESH_TOKEN_PREFIX + userId;
    }

    /**
     * 构建 token 黑名单的 Redis Key（用于登出场景）
     *
     * @param jti JWT 的唯一 ID（JWT ID）
     * @return login:blacklist:token:uuid-xxxx
     */
    public static String tokenBlacklistKey(String jti) {
        return TOKEN_BLACKLIST_PREFIX + jti;
    }

    // ==========================================
    // 2. 用户黑名单（精准踢人）
    // ==========================================

    /**
     * 用户黑名单 Set 的 Key
     * <p>
     * 数据结构：Redis Set，存储被踢出的 userId
     * 管理员踢人时加入，取消踢人时移除。
     * 无 TTL，永久有效，直到管理员手动移除。
     * </p>
     * <p>
     * 完整 key: login:blacklist:user:set
     * </p>
     */
    public static final String USER_BLACKLIST_SET_KEY = "login:blacklist:user:set";

    /**
     * 用户被踢时间前缀，完整 key: login:blacklist:user:kick_time:<userId>
     * <p>
     * 存储用户被踢出的时间戳（毫秒），方便查询和审计。
     * </p>
     */
    public static final String USER_KICK_TIME_PREFIX = "login:blacklist:user:kick_time:";

    /**
     * 用户被踢原因前缀，完整 key: login:blacklist:user:kick_reason:<userId>
     * <p>
     * 存储用户被踢出的原因描述。
     * </p>
     */
    public static final String USER_KICK_REASON_PREFIX = "login:blacklist:user:kick_reason:";

    /**
     * 构建用户被踢时间的 Redis Key
     *
     * @param userId 用户 ID
     * @return login:blacklist:user:kick_time:123
     */
    public static String userKickTimeKey(Long userId) {
        return USER_KICK_TIME_PREFIX + userId;
    }

    /**
     * 构建用户被踢原因的 Redis Key
     *
     * @param userId 用户 ID
     * @return login:blacklist:user:kick_reason:123
     */
    public static String userKickReasonKey(Long userId) {
        return USER_KICK_REASON_PREFIX + userId;
    }

    // ==========================================
    // 3. 版本控制（批量踢人）
    // ==========================================

    /**
     * 最低允许的客户端版本号
     * <p>
     * 数据结构：Redis String，存储版本号如 "1.2.0"
     * Gateway 在每次请求时校验 X-Client-Version 请求头，
     * 低于此版本的客户端将被拦截。
     * </p>
     * <p>
     * 完整 key: login:version:min
     * </p>
     */
    public static final String MIN_VERSION_KEY = "login:version:min";

    /**
     * 版本黑名单（指定版本号禁止访问）
     * <p>
     * 数据结构：Redis Set，存储被禁止的版本号列表
     * 用于精确封禁某个已知有问题的版本。
     * </p>
     * <p>
     * 完整 key: login:version:blacklist:set
     * </p>
     */
    public static final String VERSION_BLACKLIST_SET_KEY = "login:version:blacklist:set";

    /**
     * 版本踢人提示信息
     * <p>
     * 完整 key: login:version:kick_message
     * </p>
     */
    public static final String VERSION_KICK_MESSAGE_KEY = "login:version:kick_message";

    // ==========================================
    // 4. 白名单（动态路径）
    // ==========================================

    /**
     * 动态白名单路径 Set
     * <p>
     * 数据结构：Redis Set，存储不需要鉴权的路径列表
     * 支持 Ant 风格路径匹配（如 /public/**  /actuator/health）
     * </p>
     * <p>
     * 完整 key: login:whitelist:paths
     * </p>
     */
    public static final String WHITELIST_PATHS_SET_KEY = "login:whitelist:paths";

    // ==========================================
    // 5. 在线用户统计
    // ==========================================

    /**
     * 在线用户 Set
     * <p>
     * 数据结构：Redis Set，存储当前在线的 userId
     * 登录时加入，登出或被踢时移除。
     * </p>
     * <p>
     * 完整 key: login:online:users
     * </p>
     */
    public static final String ONLINE_USERS_SET_KEY = "login:online:users";
}
