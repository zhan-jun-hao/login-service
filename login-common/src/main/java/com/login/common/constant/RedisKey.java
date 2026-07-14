package com.login.common.constant;

/**
 * Redis Key 常量
 * 支持单设备登录
 * 因为refresh_token: 一个userId对应一个refresh_token
 * blacklist: jwtId对应一个
 */
public final class RedisKey {

    private RedisKey() {}

    /** refresh_token 前缀，完整 key: login:refresh_token:<userId> */
    public static final String REFRESH_TOKEN_PREFIX = "login:refresh_token:";

    /** token 黑名单前缀，完整 key: login:blacklist:<jti> */
    public static final String TOKEN_BLACKLIST_PREFIX = "login:blacklist:";

    public static String refreshTokenKey(Long userId) {
        return REFRESH_TOKEN_PREFIX + userId;
    }

    public static String tokenBlacklistKey(String jti) {
        return TOKEN_BLACKLIST_PREFIX + jti;
    }
}
