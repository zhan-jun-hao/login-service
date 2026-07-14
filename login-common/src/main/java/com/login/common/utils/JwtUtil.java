package com.login.common.utils;

import com.login.common.model.LoginUser;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.UUID;

/**
 * JWT 工具类 — 基于 jjwt 0.12.x
 * <p>
 * access_token:  有效期 30 分钟，用于接口鉴权
 * refresh_token: 有效期 7 天，用于刷新 access_token
 * </p>
 */
@Slf4j
public class JwtUtil {

    /** HMAC-SHA256 密钥（生产环境应从配置中心读取） */
    private static final String SECRET = "login-service-jwt-secret-key-2024-must-be-at-least-256-bits-long!!";
    private static final SecretKey SECRET_KEY = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));

    /** access_token 有效期：30 分钟 */
    public static final long ACCESS_TOKEN_EXPIRE = 30 * 60 * 1000L;

    /** refresh_token 有效期：7 天 */
    public static final long REFRESH_TOKEN_EXPIRE = 7 * 24 * 60 * 60 * 1000L;

    /**
     * token字段
     * userId:
     * username:
     * nickname:
     * role:
     * tokenType:
     */
    private static final String CLAIM_USER_ID = "userId";
    private static final String CLAIM_USERNAME = "username";
    private static final String CLAIM_NICKNAME = "nickname";
    private static final String CLAIM_ROLE = "role";
    private static final String CLAIM_TOKEN_TYPE = "tokenType";

    /**
     * tokenType:
     * access 登陆
     * refresh 刷新
     */
    public static final String TOKEN_TYPE_ACCESS = "access";
    public static final String TOKEN_TYPE_REFRESH = "refresh";

    /**
     * 生成 access_token
     */
    public static String generateAccessToken(LoginUser user) {
        return buildToken(user, TOKEN_TYPE_ACCESS, ACCESS_TOKEN_EXPIRE);
    }

    /**
     * 生成 refresh_token
     */
    public static String generateRefreshToken(LoginUser user) {
        return buildToken(user, TOKEN_TYPE_REFRESH, REFRESH_TOKEN_EXPIRE);
    }

    private static String buildToken(LoginUser user, String tokenType, long expireMs) {
        Date now = new Date();
        Date expiration = new Date(now.getTime() + expireMs);

        return Jwts.builder()
                .id(UUID.randomUUID().toString()) // JWT的ID
                .claim(CLAIM_USER_ID, user.getUserId()) // userId
                .claim(CLAIM_USERNAME, user.getUsername()) // username
                .claim(CLAIM_NICKNAME, user.getNickname()) // nickname
                .claim(CLAIM_ROLE, user.getRole()) // role: user / admin
                .claim(CLAIM_TOKEN_TYPE, tokenType) // tokenType
                .issuedAt(now) // 签发时间
                .expiration(expiration) // 过期时间
                .signWith(SECRET_KEY) // 签名
                .compact();
    }

    /**
     * 解析所有 Claims
     */
    public static Claims parseToken(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(SECRET_KEY)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (ExpiredJwtException e) {
            // 过期了也返回 claims，方便调用方获取 token 类型等信息
            log.debug("JWT 已过期: {}", e.getMessage());
            return e.getClaims();
        } catch (JwtException e) {
            log.warn("JWT 解析失败: {}", e.getMessage());
            return null;
        }
    }

    /**
     * 从 token 中提取 LoginUser
     */
    public static LoginUser parseLoginUser(String token) {
        Claims claims = parseToken(token);
        if (claims == null) {
            return null;
        }
        return LoginUser.builder()
                .userId(claims.get(CLAIM_USER_ID, Long.class))
                .username(claims.get(CLAIM_USERNAME, String.class))
                .nickname(claims.get(CLAIM_NICKNAME, String.class))
                .role(claims.get(CLAIM_ROLE, String.class))
                .build();
    }

    /**
     * 校验 token 是否有效（签名正确 + 未过期）
     */
    public static boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith(SECRET_KEY)
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (JwtException e) {
            log.debug("JWT 校验失败: {}", e.getMessage());
            return false;
        }
    }

    /**
     * 校验 token 是否有效，并返回 Claims（签名正确 + 未过期）
     */
    public static Claims validateAndGetClaims(String token) {
        try {
            return Jwts.parser()                         // 1. 创建解析器
                    .verifyWith(SECRET_KEY)              // 2. 设置签名密钥
                    .build()                             // 3. 构建解析器实例
                    .parseSignedClaims(token)            // 4. 解析 JWT（验签 + 解析）
                    .getPayload();                       // 5. 获取里面的数据（Claims）
        } catch (ExpiredJwtException e) {
            log.debug("JWT 已过期: {}", e.getMessage());
            return e.getClaims();
        } catch (JwtException e) {
            log.warn("JWT 校验失败: {}", e.getMessage());
            return null;
        }
    }

    /**
     * 从 Claims 获取 token 类型
     */
    public static String getTokenType(Claims claims) {
        return claims != null ? claims.get(CLAIM_TOKEN_TYPE, String.class) : null;
    }

    /**
     * 从 token 中获取 JTI JWT的ID
     */
    public static String getJti(String token) {
        Claims claims = parseToken(token);
        return claims != null ? claims.getId() : null;
    }

    /**
     * 从 Claims 获取用户 ID
     */
    public static Long getUserId(Claims claims) {
        return claims != null ? claims.get(CLAIM_USER_ID, Long.class) : null;
    }

    /**
     * 从 Claims 获取用户角色
     */
    public static String getRole(Claims claims) {
        return claims != null ? claims.get(CLAIM_ROLE, String.class) : null;
    }

    /**
     * 获取 token 剩余有效时间（毫秒），已过期返回 0
     */
    public static long getRemainingMs(String token) {
        Claims claims = parseToken(token);
        if (claims == null || claims.getExpiration() == null) {
            return 0;
        }
        long remaining = claims.getExpiration().getTime() - System.currentTimeMillis();
        return Math.max(remaining, 0);
    }
}
