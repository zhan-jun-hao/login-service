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
 * 负责 JWT 的生成、解析、校验，是整个认证体系的核心工具。
 * </p>
 *
 * <h3>Token 类型：</h3>
 * <ul>
 *   <li><b>access_token</b>：有效期 30 分钟，用于接口鉴权，每次请求携带</li>
 *   <li><b>refresh_token</b>：有效期 7 天，用于刷新 access_token，存储在 Redis</li>
 * </ul>
 *
 * <h3>JWT Claims 字段说明：</h3>
 * <ul>
 *   <li>jti — JWT 唯一 ID，用于黑名单（登出追踪）</li>
 *   <li>userId — 用户 ID</li>
 *   <li>username — 用户名</li>
 *   <li>nickname — 昵称</li>
 *   <li>role — 用户角色（user/admin）</li>
 *   <li>tokenType — token 类型（access/refresh）</li>
 *   <li>clientVersion — 客户端版本号（用于版本控制和批量踢人）</li>
 *   <li>iat — 签发时间</li>
 *   <li>exp — 过期时间</li>
 * </ul>
 *
 * @author login-service
 */
@Slf4j
public final class JwtUtil {

    private JwtUtil() {
        // 工具类禁止实例化
    }

    /**
     * HMAC-SHA256 密钥
     * <p>
     * 生产环境必须从配置中心（Nacos）或环境变量读取，
     * 此处为开发默认值，要求至少 256 bits (32 字节)。
     * </p>
     */
    private static final String SECRET = "login-service-jwt-secret-key-2024-must-be-at-least-256-bits-long!!";
    private static final SecretKey SECRET_KEY = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));

    // ==========================================
    // Token 有效期
    // ==========================================

    /** access_token 有效期：30 分钟 */
    public static final long ACCESS_TOKEN_EXPIRE = 30 * 60 * 1000L;

    /** refresh_token 有效期：7 天 */
    public static final long REFRESH_TOKEN_EXPIRE = 7 * 24 * 60 * 60 * 1000L;

    // ==========================================
    // Claims 字段名常量
    // ==========================================

    private static final String CLAIM_USER_ID = "userId";
    private static final String CLAIM_USERNAME = "username";
    private static final String CLAIM_NICKNAME = "nickname";
    private static final String CLAIM_ROLE = "role";
    private static final String CLAIM_TOKEN_TYPE = "tokenType";
    private static final String CLAIM_CLIENT_VERSION = "clientVersion";

    // ==========================================
    // Token 类型常量
    // ==========================================

    /** access_token 类型标识 */
    public static final String TOKEN_TYPE_ACCESS = "access";

    /** refresh_token 类型标识 */
    public static final String TOKEN_TYPE_REFRESH = "refresh";

    // ==========================================
    // Token 生成
    // ==========================================

    /**
     * 生成 access_token
     * <p>
     * 包含用户基本信息和客户端版本号，有效期 30 分钟。
     * </p>
     *
     * @param user 登录用户信息
     * @return JWT access_token 字符串
     */
    public static String generateAccessToken(LoginUser user) {
        return buildToken(user, TOKEN_TYPE_ACCESS, ACCESS_TOKEN_EXPIRE);
    }

    /**
     * 生成 refresh_token
     * <p>
     * 用于刷新 access_token，有效期 7 天。
     * </p>
     *
     * @param user 登录用户信息
     * @return JWT refresh_token 字符串
     */
    public static String generateRefreshToken(LoginUser user) {
        return buildToken(user, TOKEN_TYPE_REFRESH, REFRESH_TOKEN_EXPIRE);
    }

    /**
     * 构建 JWT Token（内部方法）
     *
     * @param user      登录用户信息
     * @param tokenType token 类型（access / refresh）
     * @param expireMs  过期时间（毫秒）
     * @return 签名的 JWT 字符串
     */
    private static String buildToken(LoginUser user, String tokenType, long expireMs) {
        Date now = new Date();
        Date expiration = new Date(now.getTime() + expireMs);

        return Jwts.builder()
                // jti：JWT 唯一 ID，用于登出时加入黑名单
                .id(UUID.randomUUID().toString())
                // 用户信息 claims
                .claim(CLAIM_USER_ID, user.getUserId())
                .claim(CLAIM_USERNAME, user.getUsername())
                .claim(CLAIM_NICKNAME, user.getNickname())
                .claim(CLAIM_ROLE, user.getRole())
                // token 类型：access 或 refresh
                .claim(CLAIM_TOKEN_TYPE, tokenType)
                // 客户端版本号：用于版本控制和批量踢人
                .claim(CLAIM_CLIENT_VERSION, user.getClientVersion())
                // 签发时间
                .issuedAt(now)
                // 过期时间
                .expiration(expiration)
                // HMAC-SHA256 签名
                .signWith(SECRET_KEY)
                .compact();
    }

    // ==========================================
    // Token 解析与校验
    // ==========================================

    /**
     * 解析 JWT Token 的所有 Claims（不校验过期）
     * <p>
     * 即使 token 过期也会返回 Claims（通过 ExpiredJwtException.getClaims()），
     * 方便调用方获取 token 类型、用户 ID 等信息做进一步处理。
     * </p>
     *
     * @param token JWT token 字符串
     * @return Claims 对象，解析失败返回 null
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
     * 从 token 中提取 LoginUser 信息
     *
     * @param token JWT token 字符串
     * @return LoginUser 对象，解析失败返回 null
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
                .clientVersion(claims.get(CLAIM_CLIENT_VERSION, String.class))
                .build();
    }

    /**
     * 校验 token 签名是否有效且未过期
     *
     * @param token JWT token 字符串
     * @return true=有效，false=签名错误或已过期
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
     * 校验 token 并返回 Claims（签名正确 + 未过期才返回）
     * <p>
     * 与 parseToken 的区别：此方法在 token 过期时返回 null（除非是 ExpiredJwtException）。
     * </p>
     *
     * @param token JWT token 字符串
     * @return Claims 对象，校验失败返回 null
     */
    public static Claims validateAndGetClaims(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(SECRET_KEY)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (ExpiredJwtException e) {
            log.debug("JWT 已过期: {}", e.getMessage());
            return e.getClaims(); // 过期也返回 claims 供参考
        } catch (JwtException e) {
            log.warn("JWT 校验失败: {}", e.getMessage());
            return null;
        }
    }

    // ==========================================
    // Claims 字段提取
    // ==========================================

    /**
     * 从 Claims 获取 token 类型（access / refresh）
     *
     * @param claims JWT Claims
     * @return token 类型字符串
     */
    public static String getTokenType(Claims claims) {
        return claims != null ? claims.get(CLAIM_TOKEN_TYPE, String.class) : null;
    }

    /**
     * 从 token 中获取 JTI（JWT 唯一 ID）
     * <p>
     * JTI 用于登出时加入 token 黑名单。
     * </p>
     *
     * @param token JWT token 字符串
     * @return JTI 字符串
     */
    public static String getJti(String token) {
        Claims claims = parseToken(token);
        return claims != null ? claims.getId() : null;
    }

    /**
     * 从 Claims 获取用户 ID
     *
     * @param claims JWT Claims
     * @return 用户 ID
     */
    public static Long getUserId(Claims claims) {
        return claims != null ? claims.get(CLAIM_USER_ID, Long.class) : null;
    }

    /**
     * 从 Claims 获取用户名
     *
     * @param claims JWT Claims
     * @return 用户名
     */
    public static String getUsername(Claims claims) {
        return claims != null ? claims.get(CLAIM_USERNAME, String.class) : null;
    }

    /**
     * 从 Claims 获取用户角色
     *
     * @param claims JWT Claims
     * @return 角色字符串（user / admin）
     */
    public static String getRole(Claims claims) {
        return claims != null ? claims.get(CLAIM_ROLE, String.class) : null;
    }

    /**
     * 从 Claims 获取客户端版本号
     * <p>
     * 用于版本控制校验 — Gateway 比较客户端版本与最低允许版本。
     * </p>
     *
     * @param claims JWT Claims
     * @return 客户端版本号（如 "1.2.0"）
     */
    public static String getClientVersion(Claims claims) {
        return claims != null ? claims.get(CLAIM_CLIENT_VERSION, String.class) : null;
    }

    // ==========================================
    // 工具方法
    // ==========================================

    /**
     * 获取 token 剩余有效时间（毫秒）
     * <p>
     * 用于登出时：将 token 加入黑名单的 TTL = 剩余有效时间，
     * 避免黑名单无限增长。
     * </p>
     *
     * @param token JWT token 字符串
     * @return 剩余毫秒数，已过期返回 0
     */
    public static long getRemainingMs(String token) {
        Claims claims = parseToken(token);
        if (claims == null || claims.getExpiration() == null) {
            return 0;
        }
        long remaining = claims.getExpiration().getTime() - System.currentTimeMillis();
        return Math.max(remaining, 0);
    }

    /**
     * 从 token 中获取 JTI，token 无效则返回 null
     *
     * @param token JWT token 字符串
     * @return JTI 或 null
     */
    public static String getJtiFromToken(String token) {
        Claims claims = parseToken(token);
        return claims != null ? claims.getId() : null;
    }
}
