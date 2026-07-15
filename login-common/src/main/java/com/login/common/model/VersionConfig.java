package com.login.common.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serial;
import java.io.Serializable;

/**
 * 版本控制配置 — 管理客户端最低版本和黑名单版本
 * <p>
 * 存储在 Redis 中，Gateway 实时读取并校验每个请求的客户端版本。
 * </p>
 *
 * @author login-service
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class VersionConfig implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * 最低允许的客户端版本号（如 "1.2.0"）
     * <p>
     * 低于此版本的客户端将被拦截，提示用户升级。
     * 设为 null 或空字符串表示不限制。
     * </p>
     */
    private String minVersion;

    /**
     * 是否启用版本校验
     * <p>
     * 关闭后所有版本均可访问，用于紧急回滚场景。
     * </p>
     */
    private Boolean enabled;

    /**
     * 版本过期时的提示消息
     * <p>
     * 返回给客户端，告知用户需要升级。
     * </p>
     */
    private String kickMessage;

    /**
     * 强制升级的最低版本（如 "1.0.0"）
     * <p>
     * 低于此版本的客户端不仅被拦截，其所有 token 也会被强制失效。
     * 用于重大安全更新场景。
     * </p>
     */
    private String forceUpdateVersion;
}
