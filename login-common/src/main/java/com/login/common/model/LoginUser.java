package com.login.common.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serial;
import java.io.Serializable;

/**
 * 登录用户信息 — 存储在 JWT claims 中的用户数据
 * <p>
 * 在用户登录认证成功后构建，用于生成 JWT token。
 * Gateway 解析 JWT 后将这些信息透传给下游服务。
 * </p>
 *
 * @author login-service
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LoginUser implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    /** 用户 ID */
    private Long userId;

    /** 用户名（登录账号） */
    private String username;

    /** 昵称（展示名称） */
    private String nickname;

    /** 角色：user（普通用户）/ admin（管理员） */
    private String role;

    /**
     * 客户端版本号
     * <p>
     * 用于版本控制和批量踢人：
     * - 登录时由客户端传入，写入 JWT
     * - 后续请求 Gateway 会校验此版本是否 >= 最低允许版本
     * - 版本过期时强制用户升级 App
     * </p>
     */
    private String clientVersion;
}
