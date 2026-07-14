package com.login.common.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.io.Serial;
import java.io.Serializable;

/**
 * 登录/注册响应中的 token 信息
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TokenResult implements Serializable {

    /**
     * serialVersionUID 是序列化版本号，用于控制>>反序列化的兼容性<<
     * 手动指定 1L 可以避免类结构变化时 JVM 自动生成不同版本号导致的不兼容错误
     * 在新增字段时保持 1L 可以兼容旧数据，在删除字段或修改类型时应该修改版本号强制不兼容
     */
    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * JWT access_token
     */
    private String accessToken;

    /**
     * JWT refresh_token
     */
    private String refreshToken;

    /**
     * access_token 过期时间（秒）
     */
    private long expiresIn;

    /**
     * token 类型 比如jwt： Bearer ...
     */
    private String tokenType;
}
