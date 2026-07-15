package com.login.common.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serial;
import java.io.Serializable;

/**
 * 踢人记录 — 记录用户被踢出的详细信息
 * <p>
 * 用于查询和审计：谁在什么时候因为什么原因被踢出。
 * </p>
 *
 * @author login-service
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class KickRecord implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    /** 被踢用户的 ID */
    private Long userId;

    /** 被踢用户的用户名 */
    private String username;

    /** 踢出时间（毫秒时间戳） */
    private Long kickTime;

    /**
     * 踢出原因类型
     * <ul>
     *   <li>MANUAL — 管理员手动踢人</li>
     *   <li>VERSION — 版本过低被批量踢出</li>
     *   <li>VIOLATION — 违规操作</li>
     *   <li>SECURITY — 安全风险</li>
     * </ul>
     */
    private String reasonType;

    /** 踢出原因描述（中文，便于审计和展示） */
    private String reasonDesc;

    /** 操作人（哪个管理员执行的踢人操作） */
    private String operator;
}
