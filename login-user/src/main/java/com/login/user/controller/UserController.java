package com.login.user.controller;

import com.login.common.context.UserContextHolder;
import com.login.common.model.Result;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * 用户控制器（受 Gateway JWT 保护）
 * <p>
 * 所有 /user/** 请求由 Gateway 拦截校验 JWT，校验通过后注入以下 header：
 * - X-User-Id   : 用户 ID
 * - X-User-Role : 用户角色 (user/admin)
 * - X-Trace-Id  : 链路追踪 ID
 * </p>
 */
@Slf4j
@RestController
@RequestMapping("/user")
public class UserController {

    /**
     * 获取当前用户信息（从 Gateway 透传的 header 获取身份）
     */
    @GetMapping("/info")
    public Result<Map<String, Object>> info(@RequestHeader("X-User-Id") Long userId,
                                            @RequestHeader("X-User-Role") String role,
                                            @RequestHeader("X-Trace-Id") String traceId) {
        log.info("查询用户信息: userId={}, role={}, traceId={}", userId, role, traceId);

        // 也可以通过 UserContextHolder 获取（ThreadLocal）
        Long contextUserId = UserContextHolder.getUserId();
        String contextTraceId = UserContextHolder.getTraceId();

        Map<String, Object> userInfo = Map.of(
                "userId", userId,
                "role", role,
                "traceId", traceId,
                "contextUserId", contextUserId != null ? contextUserId : "not set",
                "contextTraceId", contextTraceId != null ? contextTraceId : "not set",
                "message", "这是一个受保护的接口，你的 JWT 校验已通过！"
        );
        return Result.ok(userInfo);
    }

    /**
     * admin 专属接口（仅管理员可访问）
     */
    @GetMapping("/admin/dashboard")
    public Result<Map<String, Object>> adminDashboard(@RequestHeader("X-User-Id") Long userId,
                                                       @RequestHeader("X-User-Role") String role) {
        // 角色校验由 Gateway 完成，这里做二次兜底
        if (!"admin".equals(role)) {
            return Result.fail(403, "权限不足，仅管理员可访问");
        }

        log.info("管理员访问 dashboard: userId={}", userId);
        return Result.ok(Map.of(
                "message", "欢迎管理员！这是管理后台。",
                "userId", userId
        ));
    }

    /**
     * 健康检查（验证服务可达性）
     */
    @GetMapping("/hello")
    public Result<String> hello() {
        return Result.ok("Hello from user-service! 此接口受 Gateway JWT 保护。");
    }
}
