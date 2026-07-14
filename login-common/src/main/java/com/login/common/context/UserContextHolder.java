package com.login.common.context;

/**
 * 用户上下文持有者 — 基于 ThreadLocal
 * <p>
 * 在请求进入 Gateway 时设置，在请求结束时清理。
 * 存储当前请求的 userId 和 traceId，方便业务代码在任何地方获取。
 * </p>
 *
 * <pre>
 * 使用方式：
 *   // 设置（Gateway Filter 中）
 *   UserContextHolder.set(userId, traceId);
 *
 *   // 获取（业务代码任意位置）
 *   Long userId = UserContextHolder.getUserId();
 *   String traceId = UserContextHolder.getTraceId();
 *
 *   // 清理（请求结束后）
 *   UserContextHolder.clear();
 * </pre>
 */
public final class UserContextHolder {

    private UserContextHolder() {}

    /** 存储 userId */
    private static final ThreadLocal<Long> USER_ID_HOLDER = new ThreadLocal<>();

    /** 存储 traceId */
    private static final ThreadLocal<String> TRACE_ID_HOLDER = new ThreadLocal<>();

    /**
     * 设置当前请求的用户上下文
     *
     * @param userId  用户 ID
     * @param traceId 链路追踪 ID
     */
    public static void set(Long userId, String traceId) {
        USER_ID_HOLDER.set(userId);
        TRACE_ID_HOLDER.set(traceId);
    }

    /**
     * 获取当前请求的用户 ID
     *
     * @return userId，未设置时返回 null
     */
    public static Long getUserId() {
        return USER_ID_HOLDER.get();
    }

    /**
     * 获取当前请求的链路追踪 ID
     *
     * @return traceId，未设置时返回 null
     */
    public static String getTraceId() {
        return TRACE_ID_HOLDER.get();
    }

    /**
     * 清理 ThreadLocal，防止内存泄漏
     * <p>
     * 必须在请求结束后调用（通常在 Filter 的 finally 块中）。
     * </p>
     */
    public static void clear() {
        USER_ID_HOLDER.remove();
        TRACE_ID_HOLDER.remove();
    }
}
