package com.login.common.utils;

import lombok.extern.slf4j.Slf4j;

/**
 * 版本号比较工具类
 * <p>
 * 用于比较客户端版本号与最低允许版本号。
 * 支持标准的语义化版本号格式：major.minor.patch（如 "1.2.3"）。
 * </p>
 *
 * <h3>使用场景：</h3>
 * <ul>
 *   <li>Gateway 校验客户端版本是否 >= 最低允许版本</li>
 *   <li>版本黑名单检查（封禁特定版本）</li>
 *   <li>强制升级判断</li>
 * </ul>
 *
 * @author login-service
 */
@Slf4j
public final class VersionUtil {

    private VersionUtil() {
        // 工具类禁止实例化
    }

    /**
     * 比较两个版本号的大小
     *
     * @param version1 版本号 1（如 "1.2.3"）
     * @param version2 版本号 2（如 "1.3.0"）
     * @return 负数 version1 < version2，0 相等，正数 version1 > version2
     */
    public static int compare(String version1, String version2) {
        // 空值处理：空版本号视为最低版本
        if (version1 == null || version1.isBlank()) {
            return -1;
        }
        if (version2 == null || version2.isBlank()) {
            return 1;
        }

        try {
            // 按 "." 分割版本号
            String[] parts1 = version1.trim().split("\\.");
            String[] parts2 = version2.trim().split("\\.");

            // 取较长的长度，逐段比较
            int maxLength = Math.max(parts1.length, parts2.length);

            for (int i = 0; i < maxLength; i++) {
                int v1 = i < parts1.length ? parsePart(parts1[i]) : 0;
                int v2 = i < parts2.length ? parsePart(parts2[i]) : 0;

                if (v1 != v2) {
                    return v1 - v2;
                }
            }

            return 0; // 完全相等
        } catch (Exception e) {
            log.warn("版本号比较异常: v1={}, v2={}, error={}", version1, version2, e.getMessage());
            // 解析失败时保守处理：返回 -1（认为版本过低，放行由业务决定）
            return -1;
        }
    }

    /**
     * 检查 sourceVersion 是否 >= targetVersion
     *
     * @param sourceVersion 源版本（客户端版本）
     * @param targetVersion 目标版本（最低允许版本）
     * @return true 表示 sourceVersion >= targetVersion
     */
    public static boolean isGreaterOrEqual(String sourceVersion, String targetVersion) {
        return compare(sourceVersion, targetVersion) >= 0;
    }

    /**
     * 检查 sourceVersion 是否 < targetVersion
     *
     * @param sourceVersion 源版本（客户端版本）
     * @param targetVersion 目标版本（最低允许版本）
     * @return true 表示 sourceVersion < targetVersion（版本过低，需要拦截）
     */
    public static boolean isLessThan(String sourceVersion, String targetVersion) {
        return compare(sourceVersion, targetVersion) < 0;
    }

    /**
     * 检查两个版本号是否相等
     *
     * @param version1 版本号 1
     * @param version2 版本号 2
     * @return true 表示相等
     */
    public static boolean equals(String version1, String version2) {
        return compare(version1, version2) == 0;
    }

    /**
     * 解析版本号的单个段落为整数
     * <p>
     * 处理可能包含前导零和非数字字符的情况。
     * </p>
     *
     * @param part 版本号段落（如 "03" → 3, "1a" → 1）
     * @return 整数值
     */
    private static int parsePart(String part) {
        // 去除前导零和非数字字符
        String cleaned = part.replaceAll("[^0-9]", "");
        if (cleaned.isEmpty()) {
            return 0;
        }
        try {
            return Integer.parseInt(cleaned);
        } catch (NumberFormatException e) {
            return 0;
        }
    }
}
