package com.login.admin;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

/**
 * 管理员服务 — 启动类
 * <p>
 * 提供管理控制台后端接口，包括：
 * - 管理仪表盘（在线用户、黑名单、版本控制概览）
 * - 踢人管理（精准踢人 + 批量踢人）
 * - 白名单/黑名单管理
 * - 系统监控与审计日志
 * </p>
 * <p>
 * 端口：8083
 * 所有接口受 Gateway JWT 保护，仅管理员（role=admin）可访问。
 * </p>
 *
 * @author login-service
 */
@SpringBootApplication(scanBasePackages = {"com.login.admin", "com.login.common"})
@EnableDiscoveryClient  // 注册到 Nacos
public class AdminApplication {

    public static void main(String[] args) {
        SpringApplication.run(AdminApplication.class, args);
    }
}
