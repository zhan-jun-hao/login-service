-- ==========================================
-- 微服务登录鉴权系统 — 数据库初始化脚本
-- ==========================================
-- 数据库：login_service
-- 包含：用户表创建 + 管理员/测试用户初始化
-- ==========================================

-- 创建数据库（如果不存在）
CREATE DATABASE IF NOT EXISTS `login_service`
    DEFAULT CHARACTER SET utf8mb4
    DEFAULT COLLATE utf8mb4_unicode_ci;

USE `login_service`;

-- ==========================================
-- 用户表
-- ==========================================
-- 存储所有注册用户的账号信息
-- 密码使用 BCrypt 加密存储（相同密码每次密文不同，安全性高）
-- ==========================================
DROP TABLE IF EXISTS `user`;
CREATE TABLE `user` (
    `id`          BIGINT       NOT NULL AUTO_INCREMENT  COMMENT '主键 ID（自增）',
    `username`    VARCHAR(32)  NOT NULL                  COMMENT '用户名（登录账号，唯一）',
    `password`    VARCHAR(128) NOT NULL                  COMMENT '密码（BCrypt 加密存储，密文约60字符）',
    `nickname`    VARCHAR(32)  DEFAULT NULL              COMMENT '昵称（展示名称）',
    `email`       VARCHAR(64)  DEFAULT NULL              COMMENT '邮箱',
    `phone`       VARCHAR(20)  DEFAULT NULL              COMMENT '手机号',
    `role`        VARCHAR(16)  NOT NULL DEFAULT 'user'   COMMENT '角色：user-普通用户 admin-管理员',
    `status`      TINYINT      NOT NULL DEFAULT 1        COMMENT '状态：1-正常 0-禁用',
    `create_time` DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `update_time` DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_username` (`username`),
    KEY `idx_status` (`status`),
    KEY `idx_role` (`role`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='用户表';

-- ==========================================
-- 初始化管理员账号
-- ==========================================
-- 用户名：admin
-- 密码：admin123
-- 角色：admin（管理员，可访问 /admin/** 管理端点）
-- 注意：BCrypt 密文每次生成不同，以下密文仅供参考
--       如果密文不匹配，请启动服务后调用 /auth/register 接口注册
-- ==========================================
-- INSERT INTO `user` (`username`, `password`, `nickname`, `role`, `status`)
-- VALUES ('admin',
--         '$2a$10$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
--         '系统管理员',
--         'admin',
--         1);

-- ==========================================
-- 初始化测试用户
-- ==========================================
-- 用户名：testuser
-- 密码：123456
-- 角色：user（普通用户）
-- ==========================================
-- INSERT INTO `user` (`username`, `password`, `nickname`, `role`, `status`)
-- VALUES ('testuser',
--         '$2a$10$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
--         '测试用户',
--         'user',
--         1);
