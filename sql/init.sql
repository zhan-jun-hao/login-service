-- ============================================
-- 微服务登录鉴权系统 — 数据库初始化脚本
-- ============================================

-- 创建数据库
CREATE DATABASE IF NOT EXISTS `login_service`
    DEFAULT CHARACTER SET utf8mb4
    DEFAULT COLLATE utf8mb4_unicode_ci;

USE `login_service`;

-- 用户表
DROP TABLE IF EXISTS `user`;
CREATE TABLE `user` (
    `id`          BIGINT       NOT NULL AUTO_INCREMENT COMMENT '主键 ID',
    `username`    VARCHAR(64)  NOT NULL                COMMENT '用户名（登录账号）',
    `password`    VARCHAR(256) NOT NULL                COMMENT '密码（BCrypt 加密）',
    `nickname`    VARCHAR(64)  DEFAULT NULL            COMMENT '昵称',
    `email`       VARCHAR(128) DEFAULT NULL            COMMENT '邮箱',
    `phone`       VARCHAR(20)  DEFAULT NULL            COMMENT '手机号',
    `role`        VARCHAR(32)  DEFAULT 'user'          COMMENT '角色：user-普通用户 admin-管理员',
    `status`      TINYINT      DEFAULT 1              COMMENT '状态：1-正常 0-禁用',
    `create_time` DATETIME     DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `update_time` DATETIME     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_username` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='用户表';
