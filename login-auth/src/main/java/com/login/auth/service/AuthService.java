package com.login.auth.service;

import com.login.common.model.Result;
import com.login.common.model.TokenResult;

/**
 * 认证服务接口
 */
public interface AuthService {

    /**
     * 用户注册
     */
    Result<Void> register(String username, String password, String nickname);

    /**
     * 用户登录
     */
    Result<TokenResult> login(String username, String password);

    /**
     * 刷新 access_token
     */
    Result<TokenResult> refreshToken(String refreshToken);

    /**
     * 登出
     */
    Result<Void> logout(String accessToken);
}
