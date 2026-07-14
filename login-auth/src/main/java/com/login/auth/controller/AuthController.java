package com.login.auth.controller;

import com.login.auth.service.AuthService;
import com.login.common.model.Result;
import com.login.common.model.TokenResult;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import org.hibernate.validator.constraints.Length;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * 认证控制器
 */
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    /**
     * 用户注册
     */
    @PostMapping("/register")
    public Result<Void> register(@RequestBody Map<String, String> body) {
        String username = body.get("username");
        String password = body.get("password");
        String nickname = body.getOrDefault("nickname", username);

        if (username == null || username.isBlank()) {
            return Result.fail("用户名不能为空");
        }
        if (password == null || password.isBlank()) {
            return Result.fail("密码不能为空");
        }
        if (password.length() < 6) {
            return Result.fail("密码长度不能少于6位");
        }

        return authService.register(username, password, nickname);
    }

    /**
     * 用户登录
     */
    @PostMapping("/login")
    public Result<TokenResult> login(@RequestBody Map<String, String> body) {
        String username = body.get("username");
        String password = body.get("password");

        if (username == null || username.isBlank()) {
            return Result.fail("用户名不能为空");
        }
        if (password == null || password.isBlank()) {
            return Result.fail("密码不能为空");
        }

        return authService.login(username, password);
    }

    /**
     * 刷新 access_token
     */
    @PostMapping("/refresh")
    public Result<TokenResult> refresh(@RequestBody Map<String, String> body) {
        String refreshToken = body.get("refreshToken");
        return authService.refreshToken(refreshToken);
    }

    /**
     * 登出
     */
    @PostMapping("/logout")
    public Result<Void> logout(@RequestHeader(value = "Authorization", required = false) String authHeader) {
        String token = null;
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7);
        }
        return authService.logout(token);
    }
}
