package com.login.auth.controller;

import com.login.auth.service.AuthService;
import com.login.common.model.Result;
import com.login.common.model.TokenResult;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * 认证控制器 — 用户登录/注册/刷新Token/登出
 * <p>
 * 注意：此 Controller 的所有接口均为公开接口（在白名单中），
 * 不需要 JWT 鉴权。鉴权由 Gateway 的 AuthGlobalFilter 统一处理。
 * </p>
 *
 * @author login-service
 */
@Slf4j
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    /**
     * 用户注册
     * <p>
     * 创建新用户账号，密码使用 BCrypt 加密存储。
     * </p>
     *
     * @param body 请求体：{ "username": "zhangsan", "password": "123456", "nickname": "张三" }
     * @return 注册结果
     */
    @PostMapping("/register")
    public Result<Void> register(@RequestBody Map<String, String> body) {
        String username = body.get("username");
        String password = body.get("password");
        String nickname = body.getOrDefault("nickname", username);

        // ── 参数校验 ──
        if (username == null || username.isBlank()) {
            return Result.fail("用户名不能为空");
        }
        if (password == null || password.isBlank()) {
            return Result.fail("密码不能为空");
        }
        if (password.length() < 6) {
            return Result.fail("密码长度不能少于6位");
        }
        if (username.length() > 32) {
            return Result.fail("用户名长度不能超过32位");
        }

        return authService.register(username, password, nickname);
    }

    /**
     * 用户登录
     * <p>
     * 验证用户名和密码，返回 access_token 和 refresh_token。
     * 客户端需要在请求头中携带版本号（X-Client-Version），用于版本控制。
     * </p>
     *
     * @param body 请求体：{ "username": "zhangsan", "password": "123456" }
     * @param clientVersion 客户端版本号（从请求头获取，用于后续版本控制校验）
     * @return Token 信息（access_token + refresh_token + 过期时间）
     */
    @PostMapping("/login")
    public Result<TokenResult> login(@RequestBody Map<String, String> body,
                                      @RequestHeader(value = "X-Client-Version", required = false) String clientVersion) {
        String username = body.get("username");
        String password = body.get("password");

        // ── 参数校验 ──
        if (username == null || username.isBlank()) {
            return Result.fail("用户名不能为空");
        }
        if (password == null || password.isBlank()) {
            return Result.fail("密码不能为空");
        }

        log.info("用户登录请求: username={}, clientVersion={}", username, clientVersion);
        return authService.login(username, password, clientVersion);
    }

    /**
     * 刷新 access_token
     * <p>
     * 使用 refresh_token 换取新的 access_token 和 refresh_token（双 Token 轮转）。
     * 旧的 refresh_token 立即失效，防止 refresh_token 被盗用。
     * </p>
     *
     * @param body 请求体：{ "refreshToken": "xxxxx" }
     * @return 新的 Token 信息
     */
    @PostMapping("/refresh")
    public Result<TokenResult> refresh(@RequestBody Map<String, String> body) {
        String refreshToken = body.get("refreshToken");
        if (refreshToken == null || refreshToken.isBlank()) {
            return Result.unauthorized("refreshToken 不能为空");
        }
        return authService.refreshToken(refreshToken);
    }

    /**
     * 用户登出
     * <p>
     * 将当前 access_token 加入黑名单，删除 refresh_token。
     * 登出后该 token 立即失效，无法再用于接口访问。
     * </p>
     *
     * @param authHeader Authorization 请求头（Bearer xxx）
     * @return 登出结果
     */
    @PostMapping("/logout")
    public Result<Void> logout(@RequestHeader(value = "Authorization", required = false) String authHeader) {
        String token = null;
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7).trim();
        }
        return authService.logout(token);
    }
}
