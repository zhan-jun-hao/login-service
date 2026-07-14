package com.login.auth.config;

import com.login.auth.entity.User;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

/**
 * 安全用户 — 实现 Spring Security 的 UserDetails 接口
 * <p>
 * 包装 User 实体，为 DaoAuthenticationProvider 提供用户信息和权限。
 * </p>
 */
public class SecurityUser implements UserDetails {

    /**
     * 用户 ID
     */
    @Getter
    private final Long userId;

    /**
     * 昵称
     */
    @Getter
    private final String nickname;

    /**
     * 角色
     */
    @Getter
    private final String role;

    /**
     * 用户名
     */
    private final String username;

    /**
     * 密码
     */
    private final String password;

    /**
     * 账户是否启用
     */
    private final boolean enabled;

    /**
     * 权限列表
     */
    private final List<SimpleGrantedAuthority> authorities;

    public SecurityUser(User user) {
        this.userId = user.getId();
        this.nickname = user.getNickname();
        this.role = user.getRole() != null ? user.getRole() : "user";
        this.username = user.getUsername();
        this.password = user.getPassword();
        this.enabled = user.getStatus() != null && user.getStatus() == 1;
        // 角色转权限：ROLE_user / ROLE_admin
        this.authorities = List.of(new SimpleGrantedAuthority("ROLE_" + this.role));
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }


    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    /**
     * 账号过期 true表示不过期
     *
     * @return
     */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /**
     * 账号锁定 true表示不锁定
     *
     * @return
     */
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    /**
     * 密码过期 true表示不过期
     * @return
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }
}
