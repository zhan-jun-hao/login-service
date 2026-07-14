package com.login.auth.config;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.login.auth.entity.User;
import com.login.auth.mapper.UserMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * 用户详情服务 — 从数据库加载用户信息
 * <p>
 * Spring Security 的 DaoAuthenticationProvider 会调用此服务加载用户，
 * 然后自动校验密码。
 * </p>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserMapper userMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userMapper.selectOne(
                new LambdaQueryWrapper<User>().eq(User::getUsername, username));

        if (user == null) {
            log.warn("用户不存在: username={}", username);
            throw new UsernameNotFoundException("用户名或密码错误");
        }

        log.debug("加载用户成功: userId={}, username={}, role={}", user.getId(), user.getUsername(), user.getRole());
        return new SecurityUser(user);
    }
}
