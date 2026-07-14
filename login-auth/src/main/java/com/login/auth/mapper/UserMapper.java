package com.login.auth.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.login.auth.entity.User;
import org.apache.ibatis.annotations.Mapper;

/**
 * 用户 Mapper
 */
@Mapper
public interface UserMapper extends BaseMapper<User> {
}
