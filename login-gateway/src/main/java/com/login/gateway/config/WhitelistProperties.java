package com.login.gateway.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import java.util.ArrayList;
import java.util.List;

@Component
@ConfigurationProperties(prefix = "jwt.whitelist")
@Data
public class WhitelistProperties {

    /**
     * 是否启用白名单
     */
    private Boolean enabled = true;

    /**
     * 白名单路径列表
     */
    private List<String> paths = new ArrayList<>();
}