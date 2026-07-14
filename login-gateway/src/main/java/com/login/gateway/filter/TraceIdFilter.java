package com.login.gateway.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.UUID;

/**
 * TraceId 过滤器 — 全链路追踪
 * <p>
 * 在请求进入 Gateway 时最先执行，生成唯一 traceId：
 * 1. 生成 traceId（UUID 去横线）
 * 2. 写入请求头 X-Trace-Id 透传给下游服务
 * 3. 写入响应头 X-Trace-Id 返回给客户端
 * </p>
 */
@Slf4j
@Component
public class TraceIdFilter implements GlobalFilter, Ordered {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // 1. 生成 traceId — 用于全链路追踪
        String traceId = UUID.randomUUID().toString().replace("-", "");

        // 2. 向下游服务透传 traceId
        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                .header("X-Trace-Id", traceId)
                .build();
        ServerWebExchange mutatedExchange = exchange.mutate().request(mutatedRequest).build();

        // 3. 响应头也加上 traceId，方便客户端排查
        mutatedExchange.getResponse().getHeaders().set("X-Trace-Id", traceId);

        log.debug("traceId 已生成: {}", traceId);
        return chain.filter(mutatedExchange);
    }

    @Override
    public int getOrder() {
        // 在所有自定义过滤器之前执行，保证 traceId 最先被设置
        return -200;
    }
}
