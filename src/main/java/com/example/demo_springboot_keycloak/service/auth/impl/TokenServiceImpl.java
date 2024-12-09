package com.example.demo_springboot_keycloak.service.auth.impl;

import com.example.demo_springboot_keycloak.service.auth.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
public class TokenServiceImpl implements TokenService {

    private final RedisTemplate<String, Object> redisTemplate;
    private static final long TIME_TO_LIVE = 3000L;

    @Autowired
    public TokenServiceImpl(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    public void revokeToken(String key, Object token) {
        redisTemplate.opsForSet().add(key, token);
        redisTemplate.expire(key, Duration.ofSeconds(TIME_TO_LIVE));
    }

    @Override
    public boolean isTokenRevoked(String key, Object token) {
        return Boolean.TRUE.equals(redisTemplate.opsForSet().isMember(key, token));
    }
}
