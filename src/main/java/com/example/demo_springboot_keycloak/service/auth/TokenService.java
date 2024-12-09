package com.example.demo_springboot_keycloak.service.auth;

public interface TokenService {
    void revokeToken(String key, Object token);
    boolean isTokenRevoked(String key, Object token);
}
