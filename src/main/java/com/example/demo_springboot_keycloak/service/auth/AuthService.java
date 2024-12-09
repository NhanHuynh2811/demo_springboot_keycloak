package com.example.demo_springboot_keycloak.service.auth;

import com.example.demo_springboot_keycloak.domain.dto.LogoutRequestDto;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

public interface AuthService {
    ResponseEntity<Object> logout(LogoutRequestDto logoutRequestDto, JwtAuthenticationToken jwtAuthenticationToken);
}
