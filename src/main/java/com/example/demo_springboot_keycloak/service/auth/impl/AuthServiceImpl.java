package com.example.demo_springboot_keycloak.service.auth.impl;

import com.example.demo_springboot_keycloak.domain.dto.BaseResponseDto;
import com.example.demo_springboot_keycloak.domain.dto.LogoutRequestDto;
import com.example.demo_springboot_keycloak.service.auth.AuthService;
import com.example.demo_springboot_keycloak.service.auth.TokenService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;


@Slf4j
@Service
public class AuthServiceImpl implements AuthService {

    private final TokenService tokenService;
    private final RestTemplate restTemplate;

    //@Value("${keycloak.logout-url}")
    private String keycloakLogoutUrl = "http://localhost:8080/realms/msm_realm/protocol/openid-connect/logout";

    public AuthServiceImpl(RestTemplate restTemplate, TokenService tokenService) {
        this.restTemplate = restTemplate;
        this.tokenService = tokenService;
    }


    @Override
    public ResponseEntity<Object> logout(LogoutRequestDto logoutRequestDto, JwtAuthenticationToken jwt) {
        // Validate input
        if (logoutRequestDto.getTokenId() == null) {
            throw new IllegalArgumentException("Missing clientId or clientSecret");
        }

        var url = keycloakLogoutUrl+"?id_token_hint="+logoutRequestDto.getTokenId();
        try {
            log.info("logout keycloak: {}", url);
            ResponseEntity<String> response = restTemplate.getForEntity(url, String.class);
            log.info("Response from Keycloak logout: {}", response.getBody());
            String sub = jwt.getToken().getClaimAsString("sub");
            log.info("revoked token principle id: {}", sub);
            tokenService.revokeToken(sub, jwt.getToken().getTokenValue());
        } catch (Exception e) {
            throw new RuntimeException("Keycloak logout failed: " + e.getMessage(), e);
        }
        return ResponseEntity.ok().body(BaseResponseDto.builder()
                .status("SUCCESS")
                .build());
    }
}
