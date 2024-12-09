package com.example.demo_springboot_keycloak.controller;


import com.example.demo_springboot_keycloak.domain.dto.LogoutRequestDto;
import com.example.demo_springboot_keycloak.service.auth.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequestMapping(value = "/auth")
public class AuthController {

    public final AuthService authService;

    @Autowired
    AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping(value = "/logout")
    public void logout(@RequestBody LogoutRequestDto logoutRequestDto, JwtAuthenticationToken jwtAuthenticationToken) throws IOException {
        authService.logout(logoutRequestDto, jwtAuthenticationToken);
    }
}
