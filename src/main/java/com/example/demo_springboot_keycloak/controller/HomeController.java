package com.example.demo_springboot_keycloak.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.core.GrantedAuthority;

import java.util.List;

@Slf4j
@RestController
@RequestMapping(value = "/home")
public class HomeController {

    @GetMapping(value = "/public")
    public ResponseEntity<Object> home() {
        return new ResponseEntity<>("PAGE_PUBLIC", HttpStatus.OK);
    }

    @GetMapping("/me")
    @PreAuthorize("hasRole('ROLE_read')")
    public UserInfoDto getGretting(JwtAuthenticationToken auth, Authentication authentication) {
        return new UserInfoDto(
                auth.getToken().getClaimAsString(StandardClaimNames.PREFERRED_USERNAME),
                auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList());
    }

    public static record UserInfoDto(String name, List<String> roles) {
    }
}
