package com.example.demo_springboot_keycloak.controller.ui;

import java.util.Objects;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
public class ControllerUI {
    @GetMapping("/")
    public String getIndex(Model model, Authentication auth) {
        model.addAttribute(
                "name",
                auth instanceof OAuth2AuthenticationToken oauth && oauth.getPrincipal() instanceof OidcUser oidc ?
                        oidc.getPreferredUsername() :
                        "");
        model.addAttribute("isAuthenticated", auth != null && auth.isAuthenticated());
        model.addAttribute("isNice", auth != null && auth.getAuthorities().stream().anyMatch(authority -> Objects.equals("NICE", authority.getAuthority())));
        return "index.html";
    }

    @PreAuthorize("hasRole('NICE')")
    @GetMapping("/nice")
    public String getNice(Model model, Authentication auth) {
        return "nice.html";
    }
}