package com.example.demo_springboot_keycloak.utils;

import com.example.demo_springboot_keycloak.service.auth.AuthService;
import com.example.demo_springboot_keycloak.service.auth.TokenService;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.Collection;
import java.util.Map;

public class CustomJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private final Converter<Map<String, Object>, Collection<GrantedAuthority>> authoritiesConverter;
    private final TokenService tokenService;

    public CustomJwtAuthenticationConverter(Converter<Map<String, Object>, Collection<GrantedAuthority>> authoritiesConverter, TokenService tokenService)
    {
        this.authoritiesConverter = authoritiesConverter;
        this.tokenService = tokenService;
    }

    @Override
    public AbstractAuthenticationToken convert (Jwt jwt){
        String token = jwt.getTokenValue();
        if (tokenService.isTokenRevoked(jwt.getClaimAsString("sub"), token)) {
            throw new BadCredentialsException("Token is revoked");
        }
        Collection<GrantedAuthority> authorities = authoritiesConverter.convert(jwt.getClaims());
        return new JwtAuthenticationToken(jwt, authorities);
    }
}