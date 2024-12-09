package com.example.demo_springboot_keycloak.config.auth;

import com.example.demo_springboot_keycloak.service.auth.TokenService;
import com.example.demo_springboot_keycloak.utils.CustomJwtAuthenticationConverter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

@Slf4j
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class WebSecurityConfiguration {

    private static final String CLAIM_REALM_ACCESS = "realm_access";

    interface AuthoritiesConverter extends Converter<Map<String, Object>, Collection<GrantedAuthority>> {
    }

    @Bean
    AuthoritiesConverter realmRolesAuthoritiesConverter() {
        return claims -> {
            final var realmAccess = Optional.ofNullable((Map<String, Object>) claims.get(CLAIM_REALM_ACCESS));
            final var roles =
                    realmAccess.flatMap(map -> Optional.ofNullable((List<String>) map.get("roles")));
            return roles.map(List::stream)
                    .orElse(Stream.empty())
                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                    .map(GrantedAuthority.class::cast)
                    .toList();
        };
    }

    @Bean
    JwtAuthenticationConverter authenticationConverter(
            Converter<Map<String, Object>, Collection<GrantedAuthority>> authoritiesConverter) {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter
                .setJwtGrantedAuthoritiesConverter(jwt -> authoritiesConverter.convert(jwt.getClaims()));
        return jwtAuthenticationConverter;
    }


    @Bean
    AuthenticationManager customAuthenticationManager(
            TokenService tokenService,
            JwtAuthenticationConverter authenticationConverter) {
        return authentication -> {
            if (authentication instanceof JwtAuthenticationToken jwtAuth) {
                String token = jwtAuth.getToken().getTokenValue();
                if (tokenService.isTokenRevoked(jwtAuth.getToken().getClaimAsString("sub"), token)) {
                    throw new BadCredentialsException("Token is revoked");
                }
                return jwtAuth;
            }
            throw new BadCredentialsException("Invalid authentication token");
        };
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, CustomAuthenticationEntryPoint entryPoint,
                                                   CustomAccessDenied accessDenied, TokenService tokenService) throws Exception {

        Converter<Jwt, AbstractAuthenticationToken> jwtAuthenticationConverter = new CustomJwtAuthenticationConverter(realmRolesAuthoritiesConverter(), tokenService);

        http.authorizeHttpRequests(authorizeRequests ->
                authorizeRequests
                        .requestMatchers("/home/me").authenticated()
                        .requestMatchers("/home/public/**").permitAll()
                        .requestMatchers("/auth/**").permitAll()
                        .requestMatchers("/logout").authenticated()
                        .anyRequest().authenticated()

        );
        http.exceptionHandling(exceptionHandling -> exceptionHandling
                .authenticationEntryPoint(entryPoint)
                .accessDeniedHandler(accessDenied));

        http.sessionManagement(sessions -> {
            sessions.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        }).csrf(AbstractHttpConfigurer::disable);

        http.oauth2ResourceServer(resourceServer -> {
            resourceServer.jwt(jwtDecoder -> {
                jwtDecoder.jwtAuthenticationConverter(jwtAuthenticationConverter);
            });
        });

        http.logout(logout -> logout
                .logoutSuccessUrl("/logout")
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .deleteCookies("JSESSIONID")
                .logoutUrl("/logout")
                .addLogoutHandler((request, response, authentication) -> {
                    request.getSession().invalidate();
                }));

        return http.build();
    }

}
