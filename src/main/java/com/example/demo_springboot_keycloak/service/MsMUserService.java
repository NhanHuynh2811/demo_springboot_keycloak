package com.example.demo_springboot_keycloak.service;

import com.example.demo_springboot_keycloak.domain.entities.MsMUser;

public interface MsMUserService {
    MsMUser findByUsername(String username);
}
