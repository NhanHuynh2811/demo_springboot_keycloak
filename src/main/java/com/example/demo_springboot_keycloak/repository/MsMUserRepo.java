package com.example.demo_springboot_keycloak.repository;

import com.example.demo_springboot_keycloak.domain.entities.MsMUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface MsMUserRepo extends JpaRepository<MsMUser, Long> {
    MsMUser findByUsername(String username);
}
