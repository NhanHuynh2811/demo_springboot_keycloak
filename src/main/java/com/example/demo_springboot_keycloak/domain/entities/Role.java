package com.example.demo_springboot_keycloak.domain.entities;

import jakarta.persistence.Entity;
import jakarta.persistence.ManyToMany;
import lombok.*;

import java.util.Set;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Role extends BaseEntity{
    private String name;

    @ManyToMany(mappedBy = "roles")
    private Set<MsMUser> userRoleMapping;
}
