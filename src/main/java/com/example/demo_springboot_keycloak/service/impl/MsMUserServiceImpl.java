package com.example.demo_springboot_keycloak.service.impl;

import com.example.demo_springboot_keycloak.domain.entities.MsMUser;
import com.example.demo_springboot_keycloak.repository.MsMUserRepo;
import com.example.demo_springboot_keycloak.service.MsMUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class MsMUserServiceImpl implements MsMUserService {
    private final MsMUserRepo msMUserRepo;

    @Autowired
    public MsMUserServiceImpl(MsMUserRepo msMUserRepo) {
        this.msMUserRepo = msMUserRepo;
    }

    @Override
    public MsMUser findByUsername(String username) {
        return msMUserRepo.findByUsername(username);
    }
}
