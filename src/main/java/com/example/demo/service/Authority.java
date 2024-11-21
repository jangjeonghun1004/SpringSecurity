package com.example.demo.service;

import org.springframework.security.core.GrantedAuthority;

public class Authority implements GrantedAuthority {
    @Override
    public String getAuthority() {
        return "ROLE_USER";
    }
}
