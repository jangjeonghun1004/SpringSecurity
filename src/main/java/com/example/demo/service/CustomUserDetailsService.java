package com.example.demo.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 예: 데이터베이스에서 사용자 조회
        if ("james".equals(username)) {
            return org.springframework.security.core.userdetails.User
                    .withUsername("james")
                    .password("12345")
                    .roles("USER")
//                    .roles(user.getAuthorities().stream()
//                        .map(authority -> authority.getAuthority())
//                        .toArray(String[]::new))
                    .build();
        }

        throw new UsernameNotFoundException("User not found");
    }

}

