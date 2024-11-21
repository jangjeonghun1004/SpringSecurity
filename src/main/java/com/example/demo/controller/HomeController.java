package com.example.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequestMapping(value = {"", "/"})
public class HomeController {
    private final AuthenticationManager authenticationManager;

    @Autowired
    public HomeController(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }


    @GetMapping
    public String home() {
        return "index";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @PostMapping("/login")
    public String performLogin(
            @RequestParam String username,
            @RequestParam String password,
            Model model
    ) {
        try {
            // 인증 수행
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password)
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // 로그인 성공 시 홈으로 리다이렉트
            return "redirect:/";
        } catch (BadCredentialsException e) {
            // 로그인 실패 시 다시 로그인 페이지로 이동
            model.addAttribute("error", "Invalid username or password");
            return "login";
        }
    }

    @GetMapping("/loginCheck")
    public String loginCheck() {
        return "loginCheck";
    }

}
