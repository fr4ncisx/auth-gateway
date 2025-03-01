package com.server.oauth2.infrastructure.security.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.server.oauth2.infrastructure.security.dto.request.AuthLoginDTO;
import com.server.oauth2.infrastructure.security.service.AuthService;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@Valid @RequestBody AuthLoginDTO userLogin) {
        return authService.loginUser(userLogin);
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logoutUser() {
        return authService.logout();
    }

}
