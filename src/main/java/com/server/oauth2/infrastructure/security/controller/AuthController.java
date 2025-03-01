package com.server.oauth2.infrastructure.security.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.server.oauth2.infrastructure.security.dto.request.AuthLoginDTO;
import com.server.oauth2.infrastructure.security.dto.request.AuthRegisterDTO;
import com.server.oauth2.infrastructure.security.service.AuthService;

import jakarta.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody AuthRegisterDTO registerDTO) {
        authService.registerUser(registerDTO);
        return ResponseEntity.ok("Usuario registrado correctamente");
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthLoginDTO loginDTO, HttpServletRequest request) {
        return authService.loginUser(loginDTO, request);
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request) {
        return authService.logoutUser(request);
    }

    @GetMapping("/session")
    public ResponseEntity<?> getSessionStatus(HttpServletRequest request) {
        return authService.getSessionStatus(request);
    }
}
