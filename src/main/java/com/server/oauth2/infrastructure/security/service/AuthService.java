package com.server.oauth2.infrastructure.security.service;

import com.server.oauth2.domain.enums.Role;
import com.server.oauth2.domain.model.User;
import com.server.oauth2.infrastructure.repository.UserRepository;
import com.server.oauth2.infrastructure.security.dto.request.AuthLoginDTO;
import com.server.oauth2.infrastructure.security.dto.request.AuthRegisterDTO;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    public AuthService(UserRepository userRepository, BCryptPasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public User registerUser(AuthRegisterDTO registerDTO) {
        checksIfUserExists(registerDTO.getUsername());
        User user = User.builder()
                .username(registerDTO.getUsername())
                .password(passwordEncoder.encode(registerDTO.getPassword()))
                .role(validateRole(registerDTO.getRole()))
                .build();
        return userRepository.save(user);
    }

    private boolean checksIfUserExists(String username) {
        if (userRepository.findByUsername(username).isPresent()) {
            throw new IllegalStateException("El usuario ya existe: " + username);
        }
        return false;
    }

    private Role validateRole(String role) {
        for (Role r : Role.values()) {
            if (r.name().equalsIgnoreCase(role)) {
                return r;
            }
        }
        throw new IllegalArgumentException("Role no válido: " + role);
    }

    public ResponseEntity<?> loginUser(AuthLoginDTO loginDTO, HttpServletRequest request) {
        Optional<User> optionalUser = userRepository.findByUsername(loginDTO.getUsername());

        if (optionalUser.isEmpty()) {
            return ResponseEntity.status(401).body("Usuario no encontrado");
        }

        User user = optionalUser.get();
        if (!passwordEncoder.matches(loginDTO.getPassword(), user.getPassword())) {
            return ResponseEntity.status(401).body("Credenciales incorrectas");
        }

        // Here we want to delete old session and get a new one
        HttpSession oldSession = request.getSession(false);
        if (oldSession != null) {
            oldSession.invalidate();
        }

        // Crear nueva sesión
        HttpSession newSession = request.getSession(true);

        // Crear autenticación
        Authentication authentication = new UsernamePasswordAuthenticationToken(user.getUsername(), null,
                user.getAuthorities());

        // Guardar autenticación en SecurityContextHolder
        SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
        securityContext.setAuthentication(authentication);
        SecurityContextHolder.setContext(securityContext);

        // Asociar SecurityContext a la sesión
        newSession.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, securityContext);

        return ResponseEntity.ok("Login exitoso, nueva sesión ID: " + newSession.getId());
    }

    public ResponseEntity<?> logoutUser(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        SecurityContextHolder.clearContext();
        return ResponseEntity.ok("Logout exitoso");
    }

    public ResponseEntity<?> getSessionStatus(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Sesión no encontrada");
        }

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Usuario no autenticado");
        }

        return ResponseEntity.ok("Sesión activa para: " + auth.getName());
    }
}