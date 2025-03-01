package com.server.oauth2.infrastructure.security.service;

import com.server.oauth2.domain.enums.Role;
import com.server.oauth2.domain.model.User;
import com.server.oauth2.infrastructure.repository.UserRepository;
import com.server.oauth2.infrastructure.security.dto.request.AuthLoginDTO;
import com.server.oauth2.infrastructure.security.dto.request.AuthRegisterDTO;
import com.server.oauth2.infrastructure.security.dto.response.SessionStatusDTO;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Service;

@Service
public class AuthService implements UserDetailsService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    public AuthService(UserRepository userRepository, BCryptPasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado"));

        return org.springframework.security.core.userdetails.User
                .withUsername(user.getUsername())
                .password(user.getPassword())
                .authorities(user.getRole().name())
                .build();
    }

    public ResponseEntity<?> registerUser(AuthRegisterDTO registerDTO) {
        if (registerDTO.getUsername().isBlank() || registerDTO.getPassword().isBlank()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Usuario y contraseña son obligatorios");
        }

        userRepository.findByUsername(registerDTO.getUsername()).ifPresent(user -> {
            throw new IllegalStateException("El usuario ya existe: " + registerDTO.getUsername());
        });

        User user = User.builder()
                .username(registerDTO.getUsername())
                .password(passwordEncoder.encode(registerDTO.getPassword()))
                .role(validateRole(registerDTO.getRole()))
                .build();
        
        userRepository.save(user);

        return ResponseEntity.status(HttpStatus.CREATED).body("Usuario registrado correctamente");
    }

    private Role validateRole(String role) {
        try {
            return Role.valueOf(role.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Role no válido: " + role);
        }
    }

    public ResponseEntity<?> loginUser(AuthLoginDTO loginDTO, HttpServletRequest request) {
        HttpSession existingSession = request.getSession(false);
        if (existingSession != null) {
            existingSession.invalidate();
        }

        HttpSession session = request.getSession(true);

        UserDetails userDetails = loadUserByUsername(loginDTO.getUsername());

        if (!passwordEncoder.matches(loginDTO.getPassword(), userDetails.getPassword())) {
            throw new BadCredentialsException("Credenciales inválidas");
        }

        Authentication authToken = new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities());

        SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
        securityContext.setAuthentication(authToken);
        SecurityContextHolder.setContext(securityContext);

        session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, securityContext);

        return ResponseEntity.ok("Login exitoso" + " ID: " + session.getId());
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

        SecurityContext securityContext = (SecurityContext) session.getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);

        if (securityContext == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("No se ha encontrado una sesión activa");
        }

        Authentication auth = securityContext.getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Usuario no autenticado");
        }

        return ResponseEntity.ok(new SessionStatusDTO(auth.getName(), auth.getAuthorities()));
    }
}
