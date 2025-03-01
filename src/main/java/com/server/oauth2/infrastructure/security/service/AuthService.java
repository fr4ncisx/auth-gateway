package com.server.oauth2.infrastructure.security.service;

import com.server.oauth2.domain.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.server.oauth2.infrastructure.repository.UserRepository;
import com.server.oauth2.infrastructure.security.dto.request.AuthLoginDTO;
import com.server.oauth2.infrastructure.security.dto.response.TokenDTO;
import com.server.oauth2.infrastructure.security.utils.JWTUtils;

@Service
public class AuthService implements UserDetailsService {

    @Autowired
    private JWTUtils jwtUtils;
    @Autowired
    private BCryptPasswordEncoder passwordEncoder;
    @Autowired
    private UserRepository userRepository;

    public ResponseEntity<?> logout() {
        SecurityContextHolder.clearContext();
        return ResponseEntity.ok().build();
    }

    public ResponseEntity<?> loginUser(AuthLoginDTO userLogin) {
        String user = userLogin.getUsername();
        String password = userLogin.getPassword();
        Authentication authentication = authenticate(user, password);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        var userEntity = loadUserByUsername(user);
        String token = jwtUtils.generateToken((User) userEntity);
        TokenDTO response = new TokenDTO(token);
        return ResponseEntity.ok(response);
    }

    private Authentication authenticate(String user, String password) {
        UserDetails userDetails = loadUserByUsername(user);
        if (userDetails == null) {
            throw new UsernameNotFoundException("User not found");
        }
        if (!passwordEncoder.matches(password, userDetails.getPassword())) {
            throw new BadCredentialsException("Incorrect password");
        }
        return new UsernamePasswordAuthenticationToken(user, userDetails.getPassword());
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByUsername(username)
                .map(user -> user)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
    }
}