package com.server.oauth2.infrastructure.security.utils;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.server.oauth2.domain.model.User;

@Component
public class JWTUtils {

    @Value("${secret.key}")
    private String secret;

    @Value("${token.expiration}")
    private int expirationTime;

    public String generateToken(User user) {
        return JWT.create()
                .withIssuer("Health application")
                .withSubject(user.getUsername())
                .withIssuedAt(getCurrentTime())
                .withExpiresAt(expirationTime(expirationTime))
                .withClaim("rol", user.getRole().toString())
                .withClaim("expiration_date",
                        LocalDateTime.ofInstant(expirationTime(expirationTime), ZoneId.systemDefault())
                                .format(DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss")))
                .withJWTId(UUID.randomUUID().toString())
                .sign(getAlgorithm());
    }

    public String validateToken(String token) {
        JWTVerifier verifier = 
            JWT.require(getAlgorithm())
            .withIssuer("Health application")
            .build();
        return verifier.verify(token).getSubject();
    }

    private Algorithm getAlgorithm() {
        return Algorithm.HMAC512(secret);
    }

    private Instant getCurrentTime() {
        return LocalDateTime.now().atZone(ZoneId.systemDefault()).toInstant();
    }

    private Instant expirationTime(int minutes) {
        return LocalDateTime.now().plusMinutes(minutes).atZone(ZoneId.systemDefault()).toInstant();
    }
}
