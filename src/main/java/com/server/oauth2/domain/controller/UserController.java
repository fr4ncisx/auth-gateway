package com.server.oauth2.domain.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * This is for testing purposes to reduce the complexity of the code we use all
 * the logic in the controller
 */
@RestController
@RequestMapping("/user")
public class UserController {

    @GetMapping("/public")
    public String publicEndpoint() {
        return "Este endpoint es público";
    }

    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    @GetMapping("/user")
    public String userEndpoint() {
        return "Este endpoint es accesible para usuarios con rol USER o ADMIN";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public String adminEndpoint() {
        return "Este endpoint es accesible solo para ADMIN";
    }

}
