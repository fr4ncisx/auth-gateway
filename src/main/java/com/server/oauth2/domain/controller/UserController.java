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

    @PreAuthorize(value = "ROLE_ADMIN")
    @GetMapping("/user-admin")
    public String adminController() {
        return "Hi admin!";
    }

    @PreAuthorize(value = "ROLE_EMPLOYEE")
    @GetMapping("/user-employee")
    public String employeeController() {
        return "Hi employee!";
    }

    @PreAuthorize(value = "ROLE_READER")
    @GetMapping("/user-reader")
    public String readerController() {
        return "Hi reader!";
    }

}
