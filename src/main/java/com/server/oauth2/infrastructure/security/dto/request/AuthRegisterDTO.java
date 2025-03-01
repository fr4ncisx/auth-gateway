package com.server.oauth2.infrastructure.security.dto.request;

import lombok.Data;

@Data
public class AuthRegisterDTO {
    String username;
    String password;
    String role;

}
