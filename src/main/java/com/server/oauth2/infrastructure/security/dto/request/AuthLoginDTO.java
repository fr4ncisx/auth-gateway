package com.server.oauth2.infrastructure.security.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.*;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class AuthLoginDTO {
    @NotNull @NotBlank(message = "Username is empty")
    String username;    
    @NotNull @NotBlank(message = "Password is empty")
    String password;
}
