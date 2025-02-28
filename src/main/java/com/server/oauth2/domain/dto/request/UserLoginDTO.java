package com.server.oauth2.domain.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.*;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserLoginDTO {
    @NotNull @NotBlank(message = "Username is empty")
    String username;    
    @NotNull @NotBlank(message = "Password is empty")
    String password;
}
