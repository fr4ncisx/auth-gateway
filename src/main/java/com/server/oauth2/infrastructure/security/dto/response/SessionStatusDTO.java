package com.server.oauth2.infrastructure.security.dto.response;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;

public record SessionStatusDTO(String username, Collection<? extends GrantedAuthority> roles) {

}
