package com.server.oauth2.infrastructure.security;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableMethodSecurity
@EnableWebSecurity
@Configuration
public class SecurityFilterConfig {

    @Autowired
    private JWTFilter jwtFilter;

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().authenticated())
                .formLogin(formLogin -> formLogin
                        .loginPage("/login")
                        .permitAll())
                //.rememberMe(Customizer.withDefaults())
                .addFilterAfter(jwtFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    /**
     * Bean thats encodes the user password at our database with BCrypt
     */
    @Bean
    BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig)
            throws Exception {
        return authConfig.getAuthenticationManager();
    }
}
