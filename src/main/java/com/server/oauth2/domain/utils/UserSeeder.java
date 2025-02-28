package com.server.oauth2.domain.utils;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import com.server.oauth2.domain.enums.Role;
import com.server.oauth2.domain.model.User;
import com.server.oauth2.infrastructure.repository.UserRepository;

import jakarta.transaction.Transactional;

@Component
public class UserSeeder implements CommandLineRunner {

    @Autowired
    private UserRepository userRepository;

    @Override
    public void run(String... args) throws Exception {
        createUser();
    }

    @Transactional
    public void createUser() {
        if (userRepository.count() == 0) {
            userRepository.saveAll(List.of(
                    new User("admin", "1234", Role.ADMIN),
                    new User("employee", "1234", Role.EMPLOYEE),
                    new User("reader", "1234", Role.READER)));
        }
    }

}
