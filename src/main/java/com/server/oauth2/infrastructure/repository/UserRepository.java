package com.server.oauth2.infrastructure.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.server.oauth2.domain.model.User;

@Repository
public interface UserRepository extends JpaRepository<User, Long>{

}
