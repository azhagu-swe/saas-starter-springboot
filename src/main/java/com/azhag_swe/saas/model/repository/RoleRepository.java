package com.azhag_swe.saas.model.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.azhag_swe.saas.model.entity.Role;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(String name);
    
}
