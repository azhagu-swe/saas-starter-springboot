package com.azhag_swe.saas.model.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.azhag_swe.saas.model.entity.Permission;

import java.util.Optional;

public interface PermissionRepository extends JpaRepository<Permission, Long> {
    Optional<Permission> findByName(String name);

    boolean existsByName(String name);
}