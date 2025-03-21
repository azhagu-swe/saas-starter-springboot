package com.azhagu_swe.saas.service;

import com.azhagu_swe.saas.dto.request.RoleRequest;
import com.azhagu_swe.saas.dto.response.RoleResponse;
import com.azhagu_swe.saas.exception.ResourceNotFoundException;
import com.azhagu_swe.saas.mapper.RoleMapper;
import com.azhagu_swe.saas.model.entity.Role;
import com.azhagu_swe.saas.model.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class RoleService {

    private static final Logger logger = LoggerFactory.getLogger(RoleService.class);
    private final RoleRepository roleRepository;

    public Page<RoleResponse> getAllRoles(Pageable pageable) {
        logger.info("Fetching all roles with pagination");
        return roleRepository.findAll(pageable)
                .map(RoleMapper::toResponse);
    }

    public RoleResponse getRoleById(Long id) {
        logger.info("Fetching role with id {}", id);
        Role role = roleRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Permission", "id", id));
        return RoleMapper.toResponse(role);
    }

    @Transactional
    public RoleResponse createRole(RoleRequest request) {
        // Optionally, you could check for duplicates here and throw a custom exception
        // if needed.
        if (roleRepository.findByName(request.getName()).isPresent()) {
            logger.warn("Attempt to create duplicate role with name: {}", request.getName());
            throw new IllegalArgumentException("Role already exists with name: " + request.getName());
        }
        Role role = RoleMapper.toEntity(request);
        Role savedRole = roleRepository.save(role);
        logger.info("Role created with id: {}", savedRole.getId());
        return RoleMapper.toResponse(savedRole);
    }

    @Transactional
    public RoleResponse updateRole(Long id, RoleRequest request) {
        logger.info("Updating role with id {}", id);
        Role existingRole = roleRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Role", "id", id));
        RoleMapper.updateEntity(existingRole, request);
        Role updatedRole = roleRepository.save(existingRole);
        logger.info("Role updated with id: {}", updatedRole.getId());
        return RoleMapper.toResponse(updatedRole);
    }

    @Transactional
    public void deleteRole(Long id) {
        logger.info("Deleting role with id {}", id);
        Role role = roleRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Role", "id", id));
        roleRepository.delete(role);
        logger.info("Role deleted with id: {}", id);
    }
}
