package com.azhagu_swe.saas.service;

import com.azhagu_swe.saas.dto.request.PermissionRequest;
import com.azhagu_swe.saas.dto.response.PermissionResponse;
import com.azhagu_swe.saas.exception.ResourceNotFoundException;
import com.azhagu_swe.saas.mapper.PermissionMapper;
import com.azhagu_swe.saas.model.entity.Permission;
import com.azhagu_swe.saas.model.repository.PermissionRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class PermissionService {

    private static final Logger logger = LoggerFactory.getLogger(PermissionService.class);
    private final PermissionRepository permissionRepository;

    public List<PermissionResponse> getAllPermissions() {
        List<Permission> permissions = permissionRepository.findAll();
        return permissions.stream()
                .map(PermissionMapper::toResponse)
                .collect(Collectors.toList());
    }

    public PermissionResponse getPermissionById(Long id) {
        Permission permission = permissionRepository.findById(id)
                .orElseThrow(() -> {
                    logger.warn("Permission not found with id: {}", id);
                    return new ResourceNotFoundException("Permission", "id", id);
                });
        return PermissionMapper.toResponse(permission);
    }

    @Transactional
    public PermissionResponse createPermission(PermissionRequest request) {
        // Optionally, check if a permission with the same name exists
        if (permissionRepository.findByName(request.getName()).isPresent()) {
            logger.warn("Attempt to create duplicate permission with name: {}", request.getName());
            throw new IllegalArgumentException("Permission already exists with name: " + request.getName());
        }
        Permission permission = PermissionMapper.toEntity(request);
        Permission savedPermission = permissionRepository.save(permission);
        logger.info("Permission created with id: {}", savedPermission.getId());
        return PermissionMapper.toResponse(savedPermission);
    }

    @Transactional
    public PermissionResponse updatePermission(Long id, PermissionRequest request) {
        Permission permission = permissionRepository.findById(id)
                .orElseThrow(() -> {
                    logger.warn("Permission not found with id: {}", id);
                    return new ResourceNotFoundException("Permission", "id", id);
                });
        PermissionMapper.updateEntity(permission, request);
        Permission updatedPermission = permissionRepository.save(permission);
        logger.info("Permission updated with id: {}", updatedPermission.getId());
        return PermissionMapper.toResponse(updatedPermission);
    }

    @Transactional
    public void deletePermission(Long id) {
        Permission permission = permissionRepository.findById(id)
                .orElseThrow(() -> {
                    logger.warn("Permission not found with id: {}", id);
                    return new ResourceNotFoundException("Permission", "id", id);
                });
        permissionRepository.delete(permission);
        logger.info("Permission deleted with id: {}", id);
    }
}
