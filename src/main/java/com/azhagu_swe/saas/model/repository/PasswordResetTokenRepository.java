package com.azhagu_swe.saas.model.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.azhagu_swe.saas.model.entity.PasswordResetToken;
import com.azhagu_swe.saas.model.entity.User;

import java.util.Optional;

public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {
    Optional<PasswordResetToken> findByToken(String token);

    void deleteByUser(User user);
}
