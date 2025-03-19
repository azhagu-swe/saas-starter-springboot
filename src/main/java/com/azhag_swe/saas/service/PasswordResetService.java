package com.azhag_swe.saas.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.azhag_swe.saas.model.entity.PasswordResetToken;
import com.azhag_swe.saas.model.entity.User;
import com.azhag_swe.saas.model.repository.PasswordResetTokenRepository;

import java.util.UUID;

@Service
public class PasswordResetService {

    @Autowired
    private PasswordResetTokenRepository tokenRepository;

    @Transactional
    public PasswordResetToken createPasswordResetTokenForUser(User user) {
        String token = UUID.randomUUID().toString();
        PasswordResetToken resetToken = new PasswordResetToken(token, user);
        return tokenRepository.save(resetToken);
    }

    @Transactional(readOnly = true)
    public PasswordResetToken validatePasswordResetToken(String token) {
        return tokenRepository.findByToken(token)
                .filter(t -> !t.isExpired())
                .orElseThrow(() -> new RuntimeException("Invalid or expired token"));
    }

    @Transactional
    public void deleteToken(PasswordResetToken token) {
        tokenRepository.delete(token);
    }

    @Transactional
    public void deleteTokensByUser(User user) {
        tokenRepository.deleteByUser(user);
    }
}