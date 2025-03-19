package com.azhag_swe.saas.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import com.azhag_swe.saas.security.service.UserDetailsImpl;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

@Component
public class JwtUtils {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${saas.app.jwtSecret}")
    private String jwtSecret;

    @Value("${saas.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    private Key key;

    @PostConstruct
    public void init() {
        // Check if the provided secret is long enough for HS512 (>=512 bits, i.e., at
        // least 64 bytes)
        if (jwtSecret == null || jwtSecret.trim().isEmpty() ||
                jwtSecret.getBytes(StandardCharsets.UTF_8).length < 64) {
            // Generate a secure key if no valid secret is provided (this key will change
            // every startup)
            key = Keys.secretKeyFor(SignatureAlgorithm.HS512);
            logger.warn("No valid JWT secret provided. Generated a new secure key: {}", key);
        } else {
            // Use the provided secret; Keys.hmacShaKeyFor will throw an exception if it's
            // too short.
            key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
        }
    }

    public String generateJwtToken(Authentication authentication) {
        UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();
        return Jwts.builder()
                .setSubject(userPrincipal.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();
    }

    public String getUserNameFromJwtToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    public String generateJwtTokenForUser(UserDetailsImpl userDetails) {
        return Jwts.builder()
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();
    }

    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(authToken);
            return true;
        } catch (JwtException e) {
            // Log the exception using SLF4J
            logger.error("Invalid JWT token: {}", e.getMessage());
        }
        return false;
    }
}
