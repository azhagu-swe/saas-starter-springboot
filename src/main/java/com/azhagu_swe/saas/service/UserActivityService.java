package com.azhagu_swe.saas.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.azhagu_swe.saas.model.entity.UserActivity;
import com.azhagu_swe.saas.model.repository.UserActivityRepository;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserActivityService {

    private final UserActivityRepository userActivityRepository;
    private static final Logger logger = LoggerFactory.getLogger(UserActivityService.class);

    @Transactional
    public void logUserActivity(Long userId, String activityType, String ipAddress) {
        try {
            UserActivity userActivity = new UserActivity();
            userActivity.setUserId(userId);
            userActivity.setActivityType(activityType);
            userActivity.setIpAddress(ipAddress);
            userActivity.setTimestamp(System.currentTimeMillis()); // Use System.currentTimeMillis() for simplicity and
                                                                   // consistency
            userActivityRepository.save(userActivity);
            logger.info("User activity logged: userId={}, activityType={}, ipAddress={}", userId, activityType,
                    ipAddress);
        } catch (Exception e) {
            logger.error("Error logging user activity: userId={}, activityType={}, ipAddress={}. Error: {}",
                    userId, activityType, ipAddress, e.getMessage(), e);
            // Important: Consider what to do here.
            // Should the user operation fail?
            // Should this be retried?
            // For this example, we'll just log and continue. A more robust solution might
            // involve a retry mechanism or a dead-letter queue.
        }
    }
}
