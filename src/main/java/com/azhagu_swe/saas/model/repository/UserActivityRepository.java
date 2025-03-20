package com.azhagu_swe.saas.model.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import com.azhagu_swe.saas.model.entity.UserActivity;

public interface UserActivityRepository extends JpaRepository<UserActivity, Long> {
}