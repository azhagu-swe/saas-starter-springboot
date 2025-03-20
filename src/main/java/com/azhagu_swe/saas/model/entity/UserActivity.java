package com.azhagu_swe.saas.model.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Entity
@Table(name = "user_activity")
@Getter
@Setter
public class UserActivity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "activity_type", nullable = false)
    private String activityType;

    @Column(name = "ip_address", nullable = false)
    private String ipAddress;

    @Column(name = "timestamp", nullable = false)
    private Long timestamp;
}
