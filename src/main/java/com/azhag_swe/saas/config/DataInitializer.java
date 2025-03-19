package com.azhag_swe.saas.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.azhag_swe.saas.service.DataInitializerService;

import jakarta.annotation.PostConstruct;

@Component
public class DataInitializer {

    @Autowired
    private DataInitializerService initializerService;

    @PostConstruct
    public void init() {
        initializerService.initializeData();
    }
}
