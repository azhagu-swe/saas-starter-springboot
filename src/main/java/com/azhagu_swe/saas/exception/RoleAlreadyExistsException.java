package com.azhagu_swe.saas.exception;


import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

import com.azhagu_swe.saas.enumeration.ErrorCode;

@ResponseStatus(HttpStatus.CONFLICT) // 409 - Conflict
public class RoleAlreadyExistsException extends ApplicationException {

    private final String resourceName;
    private final String fieldName;
    private final Object fieldValue;

    public RoleAlreadyExistsException(String resourceName, String fieldName, Object fieldValue) {
        super(ErrorCode.ROLE_ALREADY_EXISTS, String.format("%s already exists with %s: '%s'", resourceName, fieldName, fieldValue));
        this.resourceName = resourceName;
        this.fieldName = fieldName;
        this.fieldValue = fieldValue;
    }

    public String getResourceName() {
        return resourceName;
    }

    public String getFieldName() {
        return fieldName;
    }

    public Object getFieldValue() {
        return fieldValue;
    }
}
