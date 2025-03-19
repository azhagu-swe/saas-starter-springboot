package com.azhag_swe.saas.exception;

import com.azhag_swe.saas.enumeration.ErrorCode;

public class TokenRefreshException extends ApplicationException {
    public TokenRefreshException() {
        super(ErrorCode.TOKEN_EXPIRED);
    }

    public TokenRefreshException(String token) {
        super(ErrorCode.TOKEN_EXPIRED,
                String.format("Token [%s] error: %s", token, ErrorCode.TOKEN_EXPIRED.getMessage()));
    }
}
