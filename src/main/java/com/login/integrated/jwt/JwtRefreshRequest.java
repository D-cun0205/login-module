package com.login.integrated.jwt;

import lombok.Getter;
import lombok.Setter;

@Getter @Setter
public class JwtRefreshRequest {

    private String refreshToken;

    public JwtRefreshRequest() { }

    public JwtRefreshRequest(String refreshToken) {
        this.refreshToken = refreshToken;
    }
}
