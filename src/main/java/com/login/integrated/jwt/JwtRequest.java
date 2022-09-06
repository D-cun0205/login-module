package com.login.integrated.jwt;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class JwtRequest {

    private String token;

    public JwtRequest(String token) {
        this.token = token;
    }
}
