package com.login.integrated.account.dto;

import com.login.integrated.account.authenum.AuthType;
import lombok.Getter;
import lombok.Setter;

@Getter @Setter
public class AccountDto {

    private String name;
    private String email;
    private String password;

    private AuthType authType;

    public AccountDto(String name, String email, String password, AuthType authType) {
        this.name = name;
        this.email = email;
        this.password = password;
        this.authType = authType;
    }
}