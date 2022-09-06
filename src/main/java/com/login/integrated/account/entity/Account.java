package com.login.integrated.account.entity;

import com.login.integrated.account.authenum.AuthType;
import lombok.Getter;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.List;

@Entity
@Getter
public class Account {

    @Id @GeneratedValue
    @Column(name = "account_id")
    private Long id;

    private String name;
    private String email;
    private String password;

    @ElementCollection(fetch = FetchType.EAGER)
    @Enumerated(EnumType.STRING)
    private List<AuthType> roles = new ArrayList<>();

    protected Account() { }

    public Account(String name, String email, String password, List<AuthType> roles) {
        this.name = name;
        this.email = email;
        this.password = password;
        this.roles = roles;
    }
}
