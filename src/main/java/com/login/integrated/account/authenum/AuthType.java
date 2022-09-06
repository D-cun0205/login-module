package com.login.integrated.account.authenum;

public enum AuthType {
    USER("ROLE_USER"), ADMIN("ROLE_ADMIN");

    public final String role;
    AuthType(String role) {
        this.role = role;
    }

    public String getRole() {
        return role;
    }
}
