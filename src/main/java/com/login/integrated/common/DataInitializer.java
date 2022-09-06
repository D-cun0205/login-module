package com.login.integrated.common;

import com.login.integrated.account.authenum.AuthType;
import com.login.integrated.account.entity.Account;
import com.login.integrated.account.repository.LoginRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@RequiredArgsConstructor
@Slf4j
public class DataInitializer implements CommandLineRunner {

    private final LoginRepository loginRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        loginRepository.save(
                new Account("A1", "A1@email.com", passwordEncoder.encode("1234"), List.of(AuthType.USER, AuthType.ADMIN))
        );
        loginRepository.save(
                new Account("B1", "B1@email.com", passwordEncoder.encode("1234"), List.of(AuthType.USER, AuthType.ADMIN))
        );

    }
}
