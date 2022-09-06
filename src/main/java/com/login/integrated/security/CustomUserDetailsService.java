package com.login.integrated.security;

import com.login.integrated.account.entity.Account;
import com.login.integrated.account.repository.LoginRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final LoginRepository repository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Account findAccount = repository.findByEmail(username).orElseThrow(
                () -> new UsernameNotFoundException("couldn't find email"));
        return new CustomUserDetails(findAccount);
    }
}