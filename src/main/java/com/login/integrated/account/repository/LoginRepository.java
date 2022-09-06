package com.login.integrated.account.repository;

import com.login.integrated.account.entity.Account;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface LoginRepository extends JpaRepository<Account, Long> {

    Optional<Account> findByEmail(String email);
}
