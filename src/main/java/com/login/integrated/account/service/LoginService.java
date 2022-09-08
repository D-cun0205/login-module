package com.login.integrated.account.service;

import com.login.integrated.account.authenum.AuthType;
import com.login.integrated.account.dto.AccountDto;
import com.login.integrated.account.entity.Account;
import com.login.integrated.account.repository.LoginRepository;
import com.login.integrated.exception.InvalidJwtAuthenticationException;
import com.login.integrated.jwt.JwtRefreshRequest;
import com.login.integrated.jwt.JwtResponse;
import com.login.integrated.jwt.JwtTokenProvider;
import com.login.integrated.redis.RedisTokenEntity;
import com.login.integrated.redis.RedisTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

import static com.login.integrated.jwt.JwtTokenProvider.REFRESH_EXPIRATION_MS;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
@Slf4j
public class LoginService {

    private final LoginRepository loginRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final RedisTokenRepository redisTokenRepository;

    @Transactional
    public void save(AccountDto dto) {
        Account account = new Account(
                dto.getName(),
                dto.getEmail(),
                passwordEncoder.encode(dto.getPassword()),
                List.of(AuthType.USER));
        loginRepository.save(account);
    }

    public JwtResponse login(AccountDto dto) {

        String token;
        String refreshToken;

        try {
            String username = dto.getEmail();
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, dto.getPassword()));
            List<AuthType> authTypes = getAuthTypes(username);
            token = jwtTokenProvider.createToken(username, authTypes);
            refreshToken = jwtTokenProvider.createRefreshToken(username, authTypes);
            saveRedisRefreshTokenInfo(username, refreshToken);
        } catch (AuthenticationException e) {
            throw new BadCredentialsException("Invalid email, password supplied");
        }

        return new JwtResponse(token, refreshToken);
    }

    private void saveRedisRefreshTokenInfo(String emailKey, String refreshToken) {
        RedisTokenEntity redisTokenEntity =
                new RedisTokenEntity(emailKey, refreshToken, REFRESH_EXPIRATION_MS);
        redisTokenRepository.save(redisTokenEntity);
    }

    public JwtResponse isRefreshTokenCreateToken(JwtRefreshRequest jwtRefreshRequest) {
        String refreshToken = jwtRefreshRequest.getRefreshToken();
        String redisKeyEmail = jwtTokenProvider.getUsername(refreshToken);
        String redisRefreshToken = redisTokenRepository.findById(redisKeyEmail).orElseThrow(
                () -> new UsernameNotFoundException("Invalid account")).getRefreshToken();

        if (refreshToken.equals(redisRefreshToken)) {
            return new JwtResponse(
                    jwtTokenProvider.createToken(redisKeyEmail, getAuthTypes(redisKeyEmail)),
                    refreshToken);
        } else {
            throw new InvalidJwtAuthenticationException("Invalid refresh token");
        }
    }

    private List<AuthType> getAuthTypes(String email) {
        return loginRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("couldn't find email")).getRoles();
    }

    public void removeRefreshToken(JwtRefreshRequest request) {
        String redisKeyEmail = jwtTokenProvider.getUsername(request.getRefreshToken());
        redisTokenRepository.deleteById(redisKeyEmail);
    }
}
