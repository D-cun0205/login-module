package com.login.integrated.account.service;

import com.login.integrated.account.authenum.AuthType;
import com.login.integrated.account.dto.AccountDto;
import com.login.integrated.account.entity.Account;
import com.login.integrated.account.repository.LoginRepository;
import com.login.integrated.exception.InvalidJwtAuthenticationException;
import com.login.integrated.jwt.JwtRefreshRequest;
import com.login.integrated.jwt.JwtResponse;
import com.login.integrated.jwt.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.concurrent.TimeUnit;

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
    private final RedisTemplate<String, String> redisTemplate;

    @Transactional
    public void save(AccountDto dto) {
        Account account = dtoToEntity(dto);
        loginRepository.save(account);
    }

    public JwtResponse login(AccountDto dto) {

        String token = "";
        String refreshToken = "";

        try {
            String username = dto.getEmail();
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, dto.getPassword()));
            List<AuthType> authTypes = getAuthTypes(username);
            token = jwtTokenProvider.createToken(username, authTypes);
            refreshToken = jwtTokenProvider.createRefreshToken(username, authTypes);
            saveRedisRefreshTokenInfo(refreshToken);
        } catch (AuthenticationException e) {
            throw new BadCredentialsException("Invalid email, password supplied");
        }

        return new JwtResponse(token, refreshToken);
    }

    private void saveRedisRefreshTokenInfo(String refreshToken) {
        redisTemplate.opsForValue().set(
                jwtTokenProvider.getUsername(refreshToken),
                refreshToken,
                REFRESH_EXPIRATION_MS,
                TimeUnit.MILLISECONDS
        );
    }

    public JwtResponse isRefreshTokenCreateToken(JwtRefreshRequest jwtRefreshRequest) {
        String refreshToken = jwtRefreshRequest.getRefreshToken();
        String redisKey = jwtTokenProvider.getUsername(refreshToken);
        String redisValue = redisTemplate.opsForValue().get(redisKey);
        if (refreshToken.equals(redisValue)) {
            return new JwtResponse(jwtTokenProvider.createToken(redisKey, getAuthTypes(redisKey)), refreshToken);
        } else {
            throw new InvalidJwtAuthenticationException("Invalid refresh token");
        }
    }

    private List<AuthType> getAuthTypes(String redisKey) {
        return loginRepository.findByEmail(redisKey)
                .orElseThrow(() -> new UsernameNotFoundException("couldn't find email")).getRoles();
    }

    private Account dtoToEntity(AccountDto dto) {
        return new Account(
                dto.getName(),
                dto.getEmail(),
                passwordEncoder.encode(dto.getPassword()),
                List.of(AuthType.USER));
    }
}
