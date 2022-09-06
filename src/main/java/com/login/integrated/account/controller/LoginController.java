package com.login.integrated.account.controller;

import com.login.integrated.account.dto.AccountDto;
import com.login.integrated.account.service.LoginService;
import com.login.integrated.jwt.JwtRefreshRequest;
import com.login.integrated.jwt.JwtResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1")
public class LoginController {

    private final LoginService loginService;

    @PostMapping("/join")
    public ResponseEntity<String> join(@RequestBody AccountDto dto) {
        loginService.save(dto);
        return ResponseEntity.ok().body("Success!!!");
    }

    @GetMapping("/login")
    public ResponseEntity<JwtResponse> login(@RequestBody AccountDto dto) {
        JwtResponse response = loginService.login(dto);
        return ResponseEntity.ok().body(response);
    }

    @GetMapping("/isRefreshTokenCreateToken")
    public ResponseEntity<JwtResponse> isRefreshTokenCreateToken(@RequestBody JwtRefreshRequest jwtRefreshRequest) {
        JwtResponse jwtResponse = loginService.isRefreshTokenCreateToken(jwtRefreshRequest);
        return ResponseEntity.ok().body(jwtResponse);
    }

    /**
     * 네이버, 구글, 페이스북 벤더단위로 기능 세분화 필요
     */
    @GetMapping("/oauthLogin")
    public ResponseEntity<String> oauthLogin() throws Exception {
        return ResponseEntity.ok().body("Success oauth login");
    }

}
