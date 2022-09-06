package com.login.integrated.jwt;

import com.login.integrated.account.authenum.AuthType;
import com.login.integrated.exception.InvalidJwtAuthenticationException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.security.Key;
import java.util.Date;
import java.util.List;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtTokenProvider {

    private final Key secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    private final Long ACCESS_EXPIRATION_MS = 3600000L;
    public static final Long REFRESH_EXPIRATION_MS = 86400000L;

    private final UserDetailsService userDetailsService;

    public String createToken(String username, List<AuthType> roles) {
        return getToken(
                getClaims(username, roles),
                new Date(),
                getExpiration(ACCESS_EXPIRATION_MS));
    }

    public String createRefreshToken(String username, List<AuthType> roles) {
        return getToken(
                getClaims(username, roles),
                new Date(),
                getExpiration(REFRESH_EXPIRATION_MS * 14));
    }

    private Date getExpiration(Long expiration) {
        return new Date(new Date().getTime() + expiration);
    }

    private Claims getClaims(String username, List<AuthType> roles) {
        Claims claims = Jwts.claims().setSubject(username);
        claims.put("roles", roles);
        return claims;
    }

    private String getToken(Claims claims, Date now, Date validity) {
        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(secretKey)
                .compact();
    }

    public Authentication getAuthentication(String token) {
        UserDetails userDetails =
                userDetailsService.loadUserByUsername(getUsername(token));
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

    public String getUsername(String token) {
        return getClaimsBody(token).getSubject();
    }

    public String getToken(HttpServletRequest request) {
        String token = request.getHeader("Authorization");
        return (token != null && token.startsWith("Bearer ")) ? token.substring(7) : null;
    }

    public boolean validateToken(String token) {
        try {
            return !getClaimsBody(token).getExpiration().before(new Date());
        } catch (JwtException | IllegalArgumentException e) {
            throw new InvalidJwtAuthenticationException("Expired or invalid JWT token");
        }
    }

    private Claims getClaimsBody(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
