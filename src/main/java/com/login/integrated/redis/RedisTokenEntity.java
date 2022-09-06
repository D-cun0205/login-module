package com.login.integrated.redis;

import lombok.Builder;
import lombok.Getter;
import org.springframework.data.redis.core.RedisHash;

import javax.persistence.Id;
import java.io.Serializable;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

@Getter
@RedisHash("redisTokenEntity")
public class RedisTokenEntity implements Serializable {

    @Id
    private final String id;
    private final String refreshToken;
    private final Date refreshExpiration;

    @Builder
    public RedisTokenEntity(String id, String refreshToken, Date refreshExpiration) {
        Set<String> set = new HashSet<>();
        this.id = id;
        this.refreshToken = refreshToken;
        this.refreshExpiration = refreshExpiration;
    }
}
