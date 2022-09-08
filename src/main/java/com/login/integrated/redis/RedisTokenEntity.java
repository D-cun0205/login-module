package com.login.integrated.redis;

import lombok.Getter;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.TimeToLive;

import javax.persistence.Id;
import java.io.Serializable;
import java.util.concurrent.TimeUnit;

@Getter
@RedisHash("redisTokenEntity")
public class RedisTokenEntity implements Serializable {

    @Id
    private final String id;
    private final String refreshToken;
    @TimeToLive(unit = TimeUnit.MILLISECONDS)
    private final Long expiration;

    public RedisTokenEntity(String id, String refreshToken, Long expiration) {
        this.id = id;
        this.refreshToken = refreshToken;
        this.expiration = expiration;
    }
}