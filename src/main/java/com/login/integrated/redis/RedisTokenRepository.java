package com.login.integrated.redis;

import org.springframework.data.repository.CrudRepository;

public interface RedisTokenRepository extends CrudRepository<RedisTokenEntity, String> { }
