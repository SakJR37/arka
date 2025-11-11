package com.arka.auth.service;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;

@Service
public class JwtService {
  private static final Logger log = LoggerFactory.getLogger(JwtService.class);

  @Value("${jwt.secret:arkaSecretKeyForJWTTokenGenerationWithMinimum256BitsRequired}")
  private String secretKey;

  @Value("${jwt.expiration:86400000}") // 24 hours default
  private long jwtExpiration;

  public String generateToken(String username, Map<String, Object> claims) {
    Date now = new Date();
    Date expiryDate = new Date(now.getTime() + jwtExpiration);

    SecretKey key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));

    return Jwts.builder()
        .setSubject(username)
        .addClaims(claims)
        .setIssuedAt(now)
        .setExpiration(expiryDate)
        .signWith(key, SignatureAlgorithm.HS256)
        .compact();
  }

  public Claims validateToken(String token) {
    try {
      SecretKey key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
      
      return Jwts.parserBuilder()
          .setSigningKey(key)
          .build()
          .parseClaimsJws(token)
          .getBody();
    } catch (JwtException e) {
      log.error("Invalid JWT token: {}", e.getMessage());
      throw new RuntimeException("Invalid token");
    }
  }

  public String getUsernameFromToken(String token) {
    return validateToken(token).getSubject();
  }

  public boolean isTokenExpired(String token) {
    try {
      Date expiration = validateToken(token).getExpiration();
      return expiration.before(new Date());
    } catch (Exception e) {
      return true;
    }
  }
}
