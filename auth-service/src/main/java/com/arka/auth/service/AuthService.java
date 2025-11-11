package com.arka.auth.service;

import com.arka.auth.model.User;
import com.arka.auth.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Service
public class AuthService {
  private static final Logger log = LoggerFactory.getLogger(AuthService.class);

  private final UserRepository userRepository;
  private final JwtService jwtService;
  private final BCryptPasswordEncoder passwordEncoder;

  public AuthService(UserRepository userRepository, JwtService jwtService) {
    this.userRepository = userRepository;
    this.jwtService = jwtService;
    this.passwordEncoder = new BCryptPasswordEncoder();
  }

  public Map<String, String> register(String username, String email, String password) {
    Map<String, String> response = new HashMap<>();

    if (userRepository.existsByUsername(username)) {
      throw new RuntimeException("Username already exists");
    }

    if (userRepository.existsByEmail(email)) {
      throw new RuntimeException("Email already exists");
    }

    User user = new User();
    user.setUsername(username);
    user.setEmail(email);
    user.setPassword(passwordEncoder.encode(password));

    userRepository.save(user);
    log.info("User registered successfully: {}", username);

    response.put("message", "User registered successfully");
    response.put("username", username);
    return response;
  }

  public Map<String, String> login(String username, String password) {
    Optional<User> userOpt = userRepository.findByUsername(username);

    if (userOpt.isEmpty()) {
      throw new RuntimeException("Invalid credentials");
    }

    User user = userOpt.get();
    if (!passwordEncoder.matches(password, user.getPassword())) {
      throw new RuntimeException("Invalid credentials");
    }

    Map<String, Object> claims = new HashMap<>();
    claims.put("email", user.getEmail());
    claims.put("userId", user.getId());

    String token = jwtService.generateToken(username, claims);
    log.info("User logged in successfully: {}", username);

    Map<String, String> response = new HashMap<>();
    response.put("token", token);
    response.put("message", "Login successful");
    response.put("username", username);
    return response;
  }

  public boolean validateToken(String token) {
    try {
      jwtService.validateToken(token);
      return !jwtService.isTokenExpired(token);
    } catch (Exception e) {
      log.error("Token validation failed: {}", e.getMessage());
      return false;
    }
  }
}
