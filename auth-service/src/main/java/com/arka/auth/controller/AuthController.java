package com.arka.auth.controller;

import com.arka.auth.service.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

  private final AuthService authService;

  public AuthController(AuthService authService) {
    this.authService = authService;
  }

  @PostMapping("/login")
  public ResponseEntity<Map<String, String>> login(@RequestBody Map<String, String> credentials) {
    try {
      String username = credentials.get("username");
      String password = credentials.get("password");
      Map<String, String> response = authService.login(username, password);
      return ResponseEntity.ok(response);
    } catch (Exception e) {
      Map<String, String> error = new HashMap<>();
      error.put("error", e.getMessage());
      return ResponseEntity.status(401).body(error);
    }
  }

  @PostMapping("/register")
  public ResponseEntity<Map<String, String>> register(@RequestBody Map<String, String> userDto) {
    try {
      String username = userDto.get("username");
      String email = userDto.get("email");
      String password = userDto.get("password");
      Map<String, String> response = authService.register(username, email, password);
      return ResponseEntity.status(201).body(response);
    } catch (Exception e) {
      Map<String, String> error = new HashMap<>();
      error.put("error", e.getMessage());
      return ResponseEntity.status(400).body(error);
    }
  }

  @PostMapping("/validate")
  public ResponseEntity<Map<String, Boolean>> validateToken(@RequestHeader("Authorization") String token) {
    String jwtToken = token.replace("Bearer ", "");
    boolean isValid = authService.validateToken(jwtToken);
    Map<String, Boolean> response = new HashMap<>();
    response.put("valid", isValid);
    return ResponseEntity.ok(response);
  }
}
