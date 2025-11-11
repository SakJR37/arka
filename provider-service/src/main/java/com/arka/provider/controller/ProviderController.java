package com.arka.provider.controller;

import com.arka.provider.model.Provider;
import com.arka.provider.service.ProviderService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/api/providers")
public class ProviderController {
  private final ProviderService providerService;

  public ProviderController(ProviderService providerService) {
    this.providerService = providerService;
  }

  @PostMapping
  public ResponseEntity<Provider> create(@RequestBody Provider provider) {
    Provider created = providerService.create(provider);
    return ResponseEntity.status(201).body(created);
  }

  @PutMapping("/{id}")
  public ResponseEntity<Provider> update(@PathVariable Long id, @RequestBody Provider provider) {
    try {
      Provider updated = providerService.update(id, provider);
      return ResponseEntity.ok(updated);
    } catch (IllegalArgumentException ex) {
      return ResponseEntity.notFound().build();
    }
  }

  @GetMapping
  public List<Provider> listAll(@RequestParam(required = false) Boolean active) {
    if (Boolean.TRUE.equals(active)) {
      return providerService.findActive();
    }
    return providerService.findAll();
  }

  @GetMapping("/{id}")
  public ResponseEntity<Provider> get(@PathVariable Long id) {
    return providerService.findById(id)
      .map(ResponseEntity::ok)
      .orElse(ResponseEntity.notFound().build());
  }
}
