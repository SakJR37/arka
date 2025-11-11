package com.arka.catalog.controller;

import com.arka.catalog.model.ProductCatalog;
import com.arka.catalog.service.CatalogService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/api/catalog")
public class CatalogController {
  private final CatalogService catalogService;

  public CatalogController(CatalogService catalogService) {
    this.catalogService = catalogService;
  }

  @PostMapping
  public ResponseEntity<ProductCatalog> create(@RequestBody ProductCatalog catalog) {
    ProductCatalog created = catalogService.createOrUpdate(catalog);
    return ResponseEntity.status(201).body(created);
  }

  @GetMapping
  public List<ProductCatalog> listAll(@RequestParam(required = false) Boolean active) {
    if (Boolean.TRUE.equals(active)) {
      return catalogService.findActive();
    }
    return catalogService.findAll();
  }

  @GetMapping("/{id}")
  public ResponseEntity<ProductCatalog> get(@PathVariable Long id) {
    return catalogService.findById(id)
      .map(ResponseEntity::ok)
      .orElse(ResponseEntity.notFound().build());
  }

  @GetMapping("/category/{category}")
  public List<ProductCatalog> getByCategory(@PathVariable String category) {
    return catalogService.findByCategory(category);
  }

  @DeleteMapping("/{id}")
  public ResponseEntity<Void> deactivate(@PathVariable Long id) {
    catalogService.deactivate(id);
    return ResponseEntity.noContent().build();
  }
}
