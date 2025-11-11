package com.arka.category.controller;

import com.arka.category.model.Category;
import com.arka.category.service.CategoryService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/api/categories")
public class CategoryController {
  private final CategoryService categoryService;

  public CategoryController(CategoryService categoryService) {
    this.categoryService = categoryService;
  }

  @PostMapping
  public ResponseEntity<Category> create(@RequestBody Category category) {
    try {
      Category created = categoryService.create(category);
      return ResponseEntity.status(201).body(created);
    } catch (IllegalArgumentException ex) {
      return ResponseEntity.badRequest().build();
    }
  }

  @PutMapping("/{id}")
  public ResponseEntity<Category> update(@PathVariable Long id, @RequestBody Category category) {
    try {
      Category updated = categoryService.update(id, category);
      return ResponseEntity.ok(updated);
    } catch (IllegalArgumentException ex) {
      return ResponseEntity.notFound().build();
    }
  }

  @GetMapping
  public List<Category> listAll(@RequestParam(required = false) Boolean active) {
    if (Boolean.TRUE.equals(active)) {
      return categoryService.findActive();
    }
    return categoryService.findAll();
  }

  @GetMapping("/{id}")
  public ResponseEntity<Category> get(@PathVariable Long id) {
    return categoryService.findById(id)
      .map(ResponseEntity::ok)
      .orElse(ResponseEntity.notFound().build());
  }

  @DeleteMapping("/{id}")
  public ResponseEntity<Void> delete(@PathVariable Long id) {
    categoryService.delete(id);
    return ResponseEntity.noContent().build();
  }
}
