package com.arka.inventory.controller;

import com.arka.inventory.model.Product;
import com.arka.inventory.dto.ProductRequest;
import com.arka.inventory.service.ProductService;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import jakarta.validation.Valid;
import java.net.URI;
import java.util.List;

@RestController
@RequestMapping("/api/products")
@Validated
public class ProductController {
  private final ProductService productService;
  public ProductController(ProductService productService){ this.productService = productService; }

  @PostMapping
  public ResponseEntity<Product> create(@Valid @RequestBody ProductRequest req){
    Product p = new Product();
    p.setName(req.getName());
    p.setDescription(req.getDescription());
    p.setPrice(req.getPrice());
    p.setStock(req.getStock());
    p.setCategory(req.getCategory());

    Product created = productService.create(p);
    return ResponseEntity.created(URI.create("/api/products/" + created.getId())).body(created);
  }

  @GetMapping
  public List<Product> list(){ return productService.listAll(); }

  @GetMapping("/{id}")
  public ResponseEntity<Product> get(@PathVariable Long id){
    return productService.findById(id)
      .map(ResponseEntity::ok)
      .orElse(ResponseEntity.notFound().build());
  }

  @PutMapping("/{id}/stock")
  public ResponseEntity<?> updateStock(@PathVariable Long id, @RequestParam int delta, @RequestParam(required=false) String reason){
    try{
      Product updated = productService.updateStock(id, delta, reason == null ? "manual" : reason);
      return ResponseEntity.ok(updated);
    }catch(IllegalArgumentException ex){
      return ResponseEntity.badRequest().body(ex.getMessage());
    }catch(Exception ex){
      return ResponseEntity.status(500).body("Error updating stock: " + ex.getMessage());
    }
  }

  @GetMapping("/low-stock")
  public List<Product> lowStock(@RequestParam(defaultValue = "10") Integer threshold){
    return productService.lowStock(threshold);
  }
}