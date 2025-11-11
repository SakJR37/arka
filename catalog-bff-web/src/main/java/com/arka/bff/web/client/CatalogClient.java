package com.arka.bff.web.client;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.*;
import java.util.List;
import java.util.Map;

@FeignClient(name = "catalog-service")
public interface CatalogClient {
  @GetMapping("/api/catalog")
  List<Map<String, Object>> getAllProducts();

  @GetMapping("/api/catalog/{id}")
  Map<String, Object> getProductById(@PathVariable("id") Long id);
}
