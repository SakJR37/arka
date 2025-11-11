package com.arka.bff.web.client;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

@FeignClient(name = "inventory-service")
public interface InventoryClient {
  @GetMapping("/api/products/{id}")
  Map<String, Object> getProductStock(@PathVariable("id") Long id);
}
