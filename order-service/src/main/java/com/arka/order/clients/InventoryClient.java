package com.arka.order.clients;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.*;
@FeignClient(name = "inventory-service")
public interface InventoryClient {
  @PutMapping("/api/products/{id}/stock")
  void updateStock(@PathVariable("id") Long id, @RequestParam("delta") int delta, @RequestParam(value="reason", required=false) String reason);
}
