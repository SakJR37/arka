package com.arka.shipping.controller;

import com.arka.shipping.model.ShippingOption;
import com.arka.shipping.service.ShippingService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/api/shipping")
public class ShippingController {
  private final ShippingService shippingService;

  public ShippingController(ShippingService shippingService) {
    this.shippingService = shippingService;
  }

  @GetMapping("/options")
  public List<ShippingOption> getOptions(@RequestParam(required = false) Boolean active) {
    if (Boolean.TRUE.equals(active)) {
      return shippingService.findActive();
    }
    return shippingService.findAll();
  }

  @GetMapping("/options/{id}")
  public ResponseEntity<ShippingOption> getOption(@PathVariable Long id) {
    return shippingService.findById(id)
      .map(ResponseEntity::ok)
      .orElse(ResponseEntity.notFound().build());
  }
}
