package com.arka.cart.controller;

import com.arka.cart.model.Cart;
import com.arka.cart.service.AbandonedCartService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/carts/abandoned")
public class AbandonedCartController {
  private final AbandonedCartService abandonedCartService;

  public AbandonedCartController(AbandonedCartService abandonedCartService) {
    this.abandonedCartService = abandonedCartService;
  }

  @GetMapping
  public ResponseEntity<List<Cart>> getAbandonedCarts(@RequestParam(defaultValue = "7") int daysThreshold) {
    List<Cart> abandonedCarts = abandonedCartService.findAbandonedCarts(daysThreshold);
    return ResponseEntity.ok(abandonedCarts);
  }

  @PostMapping("/{cartId}/remind")
  public ResponseEntity<Map<String, String>> sendReminder(@PathVariable Long cartId) {
    abandonedCartService.sendReminderEmail(cartId);
    return ResponseEntity.ok(Map.of("message", "Reminder sent successfully", "cartId", cartId.toString()));
  }

  @GetMapping("/stats")
  public ResponseEntity<Map<String, Object>> getAbandonedCartStats(@RequestParam(defaultValue = "7") int daysThreshold) {
    Map<String, Object> stats = abandonedCartService.getAbandonedCartStats(daysThreshold);
    return ResponseEntity.ok(stats);
  }
}
