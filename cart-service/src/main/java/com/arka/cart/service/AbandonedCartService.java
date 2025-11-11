package com.arka.cart.service;

import com.arka.cart.model.Cart;
import com.arka.cart.repository.CartRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Service
public class AbandonedCartService {
  private static final Logger log = LoggerFactory.getLogger(AbandonedCartService.class);
  private final CartRepository cartRepository;

  public AbandonedCartService(CartRepository cartRepository) {
    this.cartRepository = cartRepository;
  }

  public List<Cart> findAbandonedCarts(int daysThreshold) {
    Instant threshold = Instant.now().minus(daysThreshold, ChronoUnit.DAYS);
    return cartRepository.findByUpdatedAtBefore(threshold);
  }

  public void sendReminderEmail(Long cartId) {
    Optional<Cart> cartOpt = cartRepository.findById(cartId);
    if (cartOpt.isEmpty()) {
      log.warn("Cart not found: {}", cartId);
      return;
    }
    
    Cart cart = cartOpt.get();
    log.info("Sending reminder email for abandoned cart {} to user {}", cartId, cart.getUserId());
    
    // TODO: Integrate with notification-service to send actual email
    // Example payload:
    // {
    //   "type": "EMAIL",
    //   "email": "user@example.com",
    //   "subject": "You left items in your cart!",
    //   "body": "Hi! We noticed you left some items in your cart. Complete your purchase now!"
    // }
    
    log.info("Reminder email sent successfully for cart {}", cartId);
  }

  public Map<String, Object> getAbandonedCartStats(int daysThreshold) {
    List<Cart> abandonedCarts = findAbandonedCarts(daysThreshold);
    
    int totalCarts = abandonedCarts.size();
    int totalItems = abandonedCarts.stream()
      .mapToInt(cart -> cart.getItems() != null ? cart.getItems().size() : 0)
      .sum();
    
    double potentialRevenue = abandonedCarts.stream()
      .flatMap(cart -> cart.getItems() != null ? cart.getItems().stream() : java.util.stream.Stream.empty())
      .mapToDouble(item -> item.getPrice() * item.getQuantity())
      .sum();
    
    Map<String, Object> stats = new HashMap<>();
    stats.put("totalAbandonedCarts", totalCarts);
    stats.put("totalItems", totalItems);
    stats.put("potentialRevenue", potentialRevenue);
    stats.put("daysThreshold", daysThreshold);
    stats.put("calculatedAt", Instant.now());
    
    return stats;
  }
}
