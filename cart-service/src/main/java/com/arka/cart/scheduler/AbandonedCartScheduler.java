package com.arka.cart.scheduler;

import com.arka.cart.model.Cart;
import com.arka.cart.repository.CartRepository;
import com.arka.cart.service.SqsPublisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
public class AbandonedCartScheduler {
  private static final Logger log = LoggerFactory.getLogger(AbandonedCartScheduler.class);
  private final CartRepository cartRepository;
  private final SqsPublisher sqsPublisher;

  public AbandonedCartScheduler(CartRepository cartRepository, SqsPublisher sqsPublisher) {
    this.cartRepository = cartRepository;
    this.sqsPublisher = sqsPublisher;
  }

  @Scheduled(cron = "0 0 2 * * ?") // Daily at 2 AM
  public void detectAbandonedCarts() {
    Instant threshold = Instant.now().minus(7, ChronoUnit.DAYS);
    List<Cart> abandonedCarts = cartRepository.findByUpdatedAtBefore(threshold);
    
    log.info("Found {} abandoned carts", abandonedCarts.size());
    
    abandonedCarts.forEach(cart -> {
      log.info("Abandoned cart detected: userId={}, items={}", 
        cart.getUserId(), cart.getItems().size());
      
      try {
        // Calculate total value
        double totalValue = cart.getItems().stream()
            .mapToDouble(item -> item.getPrice() * item.getQuantity())
            .sum();

        // Prepare cart data for SQS
        Map<String, Object> cartData = new HashMap<>();
        cartData.put("cartId", cart.getId());
        cartData.put("userId", cart.getUserId());
        cartData.put("items", cart.getItems().size());
        cartData.put("totalValue", totalValue);
        cartData.put("abandonedAt", Instant.now().toString());

        // Publish to SQS queue for Lambda processing
        sqsPublisher.publishAbandonedCart(cartData);
        log.info("Published abandoned cart to SQS: cartId={}", cart.getId());
        
      } catch (Exception e) {
        log.error("Failed to publish abandoned cart {}: {}", cart.getId(), e.getMessage());
      }
    });
  }
}
