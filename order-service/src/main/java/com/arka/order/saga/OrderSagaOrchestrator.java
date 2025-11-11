package com.arka.order.saga;

import com.arka.order.clients.InventoryClient;
import com.arka.order.clients.NotificationClient;
import com.arka.order.model.Order;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import java.util.HashMap;
import java.util.Map;

@Component
public class OrderSagaOrchestrator {
  private static final Logger log = LoggerFactory.getLogger(OrderSagaOrchestrator.class);
  
  private final InventoryClient inventoryClient;
  private final NotificationClient notificationClient;

  public OrderSagaOrchestrator(InventoryClient inventoryClient, NotificationClient notificationClient) {
    this.inventoryClient = inventoryClient;
    this.notificationClient = notificationClient;
  }

  public void executeOrderSaga(Order order) {
    log.info("Starting Order Saga for order: {}", order.getId());
    
    try {
      // Step 1: Reserve inventory
      order.getItems().forEach(item -> {
        inventoryClient.updateStock(item.getProductId(), -item.getQuantity(), "ORDER_RESERVE");
      });
      
      // Step 2: Process payment (placeholder)
      log.info("Payment processed for order: {}", order.getId());
      
      // Step 3: Send notification
      Map<String, Object> notification = new HashMap<>();
      notification.put("type", "EMAIL");
      notification.put("email", order.getCustomerEmail());
      notification.put("subject", "Order Confirmation");
      notification.put("body", "Your order #" + order.getId() + " has been confirmed");
      notificationClient.send(notification);
      
      log.info("Order Saga completed successfully for order: {}", order.getId());
      
    } catch (Exception ex) {
      log.error("Order Saga failed for order: {}. Initiating compensating transaction", order.getId());
      compensate(order);
      throw new RuntimeException("Order Saga failed: " + ex.getMessage(), ex);
    }
  }

  private void compensate(Order order) {
    // Rollback inventory reservation
    order.getItems().forEach(item -> {
      try {
        inventoryClient.updateStock(item.getProductId(), item.getQuantity(), "ORDER_ROLLBACK");
      } catch (Exception ex) {
        log.error("Failed to compensate inventory for product: {}", item.getProductId());
      }
    });
  }
}
