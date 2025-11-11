package com.arka.order.service;

import com.arka.order.clients.NotificationClient;
import com.arka.order.model.Order;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class OrderNotificationService {
  private static final Logger log = LoggerFactory.getLogger(OrderNotificationService.class);
  private final NotificationClient notificationClient;

  public OrderNotificationService(NotificationClient notificationClient) {
    this.notificationClient = notificationClient;
  }

  public void notifyOrderStatusChange(Order order, String newStatus) {
    log.info("Sending notification for order {} status change to: {}", order.getId(), newStatus);
    
    String subject = getSubjectForStatus(newStatus);
    String body = getBodyForStatus(order, newStatus);
    
    Map<String, Object> payload = Map.of(
      "type", "EMAIL",
      "email", order.getCustomerEmail(),
      "subject", subject,
      "body", body
    );
    
    try {
      notificationClient.send(payload);
      log.info("Notification sent successfully for order {}", order.getId());
    } catch (Exception e) {
      log.error("Failed to send notification for order {}: {}", order.getId(), e.getMessage());
    }
  }

  private String getSubjectForStatus(String status) {
    return switch (status.toUpperCase()) {
      case "PENDING" -> "Order Received - Pending Confirmation";
      case "CONFIRMED" -> "Order Confirmed";
      case "IN_TRANSIT" -> "Order Shipped - In Transit";
      case "DELIVERED" -> "Order Delivered";
      case "CANCELLED" -> "Order Cancelled";
      default -> "Order Status Update";
    };
  }

  private String getBodyForStatus(Order order, String status) {
    String baseMsg = "Hello,\n\nYour order #" + order.getId() + " ";
    return switch (status.toUpperCase()) {
      case "PENDING" -> baseMsg + "has been received and is pending confirmation.\n\nTotal: $" + order.getTotal();
      case "CONFIRMED" -> baseMsg + "has been confirmed and is being prepared for shipment.\n\nTotal: $" + order.getTotal();
      case "IN_TRANSIT" -> baseMsg + "has been shipped and is on its way to you!";
      case "DELIVERED" -> baseMsg + "has been delivered. Thank you for your purchase!";
      case "CANCELLED" -> baseMsg + "has been cancelled.";
      default -> baseMsg + "status has been updated to: " + status;
    };
  }
}
