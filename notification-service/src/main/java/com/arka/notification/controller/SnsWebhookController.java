package com.arka.notification.controller;

import com.arka.notification.service.NotificationService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/sns")
public class SnsWebhookController {
  private static final Logger log = LoggerFactory.getLogger(SnsWebhookController.class);
  
  private final NotificationService notificationService;
  private final ObjectMapper objectMapper;

  public SnsWebhookController(NotificationService notificationService) {
    this.notificationService = notificationService;
    this.objectMapper = new ObjectMapper();
  }

  @PostMapping("/webhook")
  public ResponseEntity<String> handleSnsNotification(@RequestBody String payload,
                                                       @RequestHeader(value = "x-amz-sns-message-type", required = false) String messageType) {
    try {
      log.info("Received SNS notification: {}", payload);

      JsonNode jsonNode = objectMapper.readTree(payload);

      // Handle subscription confirmation
      if ("SubscriptionConfirmation".equals(messageType)) {
        String subscribeUrl = jsonNode.get("SubscribeURL").asText();
        log.info("SNS Subscription confirmation URL: {}", subscribeUrl);
        // In production, you would call this URL to confirm subscription
        return ResponseEntity.ok("Subscription pending confirmation");
      }

      // Handle notification
      if ("Notification".equals(messageType)) {
        String message = jsonNode.get("Message").asText();
        JsonNode messageData = objectMapper.readTree(message);

        String type = messageData.get("type").asText();
        
        if ("ABANDONED_CART".equals(type)) {
          String userId = messageData.get("userId").asText();
          String cartId = messageData.get("cartId").asText();
          
          log.info("Processing abandoned cart notification: userId={}, cartId={}", userId, cartId);
          
          // Send reminder email
          notificationService.sendEmail(
              "user" + userId + "@example.com", // In production, fetch real email from user service
              "Abandoned Cart Reminder",
              "You have items in your cart waiting for you! CartID: " + cartId
          );
        }

        return ResponseEntity.ok("Notification processed");
      }

      return ResponseEntity.ok("Unknown message type");

    } catch (Exception e) {
      log.error("Error processing SNS notification: {}", e.getMessage(), e);
      return ResponseEntity.status(500).body("Error processing notification");
    }
  }
}
