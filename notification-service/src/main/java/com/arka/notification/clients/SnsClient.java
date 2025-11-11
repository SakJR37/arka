package com.arka.notification.clients;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sns.SnsClient;
import software.amazon.awssdk.services.sns.model.*;

import java.util.Map;

@Component
public class SnsPublisher {

  private final SnsClient snsClient;

  @Value("${aws.sns.order-created-topic}")
  private String orderCreatedTopicArn;

  @Value("${aws.sns.inventory-reserved-topic}")
  private String inventoryReservedTopicArn;

  @Value("${aws.sns.low-stock-alert-topic}")
  private String lowStockAlertTopicArn;

  public SnsPublisher(@Value("${aws.region}") String region) {
    this.snsClient = SnsClient.builder()
        .region(Region.of(region))
        .build();
  }

  public void publishToOrderCreated(String message) {
    publishMessage(orderCreatedTopicArn, message, "OrderCreated");
  }

  public void publishToInventoryReserved(String message) {
    publishMessage(inventoryReservedTopicArn, message, "InventoryReserved");
  }

  public void publishToLowStockAlert(String message) {
    publishMessage(lowStockAlertTopicArn, message, "LowStockAlert");
  }

  public void publishMessage(String topicArn, String message, String subject) {
    try {
      PublishRequest request = PublishRequest.builder()
          .topicArn(topicArn)
          .message(message)
          .subject(subject)
          .build();

      PublishResponse response = snsClient.publish(request);
      System.out.println("SNS Message published! Message ID: " + response.messageId());

    } catch (SnsException e) {
      System.err.println("SNS Error: " + e.awsErrorDetails().errorMessage());
      throw new RuntimeException("Failed to publish SNS message", e);
    }
  }

  public void publishMessageWithAttributes(String topicArn, String message, Map<String, String> attributes) {
    try {
      PublishRequest.Builder requestBuilder = PublishRequest.builder()
          .topicArn(topicArn)
          .message(message);

      if (attributes != null && !attributes.isEmpty()) {
        attributes.forEach((key, value) -> 
          requestBuilder.messageAttributes(key, 
            MessageAttributeValue.builder()
              .dataType("String")
              .stringValue(value)
              .build())
        );
      }

      PublishResponse response = snsClient.publish(requestBuilder.build());
      System.out.println("SNS Message with attributes published! Message ID: " + response.messageId());

    } catch (SnsException e) {
      System.err.println("SNS Error: " + e.awsErrorDetails().errorMessage());
      throw new RuntimeException("Failed to publish SNS message with attributes", e);
    }
  }
}
