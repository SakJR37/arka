package com.arka.cart.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.model.SendMessageRequest;
import software.amazon.awssdk.services.sqs.model.SendMessageResponse;

import java.util.Map;

@Service
public class SqsPublisher {
  private static final Logger log = LoggerFactory.getLogger(SqsPublisher.class);
  
  private final SqsClient sqsClient;
  private final ObjectMapper objectMapper;

  @Value("${aws.sqs.abandoned-carts-queue-url:}")
  private String queueUrl;

  public SqsPublisher(@Value("${aws.region:us-east-1}") String region) {
    this.sqsClient = SqsClient.builder()
        .region(Region.of(region))
        .build();
    this.objectMapper = new ObjectMapper();
  }

  public void publishAbandonedCart(Map<String, Object> cartData) {
    try {
      String messageBody = objectMapper.writeValueAsString(cartData);
      
      SendMessageRequest request = SendMessageRequest.builder()
          .queueUrl(queueUrl)
          .messageBody(messageBody)
          .build();

      SendMessageResponse response = sqsClient.sendMessage(request);
      log.info("Published abandoned cart to SQS. MessageId: {}", response.messageId());
      
    } catch (Exception e) {
      log.error("Failed to publish abandoned cart to SQS: {}", e.getMessage(), e);
    }
  }
}
