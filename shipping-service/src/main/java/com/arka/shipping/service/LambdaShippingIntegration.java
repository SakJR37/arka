package com.arka.shipping.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.lambda.LambdaClient;
import software.amazon.awssdk.services.lambda.model.InvokeRequest;
import software.amazon.awssdk.services.lambda.model.InvokeResponse;

import java.util.HashMap;
import java.util.Map;

@Service
public class LambdaShippingIntegration {

  private final LambdaClient lambdaClient;
  private final ObjectMapper objectMapper;

  @Value("${aws.lambda.pickup-calculator:arka-shipping-pickup}")
  private String pickupCalculatorFunction;

  @Value("${aws.lambda.delivery-calculator:arka-shipping-delivery}")
  private String deliveryCalculatorFunction;

  @Value("${aws.lambda.express-calculator:arka-shipping-express}")
  private String expressCalculatorFunction;

  public LambdaShippingIntegration(@Value("${aws.region}") String region) {
    this.lambdaClient = LambdaClient.builder()
        .region(Region.of(region))
        .build();
    this.objectMapper = new ObjectMapper();
  }

  public Map<String, Object> calculatePickupTime(String origin, String destination) {
    Map<String, String> payload = new HashMap<>();
    payload.put("type", "pickup");
    payload.put("origin", origin);
    payload.put("destination", destination);
    
    return invokeLambda(pickupCalculatorFunction, payload);
  }

  public Map<String, Object> calculateDeliveryTime(String origin, String destination, int weight) {
    Map<String, Object> payload = new HashMap<>();
    payload.put("type", "delivery");
    payload.put("origin", origin);
    payload.put("destination", destination);
    payload.put("weight", weight);
    
    return invokeLambda(deliveryCalculatorFunction, payload);
  }

  public Map<String, Object> calculateExpressTime(String origin, String destination, int priority) {
    Map<String, Object> payload = new HashMap<>();
    payload.put("type", "express");
    payload.put("origin", origin);
    payload.put("destination", destination);
    payload.put("priority", priority);
    
    return invokeLambda(expressCalculatorFunction, payload);
  }

  private Map<String, Object> invokeLambda(String functionName, Object payload) {
    try {
      String jsonPayload = objectMapper.writeValueAsString(payload);
      
      InvokeRequest request = InvokeRequest.builder()
          .functionName(functionName)
          .payload(SdkBytes.fromUtf8String(jsonPayload))
          .build();

      InvokeResponse response = lambdaClient.invoke(request);
      
      String responsePayload = response.payload().asUtf8String();
      return objectMapper.readValue(responsePayload, Map.class);

    } catch (Exception e) {
      System.err.println("Lambda invocation error: " + e.getMessage());
      Map<String, Object> errorResponse = new HashMap<>();
      errorResponse.put("error", true);
      errorResponse.put("message", "Failed to calculate shipping time: " + e.getMessage());
      return errorResponse;
    }
  }

  public Map<String, Object> calculateAllShippingOptions(String origin, String destination, int weight) {
    Map<String, Object> result = new HashMap<>();
    
    try {
      result.put("pickup", calculatePickupTime(origin, destination));
      result.put("delivery", calculateDeliveryTime(origin, destination, weight));
      result.put("express", calculateExpressTime(origin, destination, 1));
    } catch (Exception e) {
      result.put("error", true);
      result.put("message", "Error calculating shipping options: " + e.getMessage());
    }
    
    return result;
  }
}
