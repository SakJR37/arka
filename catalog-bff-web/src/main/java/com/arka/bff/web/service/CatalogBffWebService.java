package com.arka.bff.web.service;

import com.arka.bff.web.client.CatalogClient;
import com.arka.bff.web.client.ReviewClient;
import com.arka.bff.web.client.InventoryClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import java.util.*;

@Service
public class CatalogBffWebService {
  private static final Logger log = LoggerFactory.getLogger(CatalogBffWebService.class);

  private final CatalogClient catalogClient;
  private final ReviewClient reviewClient;
  private final InventoryClient inventoryClient;

  public CatalogBffWebService(CatalogClient catalogClient, ReviewClient reviewClient, InventoryClient inventoryClient) {
    this.catalogClient = catalogClient;
    this.reviewClient = reviewClient;
    this.inventoryClient = inventoryClient;
  }
  
  public Map<String, Object> aggregateCatalogData() {
    Map<String, Object> result = new HashMap<>();
    
    try {
      List<Map<String, Object>> products = catalogClient.getAllProducts();
      result.put("products", products);
      result.put("totalCount", products.size());
      result.put("message", "Web BFF - Catalog aggregation complete");
      log.info("Aggregated {} products from catalog-service", products.size());
    } catch (Exception e) {
      log.error("Error aggregating catalog data: {}", e.getMessage());
      result.put("error", "Failed to aggregate catalog data");
      result.put("products", Collections.emptyList());
    }
    
    return result;
  }

  public Map<String, Object> aggregateProductDetails(Long productId) {
    Map<String, Object> result = new HashMap<>();
    
    try {
      // Fetch product details from catalog-service
      Map<String, Object> product = catalogClient.getProductById(productId);
      
      // Fetch reviews from review-service
      List<Map<String, Object>> reviews = reviewClient.getReviewsByProduct(productId);
      
      // Fetch stock from inventory-service
      Map<String, Object> stock = inventoryClient.getProductStock(productId);
      
      result.put("product", product);
      result.put("reviews", reviews);
      result.put("stock", stock);
      result.put("averageRating", calculateAverageRating(reviews));
      result.put("message", "Web BFF - Product details aggregated successfully");
      
      log.info("Aggregated details for product {}: {} reviews, stock available", productId, reviews.size());
    } catch (Exception e) {
      log.error("Error aggregating product details for {}: {}", productId, e.getMessage());
      result.put("error", "Failed to aggregate product details");
    }
    
    return result;
  }

  private double calculateAverageRating(List<Map<String, Object>> reviews) {
    if (reviews == null || reviews.isEmpty()) {
      return 0.0;
    }
    
    double sum = reviews.stream()
        .mapToDouble(r -> ((Number) r.getOrDefault("rating", 0)).doubleValue())
        .sum();
    
    return sum / reviews.size();
  }
}
