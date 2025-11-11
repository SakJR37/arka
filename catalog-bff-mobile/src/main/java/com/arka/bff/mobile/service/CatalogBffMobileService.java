package com.arka.bff.mobile.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.client.discovery.DiscoveryClient;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import java.util.*;

@Service
public class CatalogBffMobileService {
  private static final Logger log = LoggerFactory.getLogger(CatalogBffMobileService.class);

  private final RestTemplate restTemplate;
  private final DiscoveryClient discoveryClient;

  public CatalogBffMobileService(RestTemplate restTemplate, DiscoveryClient discoveryClient) {
    this.restTemplate = restTemplate;
    this.discoveryClient = discoveryClient;
  }
  
  public Map<String, Object> aggregateCatalogData() {
    Map<String, Object> result = new HashMap<>();
    
    try {
      // Fetch lightweight product list for mobile (only essential fields)
      String catalogUrl = "http://catalog-service/api/catalog";
      List<Map<String, Object>> products = restTemplate.getForObject(catalogUrl, List.class);
      
      // Optimize for mobile: return only essential fields
      List<Map<String, Object>> optimizedProducts = new ArrayList<>();
      if (products != null) {
        for (Map<String, Object> product : products) {
          Map<String, Object> optimized = new HashMap<>();
          optimized.put("id", product.get("id"));
          optimized.put("name", product.get("name"));
          optimized.put("price", product.get("price"));
          optimized.put("imageUrl", product.get("imageUrl"));
          optimized.put("rating", product.get("rating"));
          optimizedProducts.add(optimized);
        }
      }
      
      result.put("products", optimizedProducts);
      result.put("count", optimizedProducts.size());
      result.put("message", "Mobile BFF - Lightweight catalog data");
      log.info("Aggregated {} optimized products for mobile", optimizedProducts.size());
    } catch (Exception e) {
      log.error("Error aggregating mobile catalog data: {}", e.getMessage());
      result.put("error", "Failed to load catalog");
      result.put("products", Collections.emptyList());
    }
    
    return result;
  }

  public Map<String, Object> aggregateProductDetails(Long productId) {
    Map<String, Object> result = new HashMap<>();
    
    try {
      // Fetch essential product details for mobile
      String productUrl = "http://catalog-service/api/catalog/" + productId;
      Map<String, Object> product = restTemplate.getForObject(productUrl, Map.class);
      
      // Fetch only top 3 reviews for mobile
      String reviewsUrl = "http://review-service/api/reviews/product/" + productId;
      List<Map<String, Object>> allReviews = restTemplate.getForObject(reviewsUrl, List.class);
      List<Map<String, Object>> topReviews = allReviews != null && allReviews.size() > 3 
          ? allReviews.subList(0, 3) 
          : allReviews;
      
      // Optimize for mobile bandwidth
      Map<String, Object> optimizedProduct = new HashMap<>();
      if (product != null) {
        optimizedProduct.put("id", product.get("id"));
        optimizedProduct.put("name", product.get("name"));
        optimizedProduct.put("price", product.get("price"));
        optimizedProduct.put("description", product.get("description"));
        optimizedProduct.put("imageUrl", product.get("imageUrl"));
      }
      
      result.put("product", optimizedProduct);
      result.put("topReviews", topReviews);
      result.put("reviewCount", allReviews != null ? allReviews.size() : 0);
      result.put("message", "Mobile BFF - Optimized product details");
      
      log.info("Aggregated optimized details for product {} (mobile)", productId);
    } catch (Exception e) {
      log.error("Error aggregating mobile product details for {}: {}", productId, e.getMessage());
      result.put("error", "Failed to load product details");
    }
    
    return result;
  }
}
