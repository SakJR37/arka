package com.arka.bff.web.client;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.*;
import java.util.List;
import java.util.Map;

@FeignClient(name = "review-service")
public interface ReviewClient {
  @GetMapping("/api/reviews/product/{productId}")
  List<Map<String, Object>> getReviewsByProduct(@PathVariable("productId") Long productId);
}
