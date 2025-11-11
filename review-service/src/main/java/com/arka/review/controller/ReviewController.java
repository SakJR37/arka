package com.arka.review.controller;

import com.arka.review.model.Review;
import com.arka.review.service.ReviewService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/api/reviews")
public class ReviewController {
  private final ReviewService reviewService;

  public ReviewController(ReviewService reviewService) {
    this.reviewService = reviewService;
  }

  @PostMapping
  public ResponseEntity<Review> create(@RequestBody Review review) {
    try {
      Review created = reviewService.create(review);
      return ResponseEntity.status(201).body(created);
    } catch (IllegalArgumentException ex) {
      return ResponseEntity.badRequest().build();
    }
  }

  @GetMapping("/product/{productId}")
  public List<Review> getByProduct(@PathVariable Long productId) {
    return reviewService.findByProductId(productId);
  }

  @GetMapping("/user/{userId}")
  public List<Review> getByUser(@PathVariable Long userId) {
    return reviewService.findByUserId(userId);
  }

  @GetMapping("/{id}")
  public ResponseEntity<Review> get(@PathVariable String id) {
    return reviewService.findById(id)
      .map(ResponseEntity::ok)
      .orElse(ResponseEntity.notFound().build());
  }

  @DeleteMapping("/{id}")
  public ResponseEntity<Void> delete(@PathVariable String id) {
    reviewService.delete(id);
    return ResponseEntity.noContent().build();
  }
}
