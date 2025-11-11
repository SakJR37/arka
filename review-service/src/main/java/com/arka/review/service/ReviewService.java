package com.arka.review.service;

import com.arka.review.model.Review;
import com.arka.review.repository.ReviewRepository;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.Optional;

@Service
public class ReviewService {
  private final ReviewRepository reviewRepository;

  public ReviewService(ReviewRepository reviewRepository) {
    this.reviewRepository = reviewRepository;
  }

  public Review create(Review review) {
    if (review.getRating() == null || review.getRating() < 1 || review.getRating() > 5) {
      throw new IllegalArgumentException("Rating must be between 1 and 5");
    }
    return reviewRepository.save(review);
  }

  public List<Review> findByProductId(Long productId) {
    return reviewRepository.findByProductId(productId);
  }

  public List<Review> findByUserId(Long userId) {
    return reviewRepository.findByUserId(userId);
  }

  public Optional<Review> findById(String id) {
    return reviewRepository.findById(id);
  }

  public void delete(String id) {
    reviewRepository.deleteById(id);
  }
}
