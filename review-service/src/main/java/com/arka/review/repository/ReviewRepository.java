package com.arka.review.repository;

import com.arka.review.model.Review;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface ReviewRepository extends MongoRepository<Review, String> {
  List<Review> findByProductId(Long productId);
  List<Review> findByUserId(Long userId);
}
