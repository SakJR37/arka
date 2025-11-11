package com.arka.review.model;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import java.time.Instant;

@Document(collection = "reviews")
public class Review {
  @Id
  private String id;
  private Long productId;
  private Long userId;
  private String userName;
  private Integer rating;
  private String comment;
  private Instant createdAt;

  public Review() {
    this.createdAt = Instant.now();
  }

  public String getId() { return id; }
  public void setId(String id) { this.id = id; }

  public Long getProductId() { return productId; }
  public void setProductId(Long productId) { this.productId = productId; }

  public Long getUserId() { return userId; }
  public void setUserId(Long userId) { this.userId = userId; }

  public String getUserName() { return userName; }
  public void setUserName(String userName) { this.userName = userName; }

  public Integer getRating() { return rating; }
  public void setRating(Integer rating) { this.rating = rating; }

  public String getComment() { return comment; }
  public void setComment(String comment) { this.comment = comment; }

  public Instant getCreatedAt() { return createdAt; }
}
