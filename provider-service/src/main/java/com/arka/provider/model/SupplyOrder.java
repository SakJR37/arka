package com.arka.provider.model;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "supply_orders")
public class SupplyOrder {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false)
  private Long providerId;

  @Column(nullable = false)
  private Long productId;

  @Column(nullable = false)
  private Integer quantity;

  private String status; // PENDING, SENT, RECEIVED, CANCELLED
  private Instant orderDate;
  private Instant expectedDelivery;
  private Instant receivedDate;

  @PrePersist
  protected void onCreate() {
    orderDate = Instant.now();
    if (status == null) status = "PENDING";
  }

  public SupplyOrder() {}

  public Long getId() { return id; }
  public void setId(Long id) { this.id = id; }

  public Long getProviderId() { return providerId; }
  public void setProviderId(Long providerId) { this.providerId = providerId; }

  public Long getProductId() { return productId; }
  public void setProductId(Long productId) { this.productId = productId; }

  public Integer getQuantity() { return quantity; }
  public void setQuantity(Integer quantity) { this.quantity = quantity; }

  public String getStatus() { return status; }
  public void setStatus(String status) { this.status = status; }

  public Instant getOrderDate() { return orderDate; }
  public Instant getExpectedDelivery() { return expectedDelivery; }
  public void setExpectedDelivery(Instant expectedDelivery) { this.expectedDelivery = expectedDelivery; }

  public Instant getReceivedDate() { return receivedDate; }
  public void setReceivedDate(Instant receivedDate) { this.receivedDate = receivedDate; }
}
