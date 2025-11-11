package com.arka.cart.model;

import jakarta.persistence.*;

@Entity
@Table(name = "cart_items")
public class CartItem {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false)
  private Long productId;

  private String productName;
  private Double price;

  @Column(nullable = false)
  private Integer quantity;

  public CartItem() {}

  public Long getId() { return id; }
  public void setId(Long id) { this.id = id; }

  public Long getProductId() { return productId; }
  public void setProductId(Long productId) { this.productId = productId; }

  public String getProductName() { return productName; }
  public void setProductName(String productName) { this.productName = productName; }

  public Double getPrice() { return price; }
  public void setPrice(Double price) { this.price = price; }

  public Integer getQuantity() { return quantity; }
  public void setQuantity(Integer quantity) { this.quantity = quantity; }
}
