package com.arka.shipping.model;

import jakarta.persistence.*;
import java.math.BigDecimal;

@Entity
@Table(name = "shipping_options")
public class ShippingOption {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false)
  private String name; // PICKUP, DELIVERY, EXPRESS

  @Column(nullable = false)
  private BigDecimal cost;

  private Integer estimatedDays;
  private String description;
  private Boolean active = true;

  public ShippingOption() {}

  public Long getId() { return id; }
  public void setId(Long id) { this.id = id; }

  public String getName() { return name; }
  public void setName(String name) { this.name = name; }

  public BigDecimal getCost() { return cost; }
  public void setCost(BigDecimal cost) { this.cost = cost; }

  public Integer getEstimatedDays() { return estimatedDays; }
  public void setEstimatedDays(Integer estimatedDays) { this.estimatedDays = estimatedDays; }

  public String getDescription() { return description; }
  public void setDescription(String description) { this.description = description; }

  public Boolean getActive() { return active; }
  public void setActive(Boolean active) { this.active = active; }
}
