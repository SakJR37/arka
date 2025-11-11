package com.arka.inventory.dto;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.math.BigDecimal;

public class ProductRequest {
  @NotBlank(message = "name is required")
  @Size(max = 255)
  private String name;

  @Size(max = 2000)
  private String description;

  @NotNull(message = "price is required")
  @Min(value = 0, message = "price must be >= 0")
  private BigDecimal price;

  @NotNull(message = "stock is required")
  @Min(value = 0, message = "stock must be >= 0")
  private Integer stock;

  @NotBlank(message = "category is required")
  private String category;

  public ProductRequest(){}

  public String getName(){ return name; }
  public void setName(String name){ this.name = name; }
  public String getDescription(){ return description; }
  public void setDescription(String description){ this.description = description; }
  public BigDecimal getPrice(){ return price; }
  public void setPrice(BigDecimal price){ this.price = price; }
  public Integer getStock(){ return stock; }
  public void setStock(Integer stock){ this.stock = stock; }
  public String getCategory(){ return category; }
  public void setCategory(String category){ this.category = category; }
}