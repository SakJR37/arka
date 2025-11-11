package com.arka.inventory.model;

import jakarta.persistence.*;
import java.math.BigDecimal;

@Entity
@Table(name = "products")
public class Product {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable=false)
  private String name;

  @Column(length=2000)
  private String description;

  @Column(nullable=false)
  private BigDecimal price;

  @Column(nullable=false)
  private Integer stock;

  private String category;

  @Version
  private Long version;

  public Product(){}

  public Long getId(){return id;} public void setId(Long id){this.id=id;}
  public String getName(){return name;} public void setName(String name){this.name=name;}
  public String getDescription(){return description;} public void setDescription(String description){this.description=description;}
  public BigDecimal getPrice(){return price;} public void setPrice(BigDecimal price){this.price=price;}
  public Integer getStock(){return stock;} public void setStock(Integer stock){this.stock=stock;}
  public String getCategory(){return category;} public void setCategory(String category){this.category=category;}
  public Long getVersion(){ return version; } public void setVersion(Long version){ this.version = version; }
}