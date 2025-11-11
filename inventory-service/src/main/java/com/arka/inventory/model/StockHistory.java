package com.arka.inventory.model;

import jakarta.persistence.*;
import java.time.Instant;
@Entity
@Table(name="stock_history")
public class StockHistory {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;
  private Long productId;
  private Integer qtyChange;
  private String reason;
  private Instant timestamp;
  public StockHistory(){}
  public Long getId(){return id;} public void setId(Long id){this.id=id;}
  public Long getProductId(){return productId;} public void setProductId(Long productId){this.productId=productId;}
  public Integer getQtyChange(){return qtyChange;} public void setQtyChange(Integer qtyChange){this.qtyChange=qtyChange;}
  public String getReason(){return reason;} public void setReason(String reason){this.reason=reason;}
  public Instant getTimestamp(){return timestamp;} public void setTimestamp(Instant timestamp){this.timestamp=timestamp;}
}
