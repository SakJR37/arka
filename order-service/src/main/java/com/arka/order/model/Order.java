package com.arka.order.model;
import jakarta.persistence.*;
import java.time.Instant;
import java.util.List;
@Entity
@Table(name = "orders")
public class Order {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;
  private String customerEmail;
  private Instant createdAt;
  private String status;
  @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER)
  @JoinColumn(name="order_id")
  private List<OrderItem> items;
  private double total;
  public Order(){}
  public Long getId(){return id;} public void setId(Long id){this.id=id;}
  public String getCustomerEmail(){return customerEmail;} public void setCustomerEmail(String customerEmail){this.customerEmail=customerEmail;}
  public Instant getCreatedAt(){return createdAt;} public void setCreatedAt(Instant createdAt){this.createdAt=createdAt;}
  public String getStatus(){return status;} public void setStatus(String status){this.status=status;}
  public List<OrderItem> getItems(){return items;} public void setItems(List<OrderItem> items){this.items=items;}
  public double getTotal(){return total;} public void setTotal(double total){this.total=total;}
}
