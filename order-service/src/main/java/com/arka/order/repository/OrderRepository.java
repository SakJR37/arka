package com.arka.order.repository;

import com.arka.order.model.Order;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;

@Repository
public interface OrderRepository extends JpaRepository<Order, Long> {
  List<Order> findByCustomerEmail(String customerEmail);
  List<Order> findByStatus(String status);
  List<Order> findByCreatedAtAfter(Instant date);
}
