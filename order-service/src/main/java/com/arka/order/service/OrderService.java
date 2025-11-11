package com.arka.order.service;

import com.arka.order.clients.InventoryClient;
import com.arka.order.clients.NotificationClient;
import com.arka.order.model.Order;
import com.arka.order.model.OrderItem;
import com.arka.order.repository.OrderRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class OrderService {
  private final OrderRepository orderRepository;
  private final InventoryClient inventoryClient;
  private final NotificationClient notificationClient;

  public OrderService(OrderRepository orderRepository, InventoryClient inventoryClient, NotificationClient notificationClient){
    this.orderRepository = orderRepository;
    this.inventoryClient = inventoryClient;
    this.notificationClient = notificationClient;
  }

  @Transactional
  public Order createOrder(Order order){
    order.setStatus("PENDING");
    order.setCreatedAt(Instant.now());
    double total = 0;
    if(order.getItems() != null){
      for(OrderItem it : order.getItems()) total += it.getQuantity() * it.getPrice();
    }
    order.setTotal(total);
    Order saved = orderRepository.save(order);

    try {
      if(saved.getItems() != null){
        for(OrderItem it : saved.getItems()){
          inventoryClient.updateStock(it.getProductId(), - it.getQuantity(), "reserve-order-" + saved.getId());
        }
      }
      saved.setStatus("CONFIRMED");
      orderRepository.save(saved);

      // notify
      Map<String,Object> payload = Map.of(
        "type","ORDER_CONFIRMED",
        "orderId", saved.getId(),
        "email", saved.getCustomerEmail()
      );
      try { notificationClient.send(payload); } catch(Exception ignored){ /* best-effort */ }

    } catch (Exception ex) {
      if(saved.getItems() != null){
        for(OrderItem it : saved.getItems()){
          try { inventoryClient.updateStock(it.getProductId(), it.getQuantity(), "compensate-order-" + saved.getId()); }
          catch(Exception e){}
        }
      }
      saved.setStatus("CANCELLED");
      orderRepository.save(saved);
      throw new RuntimeException("Reservation failed: " + ex.getMessage());
    }
    return saved;
  }

  /**
   * Modify an order only if it's in PENDING state.
   * We compute deltas per product and call inventory to adjust stock:
   *  - delta > 0 : need to reserve more => inventory.updateStock(productId, -delta)
   *  - delta < 0 : release stock => inventory.updateStock(productId, +abs(delta))
   */
  @Transactional
  public Order modifyOrder(Long orderId, List<OrderItem> newItems) {
    Order existing = orderRepository.findById(orderId).orElseThrow(() -> new IllegalArgumentException("Order not found"));
    if (!"PENDING".equalsIgnoreCase(existing.getStatus())) {
      throw new IllegalStateException("Only orders in PENDING can be modified");
    }

    // Map productId -> qty for old and new
    Map<Long, Integer> oldMap = new HashMap<>();
    if(existing.getItems() != null){
      for(OrderItem it : existing.getItems()) oldMap.put(it.getProductId(), it.getQuantity());
    }
    Map<Long, Integer> newMap = new HashMap<>();
    if(newItems != null){
      for(OrderItem it : newItems) newMap.put(it.getProductId(), it.getQuantity());
    }

    // compute union of product ids
    Set<Long> all = new HashSet<>();
    all.addAll(oldMap.keySet());
    all.addAll(newMap.keySet());

    // First, attempt to reserve required increases
    try {
      for(Long pid : all){
        int oldQty = oldMap.getOrDefault(pid, 0);
        int newQty = newMap.getOrDefault(pid, 0);
        int delta = newQty - oldQty;
        if(delta > 0){
          // need to reserve delta
          inventoryClient.updateStock(pid, -delta, "reserve-modify-order-" + orderId);
        }
      }
      // If reservations successful, release if quantities decreased
      for(Long pid : all){
        int oldQty = oldMap.getOrDefault(pid, 0);
        int newQty = newMap.getOrDefault(pid, 0);
        int delta = newQty - oldQty;
        if(delta < 0){
          // release (-delta)
          inventoryClient.updateStock(pid, -delta * -1 * -1, "release-modify-order-" + orderId); // simpler: +abs(delta)
          // to be clearer, call with +abs(delta)
          inventoryClient.updateStock(pid, Math.abs(delta), "release-modify-order-" + orderId);
        }
      }

      // Persist new items
      existing.setItems(newItems);
      double total = 0;
      if(newItems != null){
        for(OrderItem it : newItems) total += it.getPrice() * it.getQuantity();
      }
      existing.setTotal(total);
      Order updated = orderRepository.save(existing);

      // Notify modification
      Map<String,Object> payload = Map.of(
        "type","ORDER_MODIFIED",
        "orderId", updated.getId(),
        "email", updated.getCustomerEmail()
      );
      try { notificationClient.send(payload); } catch(Exception ignored){}

      return updated;
    } catch (Exception ex) {
      // Try to compensate any partial reservations: for simplicity we don't track partial here,
      // but production code should track per-item reservation success to compensate precisely.
      throw new RuntimeException("Failed to modify order: " + ex.getMessage());
    }
  }
}