package com.arka.order.service;

import com.arka.order.model.Order;
import com.arka.order.repository.OrderRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class SalesReportService {
  private static final Logger log = LoggerFactory.getLogger(SalesReportService.class);
  private final OrderRepository orderRepository;

  public SalesReportService(OrderRepository orderRepository) {
    this.orderRepository = orderRepository;
  }

  public Map<String, Object> generateWeeklySalesReport() {
    log.info("Generating weekly sales report...");
    
    Instant oneWeekAgo = Instant.now().minus(7, ChronoUnit.DAYS);
    List<Order> orders = orderRepository.findByCreatedAtAfter(oneWeekAgo);
    
    // Total de ventas
    double totalSales = orders.stream()
      .filter(o -> "CONFIRMED".equalsIgnoreCase(o.getStatus()))
      .mapToDouble(Order::getTotal)
      .sum();
    
    // Productos más vendidos (productId -> cantidad)
    Map<Long, Integer> productSales = new HashMap<>();
    orders.forEach(order -> {
      if (order.getItems() != null) {
        order.getItems().forEach(item -> {
          productSales.merge(item.getProductId(), item.getQuantity(), Integer::sum);
        });
      }
    });
    
    // Top 10 productos
    List<Map<String, Object>> topProducts = productSales.entrySet().stream()
      .sorted(Map.Entry.<Long, Integer>comparingByValue().reversed())
      .limit(10)
      .map(e -> Map.<String, Object>of("productId", e.getKey(), "quantity", e.getValue()))
      .collect(Collectors.toList());
    
    // Clientes más frecuentes (email -> cantidad de órdenes)
    Map<String, Long> customerFrequency = orders.stream()
      .filter(o -> o.getCustomerEmail() != null)
      .collect(Collectors.groupingBy(Order::getCustomerEmail, Collectors.counting()));
    
    List<Map<String, Object>> topCustomers = customerFrequency.entrySet().stream()
      .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
      .limit(10)
      .map(e -> Map.<String, Object>of("email", e.getKey(), "orders", e.getValue()))
      .collect(Collectors.toList());
    
    Map<String, Object> report = new HashMap<>();
    report.put("period", "last_7_days");
    report.put("totalSales", totalSales);
    report.put("totalOrders", orders.size());
    report.put("topProducts", topProducts);
    report.put("topCustomers", topCustomers);
    report.put("generatedAt", Instant.now());
    
    log.info("Weekly sales report generated: totalSales={}, orders={}", totalSales, orders.size());
    return report;
  }

  public String exportToCsv(Map<String, Object> report) {
    StringBuilder csv = new StringBuilder();
    
    csv.append("=== WEEKLY SALES REPORT ===\n");
    csv.append("Generated At,").append(report.get("generatedAt")).append("\n");
    csv.append("Period,").append(report.get("period")).append("\n");
    csv.append("Total Sales,").append(report.get("totalSales")).append("\n");
    csv.append("Total Orders,").append(report.get("totalOrders")).append("\n\n");
    
    csv.append("=== TOP PRODUCTS ===\n");
    csv.append("Product ID,Quantity Sold\n");
    @SuppressWarnings("unchecked")
    List<Map<String, Object>> topProducts = (List<Map<String, Object>>) report.get("topProducts");
    topProducts.forEach(p -> 
      csv.append(p.get("productId")).append(",").append(p.get("quantity")).append("\n")
    );
    
    csv.append("\n=== TOP CUSTOMERS ===\n");
    csv.append("Email,Orders Count\n");
    @SuppressWarnings("unchecked")
    List<Map<String, Object>> topCustomers = (List<Map<String, Object>>) report.get("topCustomers");
    topCustomers.forEach(c -> 
      csv.append(c.get("email")).append(",").append(c.get("orders")).append("\n")
    );
    
    return csv.toString();
  }
}
