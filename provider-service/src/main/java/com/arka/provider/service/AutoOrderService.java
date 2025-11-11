package com.arka.provider.service;

import com.arka.provider.model.SupplyOrder;
import com.arka.provider.repository.SupplyOrderRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AutoOrderService {
  private static final Logger log = LoggerFactory.getLogger(AutoOrderService.class);
  private final SupplyOrderRepository supplyOrderRepository;

  public AutoOrderService(SupplyOrderRepository supplyOrderRepository) {
    this.supplyOrderRepository = supplyOrderRepository;
  }

  @Transactional
  public SupplyOrder createAutoOrder(Long productId, Long providerId, Integer quantity) {
    log.info("Creating auto-order: productId={}, providerId={}, quantity={}", 
      productId, providerId, quantity);
    
    SupplyOrder order = new SupplyOrder();
    order.setProductId(productId);
    order.setProviderId(providerId);
    order.setQuantity(quantity);
    order.setStatus("PENDING");
    
    return supplyOrderRepository.save(order);
  }

  /**
   * Checks inventory-service for low-stock products and creates auto-orders.
   * This method should be triggered by EventBridge on a schedule (e.g., daily).
   */
  @Transactional
  public void checkAndCreateAutoOrders() {
    log.info("Starting automatic order check for low-stock products");
    
    try {
      // In production, call inventory-service REST API to get low-stock products
      // Example: List<Product> lowStockProducts = inventoryClient.getLowStockProducts();
      
      // For each low-stock product, create a supply order with the default provider
      // Example implementation:
      /*
      for (Product product : lowStockProducts) {
        Provider defaultProvider = providerRepository.findDefaultProviderForCategory(product.getCategory());
        if (defaultProvider != null) {
          int reorderQuantity = calculateReorderQuantity(product);
          createAutoOrder(product.getId(), defaultProvider.getId(), reorderQuantity);
          log.info("Auto-order created for product {} with provider {}", product.getId(), defaultProvider.getId());
        }
      }
      */
      
      log.info("Automatic order check completed");
    } catch (Exception e) {
      log.error("Error during automatic order check: {}", e.getMessage(), e);
    }
  }
  
  /**
   * Calculate reorder quantity based on product's historical sales and current stock.
   * This is a placeholder implementation.
   */
  private int calculateReorderQuantity(Long productId) {
    // In production, this would analyze sales history, lead times, and safety stock levels
    return 50; // Default reorder quantity
  }
}
