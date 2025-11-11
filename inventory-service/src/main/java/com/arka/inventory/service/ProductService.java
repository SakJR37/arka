package com.arka.inventory.service;

import com.arka.inventory.model.Product;
import com.arka.inventory.model.StockHistory;
import com.arka.inventory.repository.ProductRepository;
import com.arka.inventory.repository.StockHistoryRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.dao.OptimisticLockingFailureException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Service
public class ProductService {
  private final ProductRepository productRepository;
  private final StockHistoryRepository historyRepository;

  public ProductService(ProductRepository productRepository, StockHistoryRepository historyRepository){
    this.productRepository = productRepository;
    this.historyRepository = historyRepository;
  }

  public Product create(Product p){
    if(p.getPrice() == null || p.getPrice().doubleValue() < 0) throw new IllegalArgumentException("Price cannot be negative or null");
    if(p.getStock() == null || p.getStock() < 0) throw new IllegalArgumentException("Stock cannot be negative or null");
    return productRepository.save(p);
  }

  /**
   * Update stock with optimistic locking retry.
   * delta: positive -> increase stock, negative -> decrease (reserve)
   */
  @Transactional
  public Product updateStock(Long productId, int delta, String reason){
    int maxRetries = 3;
    int attempt = 0;
    while (true) {
      attempt++;
      try {
        Product prod = productRepository.findById(productId)
          .orElseThrow(() -> new IllegalArgumentException("Product not found"));
        int newStock = prod.getStock() + delta;
        if(newStock < 0) throw new IllegalArgumentException("Stock cannot be negative");
        prod.setStock(newStock);
        Product saved = productRepository.save(prod);

        StockHistory h = new StockHistory();
        h.setProductId(productId);
        h.setQtyChange(delta);
        h.setReason(reason);
        h.setTimestamp(Instant.now());
        historyRepository.save(h);

        return saved;
      } catch (OptimisticLockingFailureException ex) {
        if (attempt >= maxRetries) throw ex;
        // else retry
      }
    }
  }

  public Optional<Product> findById(Long id){ return productRepository.findById(id); }
  public List<Product> listAll(){ return productRepository.findAll(); }
  public List<Product> lowStock(Integer threshold) { return productRepository.findByStockLessThan(threshold); }
}