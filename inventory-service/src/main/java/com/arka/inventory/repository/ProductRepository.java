package com.arka.inventory.repository;
import com.arka.inventory.model.Product;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
public interface ProductRepository extends JpaRepository<Product, Long> {
  List<Product> findByCategory(String category);
  List<Product> findByStockLessThan(Integer threshold);
}
