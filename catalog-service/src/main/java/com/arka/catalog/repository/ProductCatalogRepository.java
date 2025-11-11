package com.arka.catalog.repository;

import com.arka.catalog.model.ProductCatalog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;
import java.util.Optional;

@Repository
public interface ProductCatalogRepository extends JpaRepository<ProductCatalog, Long> {
  List<ProductCatalog> findByCategory(String category);
  List<ProductCatalog> findByActiveTrue();
  Optional<ProductCatalog> findByProductId(Long productId);
}
