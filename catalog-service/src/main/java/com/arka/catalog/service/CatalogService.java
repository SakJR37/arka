package com.arka.catalog.service;

import com.arka.catalog.model.ProductCatalog;
import com.arka.catalog.repository.ProductCatalogRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.List;
import java.util.Optional;

@Service
public class CatalogService {
  private final ProductCatalogRepository catalogRepository;

  public CatalogService(ProductCatalogRepository catalogRepository) {
    this.catalogRepository = catalogRepository;
  }

  @Transactional
  public ProductCatalog createOrUpdate(ProductCatalog catalog) {
    Optional<ProductCatalog> existing = catalogRepository.findByProductId(catalog.getProductId());
    if (existing.isPresent()) {
      ProductCatalog existingCatalog = existing.get();
      existingCatalog.setName(catalog.getName());
      existingCatalog.setDescription(catalog.getDescription());
      existingCatalog.setPrice(catalog.getPrice());
      existingCatalog.setStock(catalog.getStock());
      existingCatalog.setCategory(catalog.getCategory());
      existingCatalog.setImageUrl(catalog.getImageUrl());
      existingCatalog.setActive(catalog.getActive());
      return catalogRepository.save(existingCatalog);
    }
    return catalogRepository.save(catalog);
  }

  public List<ProductCatalog> findAll() {
    return catalogRepository.findAll();
  }

  public List<ProductCatalog> findActive() {
    return catalogRepository.findByActiveTrue();
  }

  public List<ProductCatalog> findByCategory(String category) {
    return catalogRepository.findByCategory(category);
  }

  public Optional<ProductCatalog> findById(Long id) {
    return catalogRepository.findById(id);
  }

  @Transactional
  public void deactivate(Long id) {
    catalogRepository.findById(id).ifPresent(catalog -> {
      catalog.setActive(false);
      catalogRepository.save(catalog);
    });
  }
}
