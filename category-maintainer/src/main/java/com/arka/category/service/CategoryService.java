package com.arka.category.service;

import com.arka.category.model.Category;
import com.arka.category.repository.CategoryRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.List;
import java.util.Optional;

@Service
public class CategoryService {
  private final CategoryRepository categoryRepository;

  public CategoryService(CategoryRepository categoryRepository) {
    this.categoryRepository = categoryRepository;
  }

  @Transactional
  public Category create(Category category) {
    if (categoryRepository.findByName(category.getName()).isPresent()) {
      throw new IllegalArgumentException("Category with this name already exists");
    }
    return categoryRepository.save(category);
  }

  @Transactional
  public Category update(Long id, Category category) {
    Category existing = categoryRepository.findById(id)
      .orElseThrow(() -> new IllegalArgumentException("Category not found"));
    
    existing.setName(category.getName());
    existing.setDescription(category.getDescription());
    existing.setImageUrl(category.getImageUrl());
    existing.setActive(category.getActive());
    
    return categoryRepository.save(existing);
  }

  public List<Category> findAll() {
    return categoryRepository.findAll();
  }

  public List<Category> findActive() {
    return categoryRepository.findByActiveTrue();
  }

  public Optional<Category> findById(Long id) {
    return categoryRepository.findById(id);
  }

  @Transactional
  public void delete(Long id) {
    categoryRepository.deleteById(id);
  }
}
