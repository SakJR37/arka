package com.arka.shipping.service;

import com.arka.shipping.model.ShippingOption;
import com.arka.shipping.repository.ShippingOptionRepository;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.Optional;

@Service
public class ShippingService {
  private final ShippingOptionRepository shippingOptionRepository;

  public ShippingService(ShippingOptionRepository shippingOptionRepository) {
    this.shippingOptionRepository = shippingOptionRepository;
  }

  public List<ShippingOption> findAll() {
    return shippingOptionRepository.findAll();
  }

  public List<ShippingOption> findActive() {
    return shippingOptionRepository.findByActiveTrue();
  }

  public Optional<ShippingOption> findById(Long id) {
    return shippingOptionRepository.findById(id);
  }
}
