package com.arka.provider.service;

import com.arka.provider.model.Provider;
import com.arka.provider.repository.ProviderRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.List;
import java.util.Optional;

@Service
public class ProviderService {
  private final ProviderRepository providerRepository;

  public ProviderService(ProviderRepository providerRepository) {
    this.providerRepository = providerRepository;
  }

  @Transactional
  public Provider create(Provider provider) {
    return providerRepository.save(provider);
  }

  @Transactional
  public Provider update(Long id, Provider provider) {
    Provider existing = providerRepository.findById(id)
      .orElseThrow(() -> new IllegalArgumentException("Provider not found"));
    
    existing.setName(provider.getName());
    existing.setEmail(provider.getEmail());
    existing.setPhone(provider.getPhone());
    existing.setAddress(provider.getAddress());
    existing.setActive(provider.getActive());
    
    return providerRepository.save(existing);
  }

  public List<Provider> findAll() {
    return providerRepository.findAll();
  }

  public List<Provider> findActive() {
    return providerRepository.findByActiveTrue();
  }

  public Optional<Provider> findById(Long id) {
    return providerRepository.findById(id);
  }
}
