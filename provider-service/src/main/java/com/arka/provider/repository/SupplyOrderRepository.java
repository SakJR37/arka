package com.arka.provider.repository;

import com.arka.provider.model.SupplyOrder;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface SupplyOrderRepository extends JpaRepository<SupplyOrder, Long> {
  List<SupplyOrder> findByProviderId(Long providerId);
  List<SupplyOrder> findByStatus(String status);
}
