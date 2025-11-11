package com.arka.shipping.repository;

import com.arka.shipping.model.ShippingOption;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface ShippingOptionRepository extends JpaRepository<ShippingOption, Long> {
  List<ShippingOption> findByActiveTrue();
}
