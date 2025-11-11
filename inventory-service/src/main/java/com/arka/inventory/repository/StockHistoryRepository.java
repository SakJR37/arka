package com.arka.inventory.repository;
import com.arka.inventory.model.StockHistory;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
public interface StockHistoryRepository extends JpaRepository<StockHistory, Long> {
  List<StockHistory> findByProductId(Long productId);
}
