package com.arka.inventory.service;

import com.arka.inventory.model.Product;
import com.arka.inventory.repository.ProductRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import java.util.List;

@Service
public class StockReportService {
  private static final Logger log = LoggerFactory.getLogger(StockReportService.class);
  private final ProductRepository productRepository;
  private final S3Service s3Service;

  public StockReportService(ProductRepository productRepository, S3Service s3Service) {
    this.productRepository = productRepository;
    this.s3Service = s3Service;
  }

  private String uploadToS3(String content, String fileName) {
    return s3Service.uploadFile(content, "reports/" + fileName);
  }

  public void generateWeeklyReport() {
    log.info("Generating weekly stock report...");
    List<Product> allProducts = productRepository.findAll();
    List<Product> lowStock = productRepository.findByStockLessThan(10);
    
    log.info("Total products: {}", allProducts.size());
    log.info("Low stock products: {}", lowStock.size());
    
    try {
      // Export to CSV
      String csvContent = exportToCsv(allProducts);
      String lowStockCsv = exportToCsv(lowStock);
      
      // Upload to S3
      String reportKey = uploadToS3(csvContent, "all-products-" + System.currentTimeMillis() + ".csv");
      String lowStockKey = uploadToS3(lowStockCsv, "low-stock-" + System.currentTimeMillis() + ".csv");
      
      log.info("Reports uploaded to S3: {}, {}", reportKey, lowStockKey);
      
      // Send notification (placeholder - would call notification-service)
      log.info("Weekly report generated successfully. Low stock items: {}", lowStock.size());
    } catch (Exception e) {
      log.error("Error generating weekly report: {}", e.getMessage(), e);
    }
  }

  public String exportToCsv(List<Product> products) {
    StringBuilder csv = new StringBuilder("ID,Name,Stock,Price,Category\n");
    products.forEach(p -> 
      csv.append(String.format("%d,%s,%d,%.2f,%s\n", 
        p.getId(), p.getName(), p.getStock(), p.getPrice(), p.getCategory()))
    );
    return csv.toString();
  }
}
