package com.arka.order.scheduler;

import com.arka.order.service.SalesReportService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
public class SalesReportScheduler {
  private static final Logger log = LoggerFactory.getLogger(SalesReportScheduler.class);
  private final SalesReportService salesReportService;

  public SalesReportScheduler(SalesReportService salesReportService) {
    this.salesReportService = salesReportService;
  }

  @Scheduled(cron = "0 0 8 * * MON") // Every Monday at 8 AM
  public void generateWeeklySalesReport() {
    log.info("Starting weekly sales report generation...");
    try {
      Map<String, Object> report = salesReportService.generateWeeklySalesReport();
      String csvContent = salesReportService.exportToCsv(report);
      
      // TODO: Upload to S3 or send via email
      log.info("Weekly sales report generated successfully");
      log.debug("Report CSV preview:\n{}", csvContent.substring(0, Math.min(500, csvContent.length())));
      
    } catch (Exception e) {
      log.error("Failed to generate weekly sales report: {}", e.getMessage(), e);
    }
  }
}
