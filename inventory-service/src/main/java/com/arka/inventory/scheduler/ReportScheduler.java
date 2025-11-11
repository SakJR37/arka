package com.arka.inventory.scheduler;

import com.arka.inventory.service.StockReportService;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class ReportScheduler {
  private final StockReportService reportService;

  public ReportScheduler(StockReportService reportService) {
    this.reportService = reportService;
  }

  @Scheduled(cron = "0 0 9 * * MON") // Every Monday at 9 AM
  public void generateWeeklyStockReport() {
    reportService.generateWeeklyReport();
  }
}
