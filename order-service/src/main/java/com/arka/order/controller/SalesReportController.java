package com.arka.order.controller;

import com.arka.order.service.SalesReportService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/orders/reports")
public class SalesReportController {
  private final SalesReportService salesReportService;

  public SalesReportController(SalesReportService salesReportService) {
    this.salesReportService = salesReportService;
  }

  @GetMapping("/sales/weekly")
  public ResponseEntity<Map<String, Object>> getWeeklySalesReport() {
    Map<String, Object> report = salesReportService.generateWeeklySalesReport();
    return ResponseEntity.ok(report);
  }

  @GetMapping("/sales/weekly/csv")
  public ResponseEntity<String> getWeeklySalesReportCsv() {
    Map<String, Object> report = salesReportService.generateWeeklySalesReport();
    String csv = salesReportService.exportToCsv(report);
    
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.parseMediaType("text/csv"));
    headers.setContentDispositionFormData("attachment", "weekly-sales-report.csv");
    
    return ResponseEntity.ok()
      .headers(headers)
      .body(csv);
  }
}
