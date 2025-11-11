package com.arka.bff.mobile.controller;

import com.arka.bff.mobile.service.CatalogBffMobileService;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestController
@RequestMapping("/api/bff/mobile")
public class CatalogBffMobileController {
  private final CatalogBffMobileService bffService;

  public CatalogBffMobileController(CatalogBffMobileService bffService) {
    this.bffService = bffService;
  }

  @GetMapping("/catalog")
  public Map<String, Object> getCatalogData() {
    return bffService.aggregateCatalogData();
  }

  @GetMapping("/product/{id}")
  public Map<String, Object> getProductDetails(@PathVariable Long id) {
    return bffService.aggregateProductDetails(id);
  }
}
