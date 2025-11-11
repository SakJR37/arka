package com.arka.bff.web.controller;

import com.arka.bff.web.service.CatalogBffWebService;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestController
@RequestMapping("/api/bff/web")
public class CatalogBffWebController {
  private final CatalogBffWebService bffService;

  public CatalogBffWebController(CatalogBffWebService bffService) {
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
