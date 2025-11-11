package com.arka.order.clients;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

@FeignClient(name = "notification-service")
public interface NotificationClient {
  @PostMapping("/api/notifications/send")
  void send(@RequestBody Map<String, Object> payload);
}