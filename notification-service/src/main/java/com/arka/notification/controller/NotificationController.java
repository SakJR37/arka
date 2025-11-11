package com.arka.notification.controller;

import com.arka.notification.service.NotificationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestController
@RequestMapping("/api/notifications")
public class NotificationController {
  private static final Logger log = LoggerFactory.getLogger(NotificationController.class);
  private final NotificationService notificationService;

  public NotificationController(NotificationService notificationService) {
    this.notificationService = notificationService;
  }

  @PostMapping("/send")
  public ResponseEntity<?> send(@RequestBody Map<String,Object> payload){
    log.info("Received notification request: {}", payload);
    notificationService.processNotification(payload);
    return ResponseEntity.accepted().body(Map.of("status","queued"));
  }
}