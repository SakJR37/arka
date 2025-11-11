package com.arka.notification.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ses.SesClient;
import software.amazon.awssdk.services.ses.model.*;
import software.amazon.awssdk.services.sns.SnsClient;
import software.amazon.awssdk.services.sns.model.PublishRequest;
import software.amazon.awssdk.services.sns.model.PublishResponse;

import java.util.Map;

@Service
public class NotificationService {
  private static final Logger log = LoggerFactory.getLogger(NotificationService.class);

  @Value("${aws.region:us-east-1}")
  private String awsRegion;

  @Value("${aws.ses.from-email:noreply@arka.com}")
  private String fromEmail;

  private SesClient sesClient;
  private SnsClient snsClient;

  private SesClient getSesClient() {
    if (sesClient == null) {
      sesClient = SesClient.builder()
          .region(Region.of(awsRegion))
          .credentialsProvider(DefaultCredentialsProvider.create())
          .build();
    }
    return sesClient;
  }

  private SnsClient getSnsClient() {
    if (snsClient == null) {
      snsClient = SnsClient.builder()
          .region(Region.of(awsRegion))
          .credentialsProvider(DefaultCredentialsProvider.create())
          .build();
    }
    return snsClient;
  }

  public void sendEmail(String to, String subject, String body) {
    log.info("Sending email via AWS SES to: {}, subject: {}", to, subject);
    
    try {
      Destination destination = Destination.builder()
          .toAddresses(to)
          .build();

      Content subjectContent = Content.builder()
          .data(subject)
          .build();

      Content bodyContent = Content.builder()
          .data(body)
          .build();

      Body emailBody = Body.builder()
          .text(bodyContent)
          .build();

      Message message = Message.builder()
          .subject(subjectContent)
          .body(emailBody)
          .build();

      SendEmailRequest emailRequest = SendEmailRequest.builder()
          .source(fromEmail)
          .destination(destination)
          .message(message)
          .build();

      SendEmailResponse response = getSesClient().sendEmail(emailRequest);
      log.info("Email sent successfully. MessageId: {}", response.messageId());
    } catch (Exception e) {
      log.error("Failed to send email via SES: {}", e.getMessage(), e);
      throw new RuntimeException("Email sending failed", e);
    }
  }

  public void sendSms(String phoneNumber, String message) {
    log.info("Sending SMS via AWS SNS to: {}", phoneNumber);
    
    try {
      PublishRequest request = PublishRequest.builder()
          .phoneNumber(phoneNumber)
          .message(message)
          .build();

      PublishResponse response = getSnsClient().publish(request);
      log.info("SMS sent successfully. MessageId: {}", response.messageId());
    } catch (Exception e) {
      log.error("Failed to send SMS via SNS: {}", e.getMessage(), e);
      throw new RuntimeException("SMS sending failed", e);
    }
  }

  public void processNotification(Map<String, Object> payload) {
    String type = (String) payload.get("type");
    
    switch (type) {
      case "EMAIL":
        String email = (String) payload.get("email");
        String subject = (String) payload.get("subject");
        String body = (String) payload.get("body");
        sendEmail(email, subject, body);
        break;
      case "SMS":
        String phone = (String) payload.get("phone");
        String message = (String) payload.get("message");
        sendSms(phone, message);
        break;
      default:
        log.warn("Unknown notification type: {}", type);
    }
  }
}
