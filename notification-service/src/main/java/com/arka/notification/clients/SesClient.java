package com.arka.notification.clients;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ses.SesClient;
import software.amazon.awssdk.services.ses.model.*;

@Component
public class SesEmailClient {
  
  private final SesClient sesClient;
  
  @Value("${aws.ses.from-email}")
  private String fromEmail;

  public SesEmailClient(@Value("${aws.region}") String region) {
    this.sesClient = SesClient.builder()
        .region(Region.of(region))
        .build();
  }

  public void sendEmail(String to, String subject, String bodyText, String bodyHtml) {
    try {
      Destination destination = Destination.builder()
          .toAddresses(to)
          .build();

      Content subjectContent = Content.builder()
          .data(subject)
          .build();

      Body body = Body.builder()
          .text(Content.builder().data(bodyText).build())
          .html(Content.builder().data(bodyHtml).build())
          .build();

      Message message = Message.builder()
          .subject(subjectContent)
          .body(body)
          .build();

      SendEmailRequest emailRequest = SendEmailRequest.builder()
          .destination(destination)
          .message(message)
          .source(fromEmail)
          .build();

      SendEmailResponse response = sesClient.sendEmail(emailRequest);
      System.out.println("Email sent! Message ID: " + response.messageId());

    } catch (SesException e) {
      System.err.println("SES Error: " + e.awsErrorDetails().errorMessage());
      throw new RuntimeException("Failed to send email via SES", e);
    }
  }

  public void sendTemplatedEmail(String to, String templateName, String templateData) {
    try {
      SendTemplatedEmailRequest request = SendTemplatedEmailRequest.builder()
          .source(fromEmail)
          .destination(Destination.builder().toAddresses(to).build())
          .template(templateName)
          .templateData(templateData)
          .build();

      SendTemplatedEmailResponse response = sesClient.sendTemplatedEmail(request);
      System.out.println("Templated email sent! Message ID: " + response.messageId());

    } catch (SesException e) {
      System.err.println("SES Error: " + e.awsErrorDetails().errorMessage());
      throw new RuntimeException("Failed to send templated email via SES", e);
    }
  }
}
