package com.arka.inventory.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

@Service
public class S3Service {
  private static final Logger log = LoggerFactory.getLogger(S3Service.class);

  @Value("${aws.s3.bucket-name:arka-reports}")
  private String bucketName;

  @Value("${aws.region:us-east-1}")
  private String awsRegion;

  private S3Client s3Client;

  private S3Client getS3Client() {
    if (s3Client == null) {
      s3Client = S3Client.builder()
          .region(Region.of(awsRegion))
          .credentialsProvider(DefaultCredentialsProvider.create())
          .build();
    }
    return s3Client;
  }

  public String uploadFile(String content, String key) {
    try {
      PutObjectRequest putObjectRequest = PutObjectRequest.builder()
          .bucket(bucketName)
          .key(key)
          .contentType("text/csv")
          .build();

      getS3Client().putObject(putObjectRequest, RequestBody.fromString(content));
      log.info("File uploaded to S3: s3://{}/{}", bucketName, key);
      return key;
    } catch (Exception e) {
      log.error("Failed to upload file to S3: {}", e.getMessage(), e);
      throw new RuntimeException("S3 upload failed", e);
    }
  }
}
