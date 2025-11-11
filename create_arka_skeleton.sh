#!/usr/bin/env bash
set -e
# create_arka_full.sh - Genera estructura y archivos para ARKA backend
ROOT="$(pwd)"
echo "Generando estructura ARKA en $ROOT"

# Crear carpetas principales
mkdir -p eureka-server/src/main/java/com/arka/eureka eureka-server/src/main/resources
mkdir -p gateway/src/main/java/com/arka/gateway gateway/src/main/resources
mkdir -p inventory-service/src/main/java/com/arka/inventory/{controller,service,model,repository} inventory-service/src/main/resources
mkdir -p order-service/src/main/java/com/arka/order/{controller,service,model,clients,repository} order-service/src/main/resources
mkdir -p auth-service/src/main/java/com/arka/auth auth-service/src/main/resources
mkdir -p notification-service/src/main/java/com/arka/notification notification-service/src/main/resources
mkdir -p catalog-bff-web/src/main/java/com/arka/bff web catalog-bff-web/src/main/resources
mkdir -p catalog-bff-mobile/src/main/java/com/arka/bff/mobile catalog-bff-mobile/src/main/resources
mkdir -p review-service/src/main/java/com/arka/review review-service/src/main/resources
mkdir -p terraform .github/workflows

# README
cat > README.md <<'EOF'
# ARKA Backend - Microservices (Spring Boot)

Estructura generada automáticamente. Servicios incluidos: eureka-server, gateway, inventory-service, order-service, auth-service, notification-service, catalog-bff-web, catalog-bff-mobile, review-service.

Local quick start:
1. Java 17, Maven, Docker y Docker Compose instalados.
2. Build artifacts (mvn -f <module> package) o usar imágenes locales.
3. docker-compose up --build
EOF

# .gitignore
cat > .gitignore <<'EOF'
target/
*.log
*.tmp
*.class
.idea/
.vscode/
*.iml
docker-compose.override.yml
.DS_Store
EOF

# docker-compose.yml
cat > docker-compose.yml <<'EOF'
version: '3.8'
services:
  postgres-inventory:
    image: postgres:14
    environment:
      POSTGRES_DB: inventorydb
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
    ports:
      - "5432:5432"

  postgres-order:
    image: postgres:14
    environment:
      POSTGRES_DB: orderdb
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
    ports:
      - "5433:5432"

  mongo:
    image: mongo:6
    ports:
      - "27017:27017"

  eureka:
    build: ./eureka-server
    ports:
      - "8761:8761"
    depends_on:
      - postgres-inventory
      - postgres-order

  gateway:
    build: ./gateway
    ports:
      - "8080:8080"
    depends_on:
      - eureka

  inventory:
    build: ./inventory-service
    ports:
      - "8081:8081"
    depends_on:
      - postgres-inventory
      - eureka

  order:
    build: ./order-service
    ports:
      - "8082:8082"
    depends_on:
      - postgres-order
      - inventory
      - eureka
EOF

# Terraform skeleton
cat > terraform/main.tf <<'EOF'
# Terraform skeleton - Revisa y personaliza antes de aplicar
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}
provider "aws" {
  region = var.aws_region
}
resource "random_id" "bucket_suffix" {
  byte_length = 4
}
resource "aws_s3_bucket" "arka_reports" {
  bucket = "${var.prefix}-arka-reports-${random_id.bucket_suffix.hex}"
  acl    = "private"
}
# Añade módulos: RDS, ECR, ECS, SQS, SNS, Lambda, IAM...
EOF

# CI workflow
cat > .github/workflows/ci.yml <<'EOF'
name: CI - Build & Test

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up JDK 17
        uses: actions/setup-java@v4
        with:
          distribution: temurin
          java-version: 17
      - name: Build inventory-service
        run: mvn -B -f inventory-service/pom.xml -DskipTests package
      - name: Build order-service
        run: mvn -B -f order-service/pom.xml -DskipTests package
EOF

# eureka-server
cat > eureka-server/src/main/java/com/arka/eureka/EurekaServerApplication.java <<'EOF'
package com.arka.eureka;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.eureka.server.EnableEurekaServer;

@SpringBootApplication
@EnableEurekaServer
public class EurekaServerApplication {
  public static void main(String[] args) {
    SpringApplication.run(EurekaServerApplication.class, args);
  }
}
EOF

cat > eureka-server/src/main/resources/application.yml <<'EOF'
server:
  port: 8761

eureka:
  instance:
    hostname: eureka
  client:
    register-with-eureka: false
    fetch-registry: false
    service-url:
      defaultZone: http://eureka:8761/eureka/
EOF

cat > eureka-server/Dockerfile <<'EOF'
FROM eclipse-temurin:17-jdk-jammy
WORKDIR /app
COPY target/*.jar app.jar
EXPOSE 8761
ENTRYPOINT ["java","-jar","/app/app.jar"]
EOF

# gateway
cat > gateway/src/main/java/com/arka/gateway/GatewayApplication.java <<'EOF'
package com.arka.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class GatewayApplication {
  public static void main(String[] args) {
    SpringApplication.run(GatewayApplication.class, args);
  }
}
EOF

cat > gateway/src/main/resources/application.yml <<'EOF'
server:
  port: 8080

spring:
  cloud:
    gateway:
      routes:
        - id: inventory
          uri: lb://inventory-service
          predicates:
            - Path=/api/products/**

        - id: orders
          uri: lb://order-service
          predicates:
            - Path=/api/orders/**

eureka:
  client:
    service-url:
      defaultZone: http://eureka:8761/eureka/
EOF

cat > gateway/Dockerfile <<'EOF'
FROM eclipse-temurin:17-jdk-jammy
WORKDIR /app
COPY target/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java","-jar","/app/app.jar"]
EOF

# inventory-service pom
cat > inventory-service/pom.xml <<'EOF'
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.arka</groupId>
  <artifactId>inventory-service</artifactId>
  <version>0.0.1-SNAPSHOT</version>
  <properties>
    <java.version>17</java.version>
    <spring.boot.version>3.1.6</spring.boot.version>
  </properties>
  <dependencies>
    <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-web</artifactId></dependency>
    <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-data-jpa</artifactId></dependency>
    <dependency><groupId>org.postgresql</groupId><artifactId>postgresql</artifactId><scope>runtime</scope></dependency>
    <dependency><groupId>org.springframework.cloud</groupId><artifactId>spring-cloud-starter-netflix-eureka-client</artifactId></dependency>
    <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-validation</artifactId></dependency>
    <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-test</artifactId><scope>test</scope></dependency>
  </dependencies>
</project>
EOF

# inventory-service main + models + repo + service + controller + dockerfile + app.yml
cat > inventory-service/src/main/java/com/arka/inventory/InventoryApplication.java <<'EOF'
package com.arka.inventory;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient
public class InventoryApplication {
  public static void main(String[] args) {
    SpringApplication.run(InventoryApplication.class, args);
  }
}
EOF

cat > inventory-service/src/main/java/com/arka/inventory/model/Product.java <<'EOF'
package com.arka.inventory.model;

import jakarta.persistence.*;
import java.math.BigDecimal;

@Entity
@Table(name = "products")
public class Product {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;
  @Column(nullable=false)
  private String name;
  @Column(length=2000)
  private String description;
  @Column(nullable=false)
  private BigDecimal price;
  @Column(nullable=false)
  private Integer stock;
  private String category;
  public Product(){}
  public Long getId(){return id;} public void setId(Long id){this.id=id;}
  public String getName(){return name;} public void setName(String name){this.name=name;}
  public String getDescription(){return description;} public void setDescription(String description){this.description=description;}
  public BigDecimal getPrice(){return price;} public void setPrice(BigDecimal price){this.price=price;}
  public Integer getStock(){return stock;} public void setStock(Integer stock){this.stock=stock;}
  public String getCategory(){return category;} public void setCategory(String category){this.category=category;}
}
EOF

cat > inventory-service/src/main/java/com/arka/inventory/model/StockHistory.java <<'EOF'
package com.arka.inventory.model;

import jakarta.persistence.*;
import java.time.Instant;
@Entity
@Table(name="stock_history")
public class StockHistory {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;
  private Long productId;
  private Integer qtyChange;
  private String reason;
  private Instant timestamp;
  public StockHistory(){}
  public Long getId(){return id;} public void setId(Long id){this.id=id;}
  public Long getProductId(){return productId;} public void setProductId(Long productId){this.productId=productId;}
  public Integer getQtyChange(){return qtyChange;} public void setQtyChange(Integer qtyChange){this.qtyChange=qtyChange;}
  public String getReason(){return reason;} public void setReason(String reason){this.reason=reason;}
  public Instant getTimestamp(){return timestamp;} public void setTimestamp(Instant timestamp){this.timestamp=timestamp;}
}
EOF

cat > inventory-service/src/main/java/com/arka/inventory/repository/ProductRepository.java <<'EOF'
package com.arka.inventory.repository;
import com.arka.inventory.model.Product;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
public interface ProductRepository extends JpaRepository<Product, Long> {
  List<Product> findByCategory(String category);
  List<Product> findByStockLessThan(Integer threshold);
}
EOF

cat > inventory-service/src/main/java/com/arka/inventory/repository/StockHistoryRepository.java <<'EOF'
package com.arka.inventory.repository;
import com.arka.inventory.model.StockHistory;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
public interface StockHistoryRepository extends JpaRepository<StockHistory, Long> {
  List<StockHistory> findByProductId(Long productId);
}
EOF

cat > inventory-service/src/main/java/com/arka/inventory/service/ProductService.java <<'EOF'
package com.arka.inventory.service;
import com.arka.inventory.model.Product;
import com.arka.inventory.model.StockHistory;
import com.arka.inventory.repository.ProductRepository;
import com.arka.inventory.repository.StockHistoryRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
@Service
public class ProductService {
  private final ProductRepository productRepository;
  private final StockHistoryRepository historyRepository;
  public ProductService(ProductRepository productRepository, StockHistoryRepository historyRepository){
    this.productRepository = productRepository;
    this.historyRepository = historyRepository;
  }
  public Product create(Product p){
    if(p.getPrice().doubleValue() < 0) throw new IllegalArgumentException("Price cannot be negative");
    if(p.getStock() < 0) throw new IllegalArgumentException("Stock cannot be negative");
    return productRepository.save(p);
  }
  @Transactional
  public Product updateStock(Long productId, int delta, String reason){
    Product prod = productRepository.findById(productId).orElseThrow(() -> new IllegalArgumentException("Product not found"));
    int newStock = prod.getStock() + delta;
    if(newStock < 0) throw new IllegalArgumentException("Stock cannot be negative");
    prod.setStock(newStock);
    productRepository.save(prod);
    StockHistory h = new StockHistory();
    h.setProductId(productId);
    h.setQtyChange(delta);
    h.setReason(reason);
    h.setTimestamp(Instant.now());
    historyRepository.save(h);
    return prod;
  }
  public Optional<Product> findById(Long id){ return productRepository.findById(id); }
  public List<Product> listAll(){ return productRepository.findAll(); }
  public List<Product> lowStock(Integer threshold) { return productRepository.findByStockLessThan(threshold); }
}
EOF

cat > inventory-service/src/main/java/com/arka/inventory/controller/ProductController.java <<'EOF'
package com.arka.inventory.controller;
import com.arka.inventory.model.Product;
import com.arka.inventory.service.ProductService;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import java.net.URI;
import java.util.List;
@RestController
@RequestMapping("/api/products")
public class ProductController {
  private final ProductService productService;
  public ProductController(ProductService productService){ this.productService = productService; }
  @PostMapping
  public ResponseEntity<Product> create(@Validated @RequestBody Product p){
    Product created = productService.create(p);
    return ResponseEntity.created(URI.create("/api/products/" + created.getId())).body(created);
  }
  @GetMapping
  public List<Product> list(){ return productService.listAll(); }
  @GetMapping("/{id}")
  public ResponseEntity<Product> get(@PathVariable Long id){
    return productService.findById(id).map(ResponseEntity::ok).orElse(ResponseEntity.notFound().build());
  }
  @PutMapping("/{id}/stock")
  public ResponseEntity<?> updateStock(@PathVariable Long id, @RequestParam int delta, @RequestParam(required=false) String reason){
    try{
      Product updated = productService.updateStock(id, delta, reason == null ? "manual" : reason);
      return ResponseEntity.ok(updated);
    }catch(IllegalArgumentException ex){
      return ResponseEntity.badRequest().body(ex.getMessage());
    }
  }
  @GetMapping("/low-stock")
  public List<Product> lowStock(@RequestParam(defaultValue = "10") Integer threshold){
    return productService.lowStock(threshold);
  }
}
EOF

cat > inventory-service/src/main/resources/application.yml <<'EOF'
server:
  port: 8081
spring:
  datasource:
    url: jdbc:postgresql://postgres-inventory:5432/inventorydb
    username: postgres
    password: postgres
  jpa:
    hibernate:
      ddl-auto: update
    show-sql: true
eureka:
  client:
    service-url:
      defaultZone: http://eureka:8761/eureka/
EOF

cat > inventory-service/Dockerfile <<'EOF'
FROM eclipse-temurin:17-jdk-jammy
WORKDIR /app
COPY target/*.jar app.jar
EXPOSE 8081
ENTRYPOINT ["java","-jar","/app/app.jar"]
EOF

# order-service pom + mains + models + client + service + controller + app.yml + dockerfile
cat > order-service/pom.xml <<'EOF'
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.arka</groupId>
  <artifactId>order-service</artifactId>
  <version>0.0.1-SNAPSHOT</version>
  <properties>
    <java.version>17</java.version>
    <spring.boot.version>3.1.6</spring.boot.version>
  </properties>
  <dependencies>
    <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-web</artifactId></dependency>
    <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-data-jpa</artifactId></dependency>
    <dependency><groupId>org.postgresql</groupId><artifactId>postgresql</artifactId><scope>runtime</scope></dependency>
    <dependency><groupId>org.springframework.cloud</groupId><artifactId>spring-cloud-starter-netflix-eureka-client</artifactId></dependency>
    <dependency><groupId>org.springframework.cloud</groupId><artifactId>spring-cloud-starter-openfeign</artifactId></dependency>
    <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-test</artifactId><scope>test</scope></dependency>
  </dependencies>
</project>
EOF

cat > order-service/src/main/java/com/arka/order/OrderApplication.java <<'EOF'
package com.arka.order;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.openfeign.EnableFeignClients;
@SpringBootApplication
@EnableDiscoveryClient
@EnableFeignClients
public class OrderApplication {
  public static void main(String[] args){ SpringApplication.run(OrderApplication.class, args); }
}
EOF

cat > order-service/src/main/java/com/arka/order/model/Order.java <<'EOF'
package com.arka.order.model;
import jakarta.persistence.*;
import java.time.Instant;
import java.util.List;
@Entity
@Table(name = "orders")
public class Order {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;
  private String customerEmail;
  private Instant createdAt;
  private String status;
  @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER)
  @JoinColumn(name="order_id")
  private List<OrderItem> items;
  private double total;
  public Order(){}
  public Long getId(){return id;} public void setId(Long id){this.id=id;}
  public String getCustomerEmail(){return customerEmail;} public void setCustomerEmail(String customerEmail){this.customerEmail=customerEmail;}
  public Instant getCreatedAt(){return createdAt;} public void setCreatedAt(Instant createdAt){this.createdAt=createdAt;}
  public String getStatus(){return status;} public void setStatus(String status){this.status=status;}
  public List<OrderItem> getItems(){return items;} public void setItems(List<OrderItem> items){this.items=items;}
  public double getTotal(){return total;} public void setTotal(double total){this.total=total;}
}
EOF

cat > order-service/src/main/java/com/arka/order/model/OrderItem.java <<'EOF'
package com.arka.order.model;
import jakarta.persistence.*;
@Entity
@Table(name="order_items")
public class OrderItem {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;
  private Long productId;
  private Integer quantity;
  private Double price;
  public OrderItem(){}
  public Long getId(){return id;} public void setId(Long id){this.id=id;}
  public Long getProductId(){return productId;} public void setProductId(Long productId){this.productId=productId;}
  public Integer getQuantity(){return quantity;} public void setQuantity(Integer quantity){this.quantity=quantity;}
  public Double getPrice(){return price;} public void setPrice(Double price){this.price=price;}
}
EOF

cat > order-service/src/main/java/com/arka/order/clients/InventoryClient.java <<'EOF'
package com.arka.order.clients;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.*;
@FeignClient(name = "inventory-service")
public interface InventoryClient {
  @PutMapping("/api/products/{id}/stock")
  void updateStock(@PathVariable("id") Long id, @RequestParam("delta") int delta, @RequestParam(value="reason", required=false) String reason);
}
EOF

cat > order-service/src/main/java/com/arka/order/service/OrderService.java <<'EOF'
package com.arka.order.service;
import com.arka.order.clients.InventoryClient;
import com.arka.order.model.Order;
import com.arka.order.model.OrderItem;
import com.arka.order.repository.OrderRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.Instant;
@Service
public class OrderService {
  private final OrderRepository orderRepository;
  private final InventoryClient inventoryClient;
  public OrderService(OrderRepository orderRepository, InventoryClient inventoryClient){
    this.orderRepository = orderRepository;
    this.inventoryClient = inventoryClient;
  }
  @Transactional
  public Order createOrder(Order order){
    order.setStatus("PENDING");
    order.setCreatedAt(Instant.now());
    double total = 0;
    if(order.getItems() != null){
      for(OrderItem it : order.getItems()) total += it.getQuantity() * it.getPrice();
    }
    order.setTotal(total);
    Order saved = orderRepository.save(order);
    try {
      if(saved.getItems() != null){
        for(OrderItem it : saved.getItems()){
          inventoryClient.updateStock(it.getProductId(), - it.getQuantity(), "reserve-order-" + saved.getId());
        }
      }
      saved.setStatus("CONFIRMED");
      orderRepository.save(saved);
    } catch (Exception ex) {
      if(saved.getItems() != null){
        for(OrderItem it : saved.getItems()){
          try { inventoryClient.updateStock(it.getProductId(), it.getQuantity(), "compensate-order-" + saved.getId()); }
          catch(Exception e){}
        }
      }
      saved.setStatus("CANCELLED");
      orderRepository.save(saved);
      throw new RuntimeException("Reservation failed: " + ex.getMessage());
    }
    return saved;
  }
}
EOF

cat > order-service/src/main/java/com/arka/order/controller/OrderController.java <<'EOF'
package com.arka.order.controller;
import com.arka.order.model.Order;
import com.arka.order.service.OrderService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
@RestController
@RequestMapping("/api/orders")
public class OrderController {
  private final OrderService orderService;
  public OrderController(OrderService orderService){ this.orderService = orderService; }
  @PostMapping
  public ResponseEntity<?> create(@RequestBody Order order){
    try {
      Order o = orderService.createOrder(order);
      return ResponseEntity.status(201).body(o);
    } catch (RuntimeException ex){
      return ResponseEntity.status(409).body(ex.getMessage());
    }
  }
}
EOF

cat > order-service/src/main/resources/application.yml <<'EOF'
server:
  port: 8082
spring:
  datasource:
    url: jdbc:postgresql://postgres-order:5432/orderdb
    username: postgres
    password: postgres
  jpa:
    hibernate:
      ddl-auto: update
    show-sql: true
eureka:
  client:
    service-url:
      defaultZone: http://eureka:8761/eureka/
EOF

cat > order-service/Dockerfile <<'EOF'
FROM eclipse-temurin:17-jdk-jammy
WORKDIR /app
COPY target/*.jar app.jar
EXPOSE 8082
ENTRYPOINT ["java","-jar","/app/app.jar"]
EOF

# auth-service skeleton (README + basic config)
cat > auth-service/README.md <<'EOF'
Auth-service (JWT)

Endpoints:
- POST /auth/register
- POST /auth/login
- POST /auth/refresh

En desarrollo: H2 posible; en producción: Postgres/Secrets Manager.
EOF

# notification-service skeleton
cat > notification-service/README.md <<'EOF'
Notification-service skeleton:
- AWS SES for emails (placeholder)
- SNS publish/subscriptions
- S3 for report storage
EOF

# review-service skeleton
cat > review-service/src/main/java/com/arka/review/ReviewApplication.java <<'EOF'
package com.arka.review;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
@SpringBootApplication
public class ReviewApplication {
  public static void main(String[] args){ SpringApplication.run(ReviewApplication.class, args); }
}
EOF

cat > review-service/src/main/resources/application.yml <<'EOF'
server:
  port: 8090
spring:
  data:
    mongodb:
      uri: mongodb://localhost:27017/reviewsdb
eureka:
  client:
    service-url:
      defaultZone: http://eureka:8761/eureka/
EOF

# Simple Dockerfile placeholders for auth/notification/review/bffs
for svc in auth-service notification-service catalog-bff-web catalog-bff-mobile review-service; do
  cat > $svc/Dockerfile <<EOF
FROM eclipse-temurin:17-jdk-jammy
WORKDIR /app
COPY target/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java","-jar","/app/app.jar"]
EOF
done

echo "Generación completada. Revisa los archivos creados, compila JARs con Maven y ejecuta docker-compose up --build"
echo "Para finalizar: git add . && git commit -m \"Add ARKA backend code\" && git push origin main"