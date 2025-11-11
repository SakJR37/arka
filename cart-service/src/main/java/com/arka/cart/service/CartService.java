package com.arka.cart.service;

import com.arka.cart.model.Cart;
import com.arka.cart.model.CartItem;
import com.arka.cart.repository.CartRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.Optional;

@Service
public class CartService {
  private final CartRepository cartRepository;

  public CartService(CartRepository cartRepository) {
    this.cartRepository = cartRepository;
  }

  @Transactional
  public Cart getOrCreateCart(Long userId) {
    return cartRepository.findByUserId(userId)
      .orElseGet(() -> {
        Cart cart = new Cart();
        cart.setUserId(userId);
        return cartRepository.save(cart);
      });
  }

  @Transactional
  public Cart addItem(Long userId, CartItem item) {
    Cart cart = getOrCreateCart(userId);
    
    Optional<CartItem> existing = cart.getItems().stream()
      .filter(i -> i.getProductId().equals(item.getProductId()))
      .findFirst();
    
    if (existing.isPresent()) {
      existing.get().setQuantity(existing.get().getQuantity() + item.getQuantity());
    } else {
      cart.getItems().add(item);
    }
    
    return cartRepository.save(cart);
  }

  @Transactional
  public Cart removeItem(Long userId, Long productId) {
    Cart cart = getOrCreateCart(userId);
    cart.getItems().removeIf(item -> item.getProductId().equals(productId));
    return cartRepository.save(cart);
  }

  @Transactional
  public Cart updateItemQuantity(Long userId, Long productId, Integer quantity) {
    Cart cart = getOrCreateCart(userId);
    cart.getItems().stream()
      .filter(item -> item.getProductId().equals(productId))
      .findFirst()
      .ifPresent(item -> item.setQuantity(quantity));
    return cartRepository.save(cart);
  }

  @Transactional
  public void clearCart(Long userId) {
    cartRepository.findByUserId(userId).ifPresent(cart -> {
      cart.getItems().clear();
      cartRepository.save(cart);
    });
  }

  public Optional<Cart> findByUserId(Long userId) {
    return cartRepository.findByUserId(userId);
  }
}
