package com.jewellery.server_app.service;

import com.jewellery.server_app.model.User;
import com.jewellery.server_app.repository.RoleRepository;
import com.jewellery.server_app.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthService {

  @Autowired
  private UserRepository userRepository;

  @Autowired
  private RoleRepository roleRepository;

  @Autowired
  private PasswordEncoder passwordEncoder;

  public boolean existsByEmail(String email) {
    return userRepository.existsByEmail(email);
  }

  public User saveUser(User user) {
    user.setPassword(passwordEncoder.encode(user.getPassword()));
    return userRepository.save(user);
  }

  public Optional<User> findByEmail(String email) {
    return userRepository.findByEmail(email);
  }

  public Optional<User> getUserByEmail(String email) {
    return userRepository.findByEmail(email);
  }

  public Optional<User> getUserByEmailOrPhoneNumber(String phoneNumber) {
    return userRepository.getUserByEmailOrPhoneNumber(phoneNumber);
  }
}
