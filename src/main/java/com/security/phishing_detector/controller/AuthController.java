package com.security.phishing_detector.controller;

import java.util.Optional;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.security.phishing_detector.domain.User;
import com.security.phishing_detector.dto.AuthRequest;
import com.security.phishing_detector.dto.AuthResponse;
import com.security.phishing_detector.security.JwtUtil;
import com.security.phishing_detector.service.UserService;

@RestController
@RequestMapping("/api/v1/auth")
@CrossOrigin(origins = "*")
public class AuthController {

    private final UserService userService;
    private final JwtUtil jwtUtil;

    public AuthController(UserService userService, JwtUtil jwtUtil) {
        this.userService = userService;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@RequestBody AuthRequest request) {
        try {
            User user = userService.registerUser(request.getUsername(), request.getEmail(), request.getPassword());
            String token = jwtUtil.generateToken(user.getUsername());
            return ResponseEntity.ok(new AuthResponse(token, user.getUsername()));
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(new AuthResponse(e.getMessage()));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody AuthRequest request) {
        Optional<User> userOpt = userService.findByUsername(request.getUsername());
        if (userOpt.isPresent() && userService.validatePassword(request.getPassword(), userOpt.get().getPassword())) {
            String token = jwtUtil.generateToken(request.getUsername());
            return ResponseEntity.ok(new AuthResponse(token, request.getUsername()));
        } else {
            return ResponseEntity.badRequest().body(new AuthResponse("Invalid credentials"));
        }
    }
}