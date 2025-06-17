package com.example.jwtauth.controller;

import com.example.jwtauth.dto.AuthResponse;
import com.example.jwtauth.dto.LoginRequest;
import com.example.jwtauth.dto.RegisterRequest;
import com.example.jwtauth.model.User;
import com.example.jwtauth.repository.UserRepository;
import com.example.jwtauth.security.JwtUtils;
import com.example.jwtauth.service.UserDetailsServiceImpl;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
@Tag(name = "Authentication", description = "Authentication")
public class AuthController {
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;

    @PostMapping("/register")
    @Operation(summary = "registro de usuario", description = "registra novo usuario")
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegisterRequest signUpRequest) {
        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body("Error: Email em uso!");
        }
        User user = new User(signUpRequest.getName(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()),
                signUpRequest.getRole());

        userRepository.save(user);

        return ResponseEntity.ok("Usuario registrado com sucesso!");
    }

    @PostMapping("/login")
    @Operation(summary = "User login", description = "Login de usuario")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        UserDetailsServiceImpl.UserPrincipal userDetails = (UserDetailsServiceImpl.UserPrincipal) authentication.getPrincipal();
        User user = userRepository.findByEmail(userDetails.getUsername()).orElse(null);

        return ResponseEntity.ok(new AuthResponse(jwt,
                userDetails.getId(),
                userDetails.getName(),
                userDetails.getUsername(),
                user.getRole()));
    }
}

