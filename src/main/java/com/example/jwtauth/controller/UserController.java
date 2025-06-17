package com.example.jwtauth.controller;

import com.example.jwtauth.model.User;
import com.example.jwtauth.repository.UserRepository;
import com.example.jwtauth.service.UserDetailsServiceImpl;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/user")
@Tag(name = "Usuario", description = "Usuario")
@SecurityRequirement(name = "bearerAuth")
public class UserController {
    @Autowired
    UserRepository userRepository;

    @Autowired
    PasswordEncoder encoder;

    @PutMapping("/profile")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    @Operation(summary = "Atualizar perfil", description = "Atualizar perfil logado")
    public ResponseEntity<?> updateUserProfile(@RequestBody User updatedUser, Authentication authentication) {
        UserDetailsServiceImpl.UserPrincipal userPrincipal = (UserDetailsServiceImpl.UserPrincipal) authentication.getPrincipal();
        Optional<User> userOpt = userRepository.findByEmail(userPrincipal.getUsername());
        
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            
            if (updatedUser.getName() != null) {
                user.setName(updatedUser.getName());
            }
            
            if (updatedUser.getPassword() != null && !updatedUser.getPassword().isEmpty()) {
                user.setPassword(encoder.encode(updatedUser.getPassword()));
            }
            
            userRepository.save(user);

            user.setPassword(null);
            return ResponseEntity.ok(user);
        }
        
        return ResponseEntity.notFound().build();
    }

    @GetMapping("/perfil")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    @Operation(summary = "Pega usuario logado")
    public ResponseEntity<?> getUserProfile(Authentication authentication) {
        UserDetailsServiceImpl.UserPrincipal userPrincipal = (UserDetailsServiceImpl.UserPrincipal) authentication.getPrincipal();
        Optional<User> user = userRepository.findByEmail(userPrincipal.getUsername());

        if (user.isPresent()) {
            User u = user.get();
            u.setPassword(null);
            return ResponseEntity.ok(u);
        }

        return ResponseEntity.notFound().build();
    }
}

