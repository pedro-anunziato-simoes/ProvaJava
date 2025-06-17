package com.example.jwtauth.controller;

import com.example.jwtauth.model.User;
import com.example.jwtauth.repository.UserRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/admin")
@Tag(name = "Admin", description = "Admin")
@SecurityRequirement(name = "bearerAuth")
public class AdminController {
    @Autowired
    UserRepository userRepository;

    @Autowired
    PasswordEncoder encoder;


    @PutMapping("/users/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Atualizar usuario", description = "Atualizar informacoes(Admin)")
    public ResponseEntity<?> updateUser(@PathVariable Long id, @RequestBody User updatedUser) {
        Optional<User> userOpt = userRepository.findById(id);
        
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            
            if (updatedUser.getName() != null) {
                user.setName(updatedUser.getName());
            }
            
            if (updatedUser.getEmail() != null) {
                user.setEmail(updatedUser.getEmail());
            }
            
            if (updatedUser.getPassword() != null && !updatedUser.getPassword().isEmpty()) {
                user.setPassword(encoder.encode(updatedUser.getPassword()));
            }
            
            if (updatedUser.getRole() != null) {
                user.setRole(updatedUser.getRole());
            }
            
            userRepository.save(user);
            
            // Remove password from response
            user.setPassword(null);
            return ResponseEntity.ok(user);
        }
        
        return ResponseEntity.notFound().build();
    }

    @DeleteMapping("/users/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Delete user", description = "Deleta usuario por ID (Admin)")
    public ResponseEntity<?> deleteUser(@PathVariable Long id) {
        if (userRepository.existsById(id)) {
            userRepository.deleteById(id);
            return ResponseEntity.ok("Usuario deletado com sucesso!");
        }
        return ResponseEntity.notFound().build();
    }

    @GetMapping("/users")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Lista todos usuarios", description = "Lista todos usarios(Admin)")
    public ResponseEntity<List<User>> getAllUsers() {
        List<User> users = userRepository.findAll();
        users.forEach(user -> user.setPassword(null));
        return ResponseEntity.ok(users);
    }

    @GetMapping("/users/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Lista usuarios", description = "Lista usuarios por ID (Admin)")
    public ResponseEntity<?> getUserById(@PathVariable Long id) {
        Optional<User> user = userRepository.findById(id);
        if (user.isPresent()) {
            User u = user.get();
            u.setPassword(null);
            return ResponseEntity.ok(u);
        }
        return ResponseEntity.notFound().build();
    }

}

