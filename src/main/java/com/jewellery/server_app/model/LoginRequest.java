package com.jewellery.server_app.model;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class LoginRequest {
        // @Email
        @NotBlank
        private String email;

    
        @NotBlank
        private String password;
    
        // Getters and setters
    
    
    
}
