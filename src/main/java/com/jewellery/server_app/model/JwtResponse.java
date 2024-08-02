package com.jewellery.server_app.model;

import java.util.List;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class JwtResponse {
    private String token;
    private String email;
    private String firstName;
    private String lastName;
    private String profession;
    private String country;
    private List<String> roles;

    public JwtResponse(String token, String email, String firstName, String lastName, String profession, String country, List<String> roles) {
        this.token = token;
        this.email = email;
        this.firstName = firstName;
        this.lastName = lastName;
        this.profession = profession;
        this.country = country;
        this.roles = roles;
    }
}
