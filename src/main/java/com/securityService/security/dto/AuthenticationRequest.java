package com.securityService.security.dto;


import lombok.Data;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@Data
public class AuthenticationRequest {
    private String email;
    private String password;

}
