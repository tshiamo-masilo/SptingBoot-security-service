package com.securityService.security.controller;

import com.securityService.security.config.JwtUtils;
import com.securityService.security.dto.AuthenticationRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final JwtUtils jwtUtils;


    @PostMapping("/authentication")
    public ResponseEntity<String> authentication(@RequestBody AuthenticationRequest request){
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),request.getPassword())
        );
        final UserDetails user = userDetailsService.loadUserByUsername(request.getEmail());
        if(user != null){
            return ResponseEntity.ok(jwtUtils.generateToken(user));
        }
        return ResponseEntity.status(400).body("User does not exist");
    }
}
