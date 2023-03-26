package com.securityService.security.config;


import com.nimbusds.jwt.JWTParser;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

@Component
public class JwtUtils {
    private String jwtSigningKey = "secret";

    public String extractUserName(String token){
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token){
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsTFunction){
        final Claims claims = extractAllClaims(token);
        return claimsTFunction.apply(claims);
    }
    private Claims extractAllClaims(String token){
        return Jwts.parser().setSigningKey(jwtSigningKey).parseClaimsJws(token).getBody();//TODO
    }

    private Boolean isTokenExpired(String token){
        return extractExpiration(token).before(new Date());
    }

    public boolean hasClain(String token,String claimName){
        final Claims claims = extractAllClaims(token);
        return claims.get(claimName) != null;
    }

    public Boolean isTokenValid(String token, UserDetails userDetails){
        final String userName = extractUserName(token);
        return (userName.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    private String createToken(Map<String, Object> claims, UserDetails userDetails){
        return Jwts.builder().setClaims(claims)
                .setSubject(userDetails.getUsername())
                .claim("authorities",userDetails.getAuthorities())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+ TimeUnit.HOURS.toMillis(744))) //token expirs after a month
                .signWith(SignatureAlgorithm.HS256, jwtSigningKey).compact();
    }
    public String generateToken(Map<String,Object> claims, UserDetails userDetails){
            return createToken(claims,userDetails);
    }

    public String generateToken(UserDetails userDetails){
        Map<String, Object> claims  = new HashMap<>();
        return createToken(claims,userDetails);
    }
}
