package cl.nava.springsecurityjwt.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtGenerador {

    // Method for creating a token by authentication
    public String generateToken(Authentication authentication){
        String userName = authentication.getName();
        Date actualTime = new Date();
        Date tokenExpiration = new Date(actualTime.getTime() + SecurityConstants.JWT_EXPIRATION_TOKEN);

        // Line to generate the token
        return Jwts.builder()
                .setSubject(userName)
                .setIssuedAt(new Date())
                .setExpiration(tokenExpiration)
                .signWith(SignatureAlgorithm.HS512, SecurityConstants.JWT_SIGNATURE)
                .compact();
    }

    // Method to extract a username from a token
    public String getUserNameFromJwt(String token){
        Claims claims= Jwts.parser()
                .setSigningKey(SecurityConstants.JWT_SIGNATURE)
                .parseClaimsJws(token)
                .getBody();
        return claims.getSubject();
    }

    // Method to validate the token
    public boolean validateToken(String token){
        try {
            Jwts.parser().setSigningKey(SecurityConstants.JWT_SIGNATURE).parseClaimsJws(token);
            return true;
        }catch (Exception e){
            throw new AuthenticationCredentialsNotFoundException("Jwt has expired or is incorrect");
        }
    }
}
