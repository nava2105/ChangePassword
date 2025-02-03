package cl.nava.springsecurityjwt.controllers;

import cl.nava.springsecurityjwt.dtos.*;
import cl.nava.springsecurityjwt.factories.IUserFactory;
import cl.nava.springsecurityjwt.models.UsersModel;
import cl.nava.springsecurityjwt.security.JwtGenerador;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;

@RestController
@RequestMapping("/api/auth/")
public class RestControllerAuth {
    private final PasswordEncoder passwordEncoder;
    private final IUserFactory userFactory;
    private final JwtGenerador jwtGenerador;

    @Autowired
    public RestControllerAuth(PasswordEncoder passwordEncoder, IUserFactory userFactory, JwtGenerador jwtGenerador) {
        this.passwordEncoder = passwordEncoder;
        this.userFactory = userFactory;
        this.jwtGenerador = jwtGenerador;
    }

    // Method to update password from user ID stored in token
    @PostMapping("password/update")
    public ResponseEntity<String> updatePassword(HttpServletRequest request, @RequestBody DtoChangePassword dtoChangePassword) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return new ResponseEntity<>("Missing or invalid Authorization header", HttpStatus.BAD_REQUEST);
        }
        String token = authHeader.substring(7);
        try {
            if (!jwtGenerador.validateToken(token)) {
                return new ResponseEntity<>("Invalid token", HttpStatus.UNAUTHORIZED);
            }
            String username = jwtGenerador.getUserNameFromJwt(token);
            UsersModel user = userFactory.findByUserName(username)
                    .orElseThrow(() -> new IllegalArgumentException("User not found"));
            String encodedPassword = passwordEncoder.encode(dtoChangePassword.getPassword());
            user.setPassword(encodedPassword);
            userFactory.update(user);
            return new ResponseEntity<>("Password updated successfully", HttpStatus.OK);
        } catch (Exception ex) {
            return new ResponseEntity<>("Error updating password: " + ex.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}