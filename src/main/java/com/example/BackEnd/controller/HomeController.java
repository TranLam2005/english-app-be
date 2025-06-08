package com.example.BackEnd.controller;

import com.example.BackEnd.entity.User;
import com.example.BackEnd.security.ConfigSecurity;
import com.example.BackEnd.security.JwtUtil;
import com.example.BackEnd.services.UserService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;

@RestController
public class HomeController {
    private final UserService userService;
    private final ConfigSecurity configSecurity;
    private final JwtUtil jwtUtil;
    public HomeController(UserService userService, ConfigSecurity configSecurity, JwtUtil jwtUtil) {
        this.userService = userService;
        this.configSecurity = configSecurity;
        this.jwtUtil = jwtUtil;
    }
    @GetMapping("/")
    public ResponseEntity<?> getUsers () throws Exception {
        try {
            return ResponseEntity.ok(userService.GetAllUsers());
        }
        catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }
    @PostMapping("/login")
    public ResponseEntity<?> logIn (@RequestBody User user) {
        if(userService.exitsByUserName(user.getUsername())) {
            User userInDataBase = userService.GetUserByUserName(user.getUsername());
            if(configSecurity.passwordEncoder().matches(user.getPassword(), userInDataBase.getPassword())) {
                String token = jwtUtil.generateToken(user.getUsername());
                return ResponseEntity.ok(token);
            }
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
    @PostMapping("/logout")
    public ResponseEntity<?> logOut (HttpServletResponse response) {
        System.out.println("logout");
        Cookie cookie = new Cookie("access_token", null);
        cookie.setHttpOnly(true);
        cookie.setMaxAge(0);
        cookie.setPath("/");
        cookie.setSecure(true);
        response.addCookie(cookie);
        return ResponseEntity.ok().build();
    }
    @GetMapping("/get-access_token")
    public ResponseEntity<?> getAccessToken(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("access_token")) {
                    return ResponseEntity.ok(cookie.getValue());
                }
            }
        }
        return ResponseEntity.badRequest().build();
    }
    @PostMapping("/registry")
    public ResponseEntity<?> registry (@RequestBody User user) {
        System.out.println("username: "+ user.getUsername());
        if (!userService.exitsByUserName(user.getUsername()) && !userService.exitsByEmail(user.getEmail())) {
            User createUser = new User();
            createUser.setUsername(user.getUsername());
            createUser.setEmail(user.getEmail());
            createUser.setPassword(configSecurity.passwordEncoder().encode(user.getPassword()));
            createUser.setCreateAt(Instant.now());
            userService.add(createUser);
            return ResponseEntity.ok().build();
        }
        else if (userService.exitsByEmail(user.getEmail())) {
            return ResponseEntity.badRequest().body("Email is already in system");
        }
        return ResponseEntity.badRequest().body("User is already in system");
    }
}
