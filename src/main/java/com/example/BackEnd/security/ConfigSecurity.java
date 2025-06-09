package com.example.BackEnd.security;
import com.example.BackEnd.entity.User;
import com.example.BackEnd.services.UserService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import java.util.Arrays;
import java.util.List;

@Configuration
public class ConfigSecurity {
    private final JwtUtil jwtUtil;
    private final UserService userService;
    private  final JwtAuth jwtAuth;
    public ConfigSecurity(JwtUtil jwtUtil, UserService userService, JwtAuth jwtAuth) {
        this.jwtUtil = jwtUtil;
        this.userService = userService;
        this.jwtAuth = jwtAuth;
    }
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(cors -> cors.configurationSource(request -> {
                    CorsConfiguration corsConfiguration = new CorsConfiguration();
                    corsConfiguration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
                    corsConfiguration.setAllowCredentials(true);
                    corsConfiguration.setAllowedOrigins(List.of("http://localhost:3000", "https://english-app-sigma-nine.vercel.app"));
                    corsConfiguration.setAllowedHeaders(List.of("*"));
                    return corsConfiguration;
                }))
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> {
                    auth
                            .requestMatchers("/login").permitAll()
                            .requestMatchers("/registry").permitAll()
                            .requestMatchers("/").authenticated()
                            .requestMatchers("/logout").permitAll()
                            .requestMatchers("/get-access_token").authenticated()
                            .anyRequest().authenticated();
                })
                .formLogin(AbstractHttpConfigurer::disable)


                .oauth2Login(oAuth2Login -> {
                    oAuth2Login
                            .successHandler(successHandler())
                            .permitAll();
                })
                .addFilterBefore(jwtAuth, UsernamePasswordAuthenticationFilter.class)
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                        .maximumSessions(1)
                        .expiredUrl("/login?expired")
                );
        return http.build();
    }
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    @Bean
    public AuthenticationManager authenticationManager (AuthenticationConfiguration authenticationConfiguration) throws  Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
    @Bean
    public AuthenticationSuccessHandler successHandler() {
        return (request, response, authentication) -> {
            OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
            String email = oAuth2User.getAttribute("email");
            String token = jwtUtil.generateToken(email);
            Cookie jwtCookie = new Cookie("access_token", token);
            jwtCookie.setHttpOnly(false);
            jwtCookie.setSecure(true);
            jwtCookie.setPath("/");
            jwtCookie.setMaxAge(24*60*60);
            response.addCookie(jwtCookie);
            if (!userService.exitsByUserName(email)) {
                User user = new User();
                user.setUsername(email);
                user.setPassword(passwordEncoder().encode("123456789"));
                user.setEmail(email);
                user.setRole("User");
                userService.add(user);
            }
            response.sendRedirect("https://english-app-sigma-nine.vercel.app/");
        };
    }
}
