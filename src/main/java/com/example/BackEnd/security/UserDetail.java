package com.example.BackEnd.security;

import com.example.BackEnd.entity.User;
import com.example.BackEnd.services.UserService;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.Collections;


@Component
public class UserDetail implements UserDetailsService {
    private final UserService userService;
    public UserDetail(UserService userService) {
        this.userService = userService;
    }
    @Override
    public UserDetails loadUserByUsername (String username) throws UsernameNotFoundException {
        User user = userService.GetUserByUserName(username);
        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + user.getRole()))
        );
    }
}
