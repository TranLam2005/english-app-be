package com.example.BackEnd.services;

import com.example.BackEnd.entity.User;
import com.example.BackEnd.repository.UserRepository;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {
    private final UserRepository userRepository;
    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }
    public List<User> GetAllUsers() {
        return userRepository.getAllUsers();
    }
    public User GetUserByUserName(String userName) {
        return userRepository.findByUsername(userName);
    }


    public boolean exitsByUserName(String userName) {
        return userRepository.existsByUsername(userName);
    }

    public void add(User user) {
        userRepository.save(user);
    }

    public boolean exitsByEmail(String email) {
        return userRepository.existsByEmail(email);
    }
}
