package com.platzi.pizza.service;

import com.platzi.pizza.persistence.entity.UserEntity;
import com.platzi.pizza.persistence.entity.UserRoleEntity;
import com.platzi.pizza.persistence.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserSecurityService implements UserDetailsService {

    private final UserRepository userRepository;

    @Autowired
    public UserSecurityService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserEntity userEntity = userRepository.findById(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        String[] roles = userEntity.getRoles().stream().map(UserRoleEntity::getRole).toArray(String[]::new);

        // Construir un UserDetails usando los valores de userEntity
        return User.builder()
                .username(userEntity.getUsername())
                .password(userEntity.getPassword())
                .roles(roles) // Temporalmente se asigna el rol de 'admin'
                .accountLocked(userEntity.getLocked())
                .disabled(userEntity.getDisabled())
                .build();
    }
}