package com.platzi.pizza.persistence.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Entity
@Table(name="user", schema = "pizzeria")
@Getter
@Setter
@NoArgsConstructor
public class UserEntity {

    @Id
    @Column(nullable = false,length = 20)
    private String username;

    @Column(nullable = false,length = 200)
    private String password;

    @Column(length = 50)
    private String email;

    @Column(nullable = false)
    private Boolean locked;

    @Column(nullable = false)
    private Boolean disabled;

    @OneToMany(mappedBy = "user", fetch=FetchType.EAGER)
    private List<UserRoleEntity> roles;
}
