package com.example.gymsecurity.API.DTOs;


import com.example.gymsecurity.API.Entity.RoleName;

public record CreateUserDTO  (
        String email,
        String password,
        RoleName role
) {

}
