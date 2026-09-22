package com.example.gymsecurity.API.DTOs;

import com.example.gymsecurity.API.Entity.Role;

import java.util.List;

public record RecoveryUserDto(

        Long id,
        String email,
        List<Role> roles

) {
}
