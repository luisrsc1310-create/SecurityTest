package com.example.gymsecurity.API.Services;

import com.example.gymsecurity.API.DTOs.CreateUserDTO;
import com.example.gymsecurity.API.DTOs.LoginUserDto;
import com.example.gymsecurity.API.DTOs.RecoveryJwtTokenDto;
import com.example.gymsecurity.API.Entity.Role;
import com.example.gymsecurity.API.Entity.RoleName;
import com.example.gymsecurity.API.Repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import com.example.gymsecurity.API.Entity.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;


@Service
public class UserService {

    private final AuthenticationManager authenticationManager;
    private final JwtTokenService jwtTokenService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(
            AuthenticationManager authenticationManager,
            JwtTokenService jwtTokenService,
            UserRepository userRepository,
            PasswordEncoder passwordEncoder
    ) {
        this.authenticationManager = authenticationManager;
        this.jwtTokenService = jwtTokenService;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    // Método responsável por autenticar um usuário e retornar um token JWT
    public RecoveryJwtTokenDto authenticateUser(LoginUserDto loginUserDto) {

        System.out.println("EMAIL RECEBIDO: " + loginUserDto.email());
        System.out.println("USER EXISTE: " +
                userRepository.findByEmail(loginUserDto.email()).isPresent());

        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(
                        loginUserDto.email(),
                        loginUserDto.password()
                );

        Authentication authentication =
                authenticationManager.authenticate(authenticationToken);

        UserDetailsImpl userDetails =
                (UserDetailsImpl) authentication.getPrincipal();

        return new RecoveryJwtTokenDto(
                jwtTokenService.generateToken(userDetails)
        );
    }

    // Método responsável por criar um usuário
    public void createUser(CreateUserDTO createUserDto) {

        // Cria um novo usuário
        User newUser = User.builder()
                .email(createUserDto.email())

                // Criptografa a senha utilizando BCrypt
                .password(
                        passwordEncoder.encode(createUserDto.password())
                )

                // Usuários cadastrados normalmente recebem a role CUSTOMER
                .roles(List.of(
                        Role.builder()
                                .name(RoleName.valueOf("ROLE_CUSTOMER"))
                                .build()
                ))
                .build();

        // Salva o usuário no banco de dados
        userRepository.save(newUser);
    }
}
