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

        // Cria um objeto de autenticação com o email e a senha do usuário
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(
                        loginUserDto.email(),
                        loginUserDto.password()
                );

        // Autentica o usuário com as credenciais fornecidas
        Authentication authentication =
                authenticationManager.authenticate(authenticationToken);

        // Obtém o usuário autenticado
        UserDetailsImpl userDetails =
                (UserDetailsImpl) authentication.getPrincipal();

        // Gera o token JWT
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
                                .name(RoleName.valueOf("CUSTOMER"))
                                .build()
                ))
                .build();

        // Salva o usuário no banco de dados
        userRepository.save(newUser);
    }
}
