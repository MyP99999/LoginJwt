package com.example.EvidenNewsAggregator.auth;

import com.example.EvidenNewsAggregator.entities.tables.pojos.Users;
import com.example.EvidenNewsAggregator.jwt.JwtService;
import com.example.EvidenNewsAggregator.user.UserDetailServiceImp;
import com.example.EvidenNewsAggregator.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final UserDetailServiceImp userDetailServiceImp;
    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    public AuthenticationResponse register(RegisterRequest request) {
        // Check if the user already exists
        Users existingUser = userRepository.findByUsername(request.getUsername());
        if (existingUser != null) {
            throw new RuntimeException("User with the same username already exists.");
        }

        // Create a new user
        Users newUser = new Users();
        newUser.setUsername(request.getUsername());
        String encodedPassword = passwordEncoder.encode(request.getPassword());
        newUser.setPassword(encodedPassword);
        // Set other user properties as needed
        newUser.setRoleId(1); // Assuming you have a "role" field in your Users class

        // Save the new user to the database
        userRepository.add(newUser);

        // Authenticate the new user
        UserDetails userDetails = userDetailServiceImp.loadUserByUsername(newUser.getUsername());

        // Generate a JWT token for the new user
        String jwtToken = jwtService.generateToken(userDetails);

        return AuthenticationResponse.builder().token(jwtToken).build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );

        UserDetails userDetails = userDetailServiceImp.loadUserByUsername(request.getUsername());
        String jwtToken = jwtService.generateToken(userDetails);

        return AuthenticationResponse.builder().token(jwtToken).build();
    }
}
