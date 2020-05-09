package com.jwtexample.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jwtexample.util.AuthReq;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;

public class AuthFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    public AuthFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {
        try {
            AuthReq authenticationRequest = new ObjectMapper()
                    .readValue(request.getInputStream(), AuthReq.class);
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    authenticationRequest.getUsername(),
                    authenticationRequest.getPassword()
            );

            return authenticationManager.authenticate(authentication);
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {
        try {
            Algorithm algorithm = Algorithm.HMAC256("secret");

            String token = JWT.create()
                    .withIssuer("spring")
                    .withClaim("NAME", authResult.getName())
                    .withClaim("ROLES", authResult.getAuthorities().toString())
                    .withExpiresAt(
                            Date.from(LocalDate.now().plusWeeks(2)
                                    .atStartOfDay(ZoneId.systemDefault())
                                    .toInstant())
                    )
                    .sign(algorithm);
            response.setHeader("Authorization", "Bearer " + token);
        } catch (JWTCreationException exception) {
            // JWT Token Conversion Exception.
            throw new JWTCreationException("Could not convert Claims ! ", exception);
        }
    }
}
