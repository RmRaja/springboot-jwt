package com.jwtexample.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String token = request.getHeader("Authorization");
        if (StringUtils.isEmpty(token) || !token.substring(0, 7).equals("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        try {
            token = token.substring(7);
            Algorithm algorithm = Algorithm.HMAC256("secret");
            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer("spring")
                    .build(); //Reusable verifier instance
            DecodedJWT jwt = verifier.verify(token);
            String username = jwt.getSubject();
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    username,
                    null,
                    jwt.getClaim("ROLES").asList(GrantedAuthority.class)
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);

        } catch (JWTDecodeException e) {
            // Invalid JWT Token.
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        }
        filterChain.doFilter(request, response);
    }
}
