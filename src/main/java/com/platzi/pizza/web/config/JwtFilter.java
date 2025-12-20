package com.platzi.pizza.web.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.hibernate.annotations.Comment;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class JwtFilter {

    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;

    @Autowired
    public JwtFilter(JwtUtil jwtUtil, UserDetailsService userDetailsService) {
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
    }

    protected void doFilterInternal(HttpServletRequest request , HttpServletResponse response , FilterChain filterChain)throws ServletException, IOException{
        //1. Validar que sea un Header Authorization valido
        String autHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if(autHeader==null || autHeader.isEmpty() || !autHeader.startsWith("Bearer")){
            filterChain.doFilter(request,response);
            return;
        }
        //2. Validar que el JWT sea valido
        String jwt = autHeader.split(" ")[1].trim();

        if (!this.jwtUtil.isValid(jwt)){
            filterChain.doFilter(request,response);
            return;
        }
        //3. Cargar el usuario del UserDetailService

        String username= this.jwtUtil.getUserName(jwt);
        User user= (User) this.userDetailsService.loadUserByUsername(username);

        //4. Cargar al usuario en el contexto de seguridad
        UsernamePasswordAuthenticationToken authenticationToken= new UsernamePasswordAuthenticationToken(
                                                                                user.getUsername(),
                                                                                user.getPassword(),
                                                                                user.getAuthorities());

        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        filterChain.doFilter(request,response);

    }
}
