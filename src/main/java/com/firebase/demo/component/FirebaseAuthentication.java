package com.firebase.demo.component;

import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.FirebaseToken;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class FirebaseAuthentication {
//    @Component
    public static class AuthFilter extends AbstractAuthenticationProcessingFilter {
    private static final AntPathRequestMatcher DEFAULT_ANT_PATH_REQUEST_MATCHER = new AntPathRequestMatcher("/login", "POST");
    private SecurityContextHolderStrategy securityContextHolderStrategy;
    public AuthFilter() {
        super(DEFAULT_ANT_PATH_REQUEST_MATCHER);
    }

    public AuthFilter(AuthenticationManager authenticationManager) {
        super(DEFAULT_ANT_PATH_REQUEST_MATCHER, authenticationManager);
        this.securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
    }


    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        if (!request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        } else {
            String header = request.getHeader("Authorization");

            String[] info = header.split(":");

            if(info.length <2 || info[0].isEmpty() ||info[1].isEmpty()) throw new BadCredentialsException("Bad credentials");

            Token authRequest = new Token(info[0], info[1]);
            this.setDetails(request, authRequest);


            Authentication authentication = this.getAuthenticationManager().authenticate(authRequest);
            SecurityContext context = securityContextHolderStrategy.createEmptyContext();
            context.setAuthentication(authentication);
            SecurityContextHolder.setDeferredContext(()->context);

            return authentication;
        }
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        super.doFilter(request, response, chain);
    }

    protected void setDetails(HttpServletRequest request, Token authRequest) {
            authRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));
        }

//        @Override
//        protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
//            super.successfulAuthentication(request, response, chain, authResult);
//        }
    }

//    public static class LogoutFilter extends org.springframework.security.web.authentication.logout.LogoutFilter {
//        public AuthFilter(AuthenticationManager authenticationManager) {
//            super(authenticationManager);
//        }
//
//        public LogoutFilter(LogoutSuccessHandler logoutSuccessHandler, LogoutHandler... handlers) {
//            super(logoutSuccessHandler, handlers);
//        }
//
//        @Override
//        public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
//            if (!request.getMethod().equals("POST")) {
//                throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
//            } else {
//                String header = request.getHeader("Authorization");
//
//                String[] info = header.split(":");
//
//                if(info.length <2 || info[0].isEmpty() ||info[1].isEmpty()) throw new BadCredentialsException("Bad credentials");
//
//                Token authRequest = new Token(info[0], info[1]);
//                this.setDetails(request, authRequest);
//                return this.getAuthenticationManager().authenticate(authRequest);
//            }
//        }
//
//        protected void setDetails(HttpServletRequest request, Token authRequest) {
//            authRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));
//        }
//
//        @Override
//        protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
//            super.successfulAuthentication(request, response, chain, authResult);
//        }
//    }


    @Component
    public static class Provider implements AuthenticationProvider {
        @Autowired
        FirebaseAuth auth;
        @Override
        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            String at = (String) authentication.getCredentials();

            FirebaseToken firetoken;
            try {
                firetoken = auth.verifyIdToken(at);
            } catch (FirebaseAuthException e) {
                throw new BadCredentialsException("Bad credentials");
            }

            Token token = null;
            if(firetoken.getUid().equals(authentication.getPrincipal()))
            {
                List<GrantedAuthority> authorityList = new ArrayList<>();
                authorityList.add(new SimpleGrantedAuthority("USER")); //TODO: take from firestore
                token = new Token(firetoken.getUid(),at,authorityList);
                token.setDetails(authentication.getDetails());
            }

            return token;
        }

        @Override
        public boolean supports(Class<?> authentication) {
            return Token.class.isAssignableFrom(authentication);
        }
    }

    public static class Token extends AbstractAuthenticationToken {
        String uid;
        String token;

        public Token(String uid, String token) {
            super(null);
            this.uid = uid;
            this.token = token;
            super.setAuthenticated(false);
        }

        public Token(String uid, String token, Collection<? extends GrantedAuthority> authorities) {
            super(authorities);
            this.uid = uid;
            this.token =token;
            super.setAuthenticated(true);
        }

        @Override
        public Object getCredentials() {
            return token;
        }

        @Override
        public Object getPrincipal() {
            return uid;
        }
    }

}
