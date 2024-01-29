package org.zerock.api01.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.zerock.api01.security.handler.APILoginSuccessHandler;
import org.zerock.api01.security.APIUserDetailsService;
import org.zerock.api01.security.filter.APILoginFilter;
import org.zerock.api01.security.filter.TokenCheckFilter;
import org.zerock.api01.util.JWTUtil;

@Log4j2
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class CustomSecurityConfig {

    private final APIUserDetailsService apiUserDetailsService;

    private final JWTUtil jwtUtil;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        log.info("--------------------web configure-----------------------");

        return (web -> web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations()));
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        log.info("----------------------configure-------------------------");

        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);

        authenticationManagerBuilder
                .userDetailsService(apiUserDetailsService)
                .passwordEncoder(passwordEncoder());

        AuthenticationManager authenticationManager = authenticationManagerBuilder.build();

        http.authenticationManager(authenticationManager);

        APILoginFilter apiLoginFilter = new APILoginFilter("/generateToken");
        apiLoginFilter.setAuthenticationManager(authenticationManager);

        APILoginSuccessHandler successHandler = new APILoginSuccessHandler(jwtUtil);
        apiLoginFilter.setAuthenticationSuccessHandler(successHandler);

        http.addFilterBefore(tokenCheckFilter(jwtUtil), UsernamePasswordAuthenticationFilter.class);

        http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS));


        return http.build();
    }

    private TokenCheckFilter tokenCheckFilter(JWTUtil jwtUtil) {
        return new TokenCheckFilter(jwtUtil);
    }
}
