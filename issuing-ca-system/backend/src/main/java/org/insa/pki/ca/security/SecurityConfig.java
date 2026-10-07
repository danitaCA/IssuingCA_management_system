package org.insa.pki.ca.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, CaMtlsFilter mtlsFilter) throws Exception {
        return http.csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/actuator/health", "/actuator/health/**", "/api/v1/crl").permitAll()
                        .requestMatchers("/api/v1/certificates/**", "/api/v1/profiles").hasRole("RA_CLIENT")
                        .anyRequest().denyAll())
                .addFilterBefore(mtlsFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }
}
