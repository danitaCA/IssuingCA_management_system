package org.insa.pki.ca.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

@Component
public class CaMtlsFilter extends OncePerRequestFilter {
    private final boolean required;
    private final Set<String> allowedSubjects;
    private final boolean localProfile;

    public CaMtlsFilter(@Value("${app.security.mtls-required:true}") boolean required,
                        @Value("${app.security.allowed-client-subjects:}") String allowed,
                        org.springframework.core.env.Environment environment) {
        this.required = required;
        this.allowedSubjects = Arrays.stream(allowed.split(";" )).map(String::trim).filter(s -> !s.isBlank()).collect(java.util.stream.Collectors.toUnmodifiableSet());
        this.localProfile = Arrays.asList(environment.getActiveProfiles()).contains("local");
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return !path.startsWith("/api/v1/certificates/") && !path.equals("/api/v1/profiles");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (!required && localProfile) {
            authenticate("local-development-client");
            chain.doFilter(request, response);
            return;
        }
        if (!required) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "mTLS bypass is permitted only under the local profile");
            return;
        }
        Object value = request.getAttribute("jakarta.servlet.request.X509Certificate");
        if (!(value instanceof X509Certificate[] chainCertificates) || chainCertificates.length == 0 || allowedSubjects.isEmpty()) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "A trusted, allow-listed RA client certificate is required");
            return;
        }
        X509Certificate client = chainCertificates[0];
        try {
            client.checkValidity();
            String subject = client.getSubjectX500Principal().getName();
            if (!allowedSubjects.contains(subject)) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Client certificate subject is not authorized");
                return;
            }
            authenticate(subject);
            chain.doFilter(request, response);
        } catch (java.security.cert.CertificateExpiredException | java.security.cert.CertificateNotYetValidException exception) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Client certificate is not currently valid");
        }
    }

    private void authenticate(String subject) {
        var authentication = new UsernamePasswordAuthenticationToken(subject, null,
                List.of(new SimpleGrantedAuthority("ROLE_RA_CLIENT")));
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}
