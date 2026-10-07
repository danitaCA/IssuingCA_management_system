package org.insa.pki.ra.api;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.insa.pki.ra.api.ApiDtos.*;
import org.insa.pki.ra.domain.AppUser;
import org.insa.pki.ra.domain.Role;
import org.insa.pki.ra.security.JwtService;
import org.insa.pki.ra.service.AuditService;
import org.insa.pki.ra.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {
    private final UserService users;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final GoogleAuthenticator authenticator = new GoogleAuthenticator();
    private final AuditService audit;

    public AuthController(UserService users, PasswordEncoder passwordEncoder, JwtService jwtService, AuditService audit) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.audit = audit;
    }

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public UserResponse register(@Valid @RequestBody RegisterRequest body, HttpServletRequest request) {
        return UserResponse.from(users.register(body, request));
    }

    @PostMapping("/login")
    public TokenResponse login(@Valid @RequestBody LoginRequest body, HttpServletRequest request) {
        AppUser user;
        try {
            user = users.findByUsername(body.username());
            if (!user.isEnabled() || !passwordEncoder.matches(body.password(), user.getPasswordHash())) {
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
            }
            if (requiresMfa(user.getRole())) {
                if (!user.isTotpEnabled() || user.getTotpSecret() == null) {
                    throw new ResponseStatusException(HttpStatus.FORBIDDEN, "TOTP setup required; use /api/v1/auth/mfa/setup");
                }
                if (body.otp() == null || !authenticator.authorize(user.getTotpSecret(), Integer.parseInt(body.otp()))) {
                    throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials or MFA code");
                }
            } else if (user.isTotpEnabled() && (body.otp() == null || !authenticator.authorize(user.getTotpSecret(), Integer.parseInt(body.otp())))) {
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials or MFA code");
            }
            audit.record(user.getId(), request.getRemoteAddr(), "LOGIN_SUCCESS", "USER", user.getId(), "Authentication succeeded");
            return new TokenResponse(jwtService.issue(user), "Bearer", jwtService.getTtlSeconds());
        } catch (ResponseStatusException exception) {
            audit.record(null, request.getRemoteAddr(), "LOGIN_FAILURE", "USER", body.username(), "Authentication failed");
            throw exception;
        } catch (RuntimeException exception) {
            audit.record(null, request.getRemoteAddr(), "LOGIN_FAILURE", "USER", body.username(), "Authentication failed");
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials or MFA code");
        }
    }

    @PostMapping("/mfa/setup")
    public MfaSetupResponse setupMfa(@Valid @RequestBody MfaSetupRequest body, HttpServletRequest request) {
        AppUser user = verifyPassword(body.username(), body.password());
        if (user.isTotpEnabled()) throw new ResponseStatusException(HttpStatus.CONFLICT, "TOTP is already enabled");
        GoogleAuthenticatorKey key = authenticator.createCredentials();
        users.saveTotpSecret(user.getId(), key.getKey());
        String label = URLEncoder.encode("Issuing CA:" + user.getUsername(), StandardCharsets.UTF_8);
        String issuer = URLEncoder.encode("Issuing CA", StandardCharsets.UTF_8);
        audit.record(user.getId(), request.getRemoteAddr(), "MFA_SETUP_STARTED", "USER", user.getId(), "TOTP enrollment started");
        return new MfaSetupResponse(key.getKey(), "otpauth://totp/" + label + "?secret=" + key.getKey() + "&issuer=" + issuer);
    }

    @PostMapping("/mfa/enable")
    public UserResponse enableMfa(@Valid @RequestBody MfaEnableRequest body, HttpServletRequest request) {
        AppUser user = verifyPassword(body.username(), body.password());
        if (user.getTotpSecret() == null || !authenticator.authorize(user.getTotpSecret(), Integer.parseInt(body.otp()))) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid TOTP code");
        }
        users.enableTotp(user.getId());
        audit.record(user.getId(), request.getRemoteAddr(), "MFA_ENABLED", "USER", user.getId(), "TOTP enabled");
        return UserResponse.from(user);
    }

    private AppUser verifyPassword(String username, String password) {
        AppUser user = users.findByUsername(username);
        if (!user.isEnabled() || !passwordEncoder.matches(password, user.getPasswordHash())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
        }
        return user;
    }

    private boolean requiresMfa(Role role) {
        return role == Role.ADMIN || role == Role.OPERATOR || role == Role.SECURITY_OFFICER || role == Role.CA_ADMIN;
    }
}
