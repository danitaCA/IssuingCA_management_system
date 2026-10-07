package org.insa.pki.ra.service;

import org.insa.pki.ra.api.ApiDtos.CreateUserRequest;
import org.insa.pki.ra.api.ApiDtos.RegisterRequest;
import org.insa.pki.ra.domain.AppUser;
import org.insa.pki.ra.domain.Role;
import org.insa.pki.ra.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.UUID;

@Service
public class UserService {
    private final UserRepository users;
    private final PasswordEncoder passwordEncoder;
    private final AuditService audit;

    public UserService(UserRepository users, PasswordEncoder passwordEncoder, AuditService audit) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
        this.audit = audit;
    }

    @Transactional
    public AppUser register(RegisterRequest request, HttpServletRequest http) {
        ensureUnique(request.username(), request.email());
        AppUser user = users.save(new AppUser(UUID.randomUUID().toString(), request.username(), request.email(),
                passwordEncoder.encode(request.password()), Role.END_ENTITY));
        audit.record(user.getId(), http.getRemoteAddr(), "USER_REGISTER", "USER", user.getId(), "End entity registered");
        return user;
    }

    @Transactional
    public AppUser create(CreateUserRequest request, String actorId, HttpServletRequest http) {
        ensureUnique(request.username(), request.email());
        AppUser user = users.save(new AppUser(UUID.randomUUID().toString(), request.username(), request.email(),
                passwordEncoder.encode(request.password()), request.role()));
        audit.record(actorId, http.getRemoteAddr(), "USER_CREATE", "USER", user.getId(), "Role=" + user.getRole());
        return user;
    }

    @Transactional
    public AppUser bootstrapAdmin(String username, String email, String password) {
        if (username == null || username.isBlank() || email == null || email.isBlank() || password == null || password.isBlank()) return null;
        if (users.existsByUsername(username)) return null;
        if (users.existsByEmail(email)) throw new IllegalStateException("Bootstrap admin email already belongs to another account");
        if (password.length() < 12) throw new IllegalStateException("Bootstrap admin password must be at least 12 characters");
        return users.save(new AppUser(UUID.randomUUID().toString(), username, email, passwordEncoder.encode(password), Role.ADMIN));
    }

    @Transactional
    public AppUser setEnabled(String id, boolean enabled, String actorId, HttpServletRequest http) {
        AppUser user = users.findById(id).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
        user.setEnabled(enabled);
        audit.record(actorId, http.getRemoteAddr(), enabled ? "USER_ENABLED" : "USER_DISABLED", "USER", id,
                "Account enabled=" + enabled);
        return user;
    }

    public AppUser findByUsername(String username) {
        return users.findByUsername(username).orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials"));
    }

    @Transactional
    public void saveTotpSecret(String userId, String secret) {
        AppUser user = users.findById(userId).orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials"));
        if (user.isTotpEnabled()) throw new ResponseStatusException(HttpStatus.CONFLICT, "TOTP is already enabled");
        user.setTotpSecret(secret);
    }

    @Transactional
    public void enableTotp(String userId) {
        AppUser user = users.findById(userId).orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials"));
        user.setTotpEnabled(true);
    }

    private void ensureUnique(String username, String email) {
        if (users.existsByUsername(username) || users.existsByEmail(email)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Username or email is already registered");
        }
    }
}
