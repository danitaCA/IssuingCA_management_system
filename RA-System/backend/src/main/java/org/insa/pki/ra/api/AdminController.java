package org.insa.pki.ra.api;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.insa.pki.ra.api.ApiDtos.*;
import org.insa.pki.ra.domain.AppUser;
import org.insa.pki.ra.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/admin/users")
public class AdminController {
    private final UserService users;
    public AdminController(UserService users) { this.users = users; }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public UserResponse create(@Valid @RequestBody CreateUserRequest body, Authentication authentication,
                               HttpServletRequest request) {
        return UserResponse.from(users.create(body, authentication.getName(), request));
    }

    @PatchMapping("/{id}/enabled")
    public UserResponse setEnabled(@PathVariable String id, @Valid @RequestBody EnabledRequest body,
                                   Authentication authentication, HttpServletRequest request) {
        AppUser user = users.setEnabled(id, body.enabled(), authentication.getName(), request);
        return UserResponse.from(user);
    }
}


