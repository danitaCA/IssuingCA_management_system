package org.insa.pki.ra.api;

import org.insa.pki.ra.api.ApiDtos.CertificateProfile;
import org.insa.pki.ra.service.CertificateProfileService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/v1/profiles")
public class ProfileController {
    private final CertificateProfileService profiles;
    public ProfileController(CertificateProfileService profiles) { this.profiles = profiles; }
    @GetMapping
    public List<CertificateProfile> list() { return profiles.list(); }
}
