package org.insa.pki.ra.service;

import org.insa.pki.ra.api.ApiDtos.CertificateProfile;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Map;

@Service
public class CertificateProfileService {
    private final Map<String, CertificateProfile> profiles = Map.of(
            "tls-server", new CertificateProfile("tls-server", "TLS server authentication; DNS/IP SAN required",
                    List.of("RSA", "ECDSA"), List.of(2048, 3072, 4096, 256, 384, 521), List.of("serverAuth")),
            "client-auth", new CertificateProfile("client-auth", "Client or device authentication",
                    List.of("RSA", "ECDSA"), List.of(2048, 3072, 4096, 256, 384, 521), List.of("clientAuth")),
            "code-signing", new CertificateProfile("code-signing", "Code or document signing",
                    List.of("RSA", "ECDSA"), List.of(2048, 3072, 4096, 256, 384, 521), List.of("codeSigning"))
    );

    public List<CertificateProfile> list() { return List.copyOf(profiles.values()); }

    public CertificateProfile require(String name) {
        CertificateProfile profile = profiles.get(name);
        if (profile == null) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unknown certificate profile");
        return profile;
    }

    public void validate(CsrParser.ParsedCsr csr, String profileName) {
        require(profileName);
        boolean supported = switch (csr.keyAlgorithm()) {
            case "RSA" -> List.of(2048, 3072, 4096).contains(csr.keySize());
            case "ECDSA" -> List.of(256, 384, 521).contains(csr.keySize());
            default -> false;
        };
        if (!supported) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "CSR key algorithm or size is not permitted");
        if ("tls-server".equals(profileName) && csr.sans().isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "TLS server requests must include at least one subject alternative name");
        }
    }
}
