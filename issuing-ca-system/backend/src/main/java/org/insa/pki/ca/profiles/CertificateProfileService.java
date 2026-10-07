package org.insa.pki.ca.profiles;

import org.insa.pki.ca.csr.ParsedCsr;
import org.bouncycastle.asn1.x509.GeneralName;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import java.time.Duration;
import java.util.List;
import java.util.Map;

@Service
public class CertificateProfileService {
    private final Map<String, CertificateProfile> profiles;

    public CertificateProfileService(@Value("${app.ca.certificate-validity-days:365}") int validityDays) {
        if (validityDays < 1 || validityDays > 825) throw new IllegalArgumentException("Default certificate validity must be in 1..825 days");
        Duration validity = Duration.ofDays(validityDays);
        profiles = Map.of(
                "tls-server", new CertificateProfile("tls-server", "TLS server authentication",
                        List.of("RSA", "ECDSA"), List.of(2048, 3072, 4096, 256, 384, 521),
                        List.of("1.3.6.1.5.5.7.3.1"), validity, true, true),
                "client-auth", new CertificateProfile("client-auth", "TLS client or device authentication",
                        List.of("RSA", "ECDSA"), List.of(2048, 3072, 4096, 256, 384, 521),
                        List.of("1.3.6.1.5.5.7.3.2"), validity, false, true),
                "code-signing", new CertificateProfile("code-signing", "Code and document signing",
                        List.of("RSA", "ECDSA"), List.of(2048, 3072, 4096, 256, 384, 521),
                        List.of("1.3.6.1.5.5.7.3.3"), validity, false, false));
    }

    public List<CertificateProfile> list() { return List.copyOf(profiles.values()); }

    public CertificateProfile get(String name) {
        CertificateProfile profile = profiles.get(name);
        if (profile == null) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unknown certificate profile");
        return profile;
    }

    public CertificateProfile validate(String name, ParsedCsr csr) {
        CertificateProfile profile = get(name);
        if (!profile.keyAlgorithms().contains(csr.keyAlgorithm()) || !profile.keySizes().contains(csr.keySize())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "CSR key algorithm or size is not permitted by this profile");
        }
        if (profile.subjectAltNameRequired() && csr.subjectAltNames().isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "TLS server certificates require at least one SAN");
        }
        for (GeneralName san : csr.subjectAltNames()) {
            if (san.getTagNo() != GeneralName.dNSName && san.getTagNo() != GeneralName.iPAddress) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Only DNS and IP subject alternative names are allowed");
            }
            if (san.getTagNo() == GeneralName.dNSName) {
                String dnsName = san.getName().toString();
                if (dnsName.length() > 253 || !dnsName.matches("(?i)(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*\\.?")) {
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "CSR contains an invalid DNS SAN value");
                }
            } else if (!(san.getName() instanceof org.bouncycastle.asn1.ASN1OctetString ip)
                    || (ip.getOctets().length != 4 && ip.getOctets().length != 16)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "CSR contains an invalid IP SAN value");
            }
        }
        return profile;
    }
}
